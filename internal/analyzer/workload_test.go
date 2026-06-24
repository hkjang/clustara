package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestRolloutFinding(t *testing.T) {
	// Healthy: available == desired -> no finding.
	healthy := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "ok",
		Spec: map[string]any{"replicas": float64(3)}, StatusObject: map[string]any{"availableReplicas": float64(3), "updatedReplicas": float64(3), "readyReplicas": float64(3)}}
	if _, ok := rolloutFinding(healthy, nil); ok {
		t.Fatal("healthy rollout should produce no finding")
	}

	// Stuck via ProgressDeadlineExceeded -> high.
	stuck := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "api",
		Spec: map[string]any{"replicas": float64(3)},
		StatusObject: map[string]any{"availableReplicas": float64(1), "updatedReplicas": float64(1),
			"conditions": []any{map[string]any{"type": "Progressing", "reason": "ProgressDeadlineExceeded", "message": "deadline exceeded"}}}}
	f, ok := rolloutFinding(stuck, nil)
	if !ok || f.Condition != "RolloutStuck" || f.Severity != "high" {
		t.Fatalf("expected high RolloutStuck, got %+v / ok=%v", f, ok)
	}

	// Incomplete (no deadline) but available==0 -> high.
	zero := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "down",
		Spec: map[string]any{"replicas": float64(2)}, StatusObject: map[string]any{"availableReplicas": float64(0)}}
	f2, ok := rolloutFinding(zero, nil)
	if !ok || f2.Severity != "high" {
		t.Fatalf("expected high finding when available=0, got %+v", f2)
	}
}

func TestJobAndCronJobFindings(t *testing.T) {
	job := store.K8sInventoryItem{Kind: "Job", Namespace: "default", Name: "batch",
		StatusObject: map[string]any{"failed": float64(4), "succeeded": float64(0), "startTime": "2026-06-24T01:00:00Z"}}
	f, ok := jobFinding(job, nil)
	if !ok || f.Condition != "JobFailing" || f.Severity != "high" {
		t.Fatalf("expected high JobFailing (failed>=3), got %+v", f)
	}

	okJob := store.K8sInventoryItem{Kind: "Job", Namespace: "default", Name: "done", StatusObject: map[string]any{"succeeded": float64(1)}}
	if _, ok := jobFinding(okJob, nil); ok {
		t.Fatal("succeeded job with no failures should not be flagged")
	}

	cron := store.K8sInventoryItem{Kind: "CronJob", Namespace: "default", Name: "nightly",
		StatusObject: map[string]any{"lastScheduleTime": "2026-06-24T02:00:00Z"}}
	cf, ok := cronJobFinding(cron)
	if !ok || cf.Condition != "CronJobNoSuccess" {
		t.Fatalf("expected CronJobNoSuccess, got %+v", cf)
	}

	cronOK := store.K8sInventoryItem{Kind: "CronJob", Namespace: "default", Name: "good",
		StatusObject: map[string]any{"lastScheduleTime": "2026-06-24T02:00:00Z", "lastSuccessfulTime": "2026-06-24T02:01:00Z"}}
	if _, ok := cronJobFinding(cronOK); ok {
		t.Fatal("cronjob with a successful run should not be flagged")
	}
}

func TestAnalyzeNodeConditions(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Node", Name: "node-1", StatusObject: map[string]any{"conditions": []any{
			map[string]any{"type": "Ready", "status": "True"},
			map[string]any{"type": "MemoryPressure", "status": "True"},
		}}},
		{Kind: "Node", Name: "node-2", StatusObject: map[string]any{"conditions": []any{
			map[string]any{"type": "MemoryPressure", "status": "False"},
		}}},
		{Kind: "Pod", Namespace: "a", Name: "p1", Spec: map[string]any{"nodeName": "node-1"}},
	}
	out := analyzeNodeConditions(items)
	if len(out) != 1 || out[0].ResourceName != "node-1" || out[0].Severity != "high" {
		t.Fatalf("expected one high NodePressure for node-1, got %+v", out)
	}
	joined := ""
	for _, e := range out[0].Evidence {
		joined += e + "|"
	}
	if !containsSub([]string{joined}, "MemoryPressure") || !containsSub([]string{joined}, "p1") {
		t.Fatalf("evidence should include pressure type + affected pod: %+v", out[0].Evidence)
	}
}

func TestAnalyzeRCAIncludesRolloutAndJobs(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Job", Namespace: "default", Name: "batch", StatusObject: map[string]any{"failed": float64(1)}},
	}
	findings := AnalyzeRCA(items, nil)
	if _, ok := condition(findings, "JobFailing"); !ok {
		t.Fatalf("AnalyzeRCA should include Job findings, got %+v", findings)
	}
}
