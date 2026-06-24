package analyzer

import (
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func hasPrefix(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func containsSub(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func condition(findings []RCAFinding, cond string) (RCAFinding, bool) {
	for _, f := range findings {
		if f.Condition == cond {
			return f, true
		}
	}
	return RCAFinding{}, false
}

func TestAnalyzeRCAProbeAndDNSEvents(t *testing.T) {
	events := []store.K8sEvent{
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api-1", Type: "Warning", Reason: "Unhealthy", Message: "Readiness probe failed: HTTP 503"},
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api-1", Type: "Warning", Reason: "Unhealthy", Message: "Readiness probe failed: HTTP 503"}, // dup
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "worker-9", Type: "Warning", Reason: "Unhealthy", Message: "Liveness probe failed: timeout"},
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "web-2", Type: "Warning", Reason: "Failed", Message: "dial tcp: lookup db.svc on 10.0.0.10:53: no such host"},
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "ok-1", Type: "Normal", Reason: "Started", Message: "Readiness probe failed should be ignored when Normal"},
	}
	findings := AnalyzeRCA(nil, events)

	rp, ok := condition(findings, "ReadinessProbeFailed")
	if !ok || rp.ResourceName != "api-1" || rp.Severity != "medium" {
		t.Fatalf("expected ReadinessProbeFailed for api-1, got %+v", findings)
	}
	// Dedup: only one readiness finding for api-1.
	count := 0
	for _, f := range findings {
		if f.Condition == "ReadinessProbeFailed" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 readiness finding (deduped), got %d", count)
	}
	if lv, ok := condition(findings, "LivenessProbeFailed"); !ok || lv.Severity != "high" {
		t.Fatalf("expected high LivenessProbeFailed, got %+v", findings)
	}
	if _, ok := condition(findings, "DNSResolutionFailed"); !ok {
		t.Fatalf("expected DNSResolutionFailed, got %+v", findings)
	}
	// Normal-type events must not produce findings.
	for _, f := range findings {
		if f.ResourceName == "ok-1" {
			t.Fatalf("Normal event should not yield a finding: %+v", f)
		}
	}
}

func TestEnrichWithConfigChanges(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	findings := []RCAFinding{
		{ClusterID: "c1", Namespace: "default", ResourceKind: "Deployment", ResourceName: "api", Condition: "UnavailableReplicas", Severity: "medium"},
		{ClusterID: "c1", Namespace: "default", ResourceKind: "Deployment", ResourceName: "untouched", Condition: "CrashLoopBackOff", Severity: "high"},
	}
	revs := []store.K8sResourceRevision{
		// recent change to api -> should attach + bump severity
		{Kind: "Deployment", Namespace: "default", Name: "api", ChangeKind: "updated", ImageSet: "ex/api:2.0", ObservedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)},
		// initial observation -> ignored
		{Kind: "Deployment", Namespace: "default", Name: "untouched", ChangeKind: "created", ObservedAt: now.Add(-1 * time.Hour).Format(time.RFC3339Nano)},
	}
	out := EnrichWithConfigChanges(findings, revs, now, 24*time.Hour)

	api, _ := condition(out, "UnavailableReplicas")
	if api.Severity != "high" {
		t.Fatalf("recent change should bump medium->high, got %s", api.Severity)
	}
	if !hasPrefix(api.Evidence, "직전 config 변경") || !containsSub(api.Evidence, "ex/api:2.0") {
		t.Fatalf("expected config-change evidence with image, got %+v", api.Evidence)
	}

	// 'untouched' had only an initial (created) revision -> no enrichment.
	un, _ := condition(out, "CrashLoopBackOff")
	if hasPrefix(un.Evidence, "직전 config 변경") {
		t.Fatalf("created-only revision must not enrich: %+v", un)
	}
}

func TestAnalyzeRCANodePressure(t *testing.T) {
	events := []store.K8sEvent{
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api-1", Type: "Warning", Reason: "Evicted", Message: "The node was low on resource: memory."},
		{ClusterID: "c1", Namespace: "", InvolvedKind: "Node", InvolvedName: "node-a", Type: "Warning", Reason: "NodeHasDiskPressure", Message: "Node node-a status is now: NodeHasDiskPressure"},
	}
	findings := AnalyzeRCA(nil, events)
	count := 0
	for _, f := range findings {
		if f.Condition == "NodePressure" {
			count++
			if f.Severity != "high" {
				t.Fatalf("NodePressure should be high, got %s", f.Severity)
			}
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 NodePressure findings, got %d (%+v)", count, findings)
	}
}

func TestAnalyzePostDeploymentErrors(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	deployAt := now.Add(-1 * time.Hour)
	revs := []store.K8sResourceRevision{
		{ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "api", ChangeKind: "updated", ObservedAt: deployAt.Format(time.RFC3339Nano)},
	}
	events := []store.K8sEvent{
		// after deploy, on a child pod -> counts
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api-abc-1", Type: "Warning", Reason: "BackOff", Message: "Back-off restarting", LastSeen: now.Add(-30 * time.Minute).Format(time.RFC3339Nano)},
		// before deploy -> ignored
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api-old-9", Type: "Warning", Reason: "BackOff", Message: "old error", LastSeen: now.Add(-3 * time.Hour).Format(time.RFC3339Nano)},
		// different workload -> ignored
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "worker-1", Type: "Warning", Reason: "BackOff", Message: "unrelated", LastSeen: now.Format(time.RFC3339Nano)},
	}
	out := AnalyzePostDeploymentErrors(revs, events, now, 24*time.Hour)
	if len(out) != 1 || out[0].Condition != "PostDeploymentErrors" || out[0].ResourceName != "api" {
		t.Fatalf("expected one PostDeploymentErrors for api, got %+v", out)
	}
	if !hasPrefix(out[0].Evidence, "배포 시각: ") {
		t.Fatalf("expected deploy time evidence, got %+v", out[0].Evidence)
	}
}

func TestEnrichWithConfigChangesRespectsLookback(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	findings := []RCAFinding{{Namespace: "default", ResourceKind: "Deployment", ResourceName: "api", Condition: "UnavailableReplicas", Severity: "medium"}}
	revs := []store.K8sResourceRevision{
		{Kind: "Deployment", Namespace: "default", Name: "api", ChangeKind: "updated", ObservedAt: now.Add(-48 * time.Hour).Format(time.RFC3339Nano)},
	}
	out := EnrichWithConfigChanges(findings, revs, now, 24*time.Hour)
	if out[0].Severity != "medium" || len(out[0].Evidence) != 0 {
		t.Fatalf("change older than lookback must not enrich: %+v", out[0])
	}
}
