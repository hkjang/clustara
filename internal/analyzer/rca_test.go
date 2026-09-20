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
		{ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "api", ChangeKind: "updated", ImageSet: "ex/api:2.0", ObservedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)},
		// initial observation -> ignored
		{ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "untouched", ChangeKind: "created", ObservedAt: now.Add(-1 * time.Hour).Format(time.RFC3339Nano)},
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

// Include the empty cluster as a distinct identity, never as a wildcard.
func TestAnalyzeRCAClusterEvidence(t *testing.T) {
	for _, kind := range []string{"Pod", "Deployment"} {
		for _, fallback := range []bool{false, true} {
			if kind == "Pod" && fallback {
				continue
			}
			t.Run(kind+map[bool]string{false: "/direct", true: "/fallback"}[fallback], func(t *testing.T) {
				var items []store.K8sInventoryItem
				var events []store.K8sEvent
				messages := map[string]string{"prod": "api insufficient cpu", "dr": "api untolerated taint", "": "api pvc unbound"}
				for _, cluster := range []string{"prod", "dr", ""} {
					items = append(items, store.K8sInventoryItem{ClusterID: cluster, Namespace: "default", Kind: kind, Name: "api", Status: "Pending"})
					e := store.K8sEvent{ClusterID: cluster, Namespace: "default", InvolvedKind: kind, InvolvedName: "api", Reason: "FailedScheduling", Message: messages[cluster]}
					if fallback {
						e.InvolvedKind, e.InvolvedName = "Pod", "api-child"
					}
					events = append(events, e)
				}
				seen := map[string]bool{}
				for _, f := range AnalyzeRCA(items, events) {
					if f.Condition != "Pending" {
						continue
					}
					key := f.ClusterID + "/" + f.Condition
					if seen[key] {
						t.Fatalf("duplicate finding: %+v", f)
					}
					seen[key] = true
					want := "FailedScheduling: " + messages[f.ClusterID]
					if len(f.Evidence) != 1 || f.Evidence[0] != want {
						t.Errorf("%s evidence=%v, want %q", key, f.Evidence, want)
					}
					if wantCause := pendingCause([]store.K8sEvent{{Message: messages[f.ClusterID]}}); f.Cause != wantCause {
						t.Errorf("%s cause=%q, want %q", key, f.Cause, wantCause)
					}
				}
				if len(seen) != 3 {
					t.Fatalf("expected three Pending findings, got %v", seen)
				}
			})
		}
	}
}

func TestAnalyzeRCAProbeClusterDedup(t *testing.T) {
	var events []store.K8sEvent
	for _, cluster := range []string{"prod", "dr", ""} {
		e := store.K8sEvent{ClusterID: cluster, Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api", Type: "Warning", Reason: "Unhealthy", Message: "Liveness probe failed"}
		events = append(events, e, e)
		e.Type, e.InvolvedName = "Normal", "ignored"
		events = append(events, e)
	}
	findings := AnalyzeRCA(nil, events)
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.ClusterID + "/" + f.Condition
		if seen[key] || f.Condition != "LivenessProbeFailed" || f.ResourceName != "api" || len(f.Evidence) != 1 {
			t.Fatalf("unexpected finding: %+v", f)
		}
		seen[key] = true
	}
	for _, cluster := range []string{"prod", "dr", ""} {
		if !seen[cluster+"/LivenessProbeFailed"] {
			t.Errorf("missing finding for cluster %q: %+v", cluster, findings)
		}
	}
}

func TestEnrichWithConfigChangesClusterIsolation(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, revisionCluster := range []string{"prod", "dr", ""} {
		t.Run("revision/"+revisionCluster, func(t *testing.T) {
			var findings []RCAFinding
			for _, cluster := range []string{"prod", "dr", ""} {
				findings = append(findings, RCAFinding{ClusterID: cluster, Namespace: "default", ResourceKind: "Deployment", ResourceName: "api", Condition: "UnavailableReplicas", Severity: "medium"})
			}
			revs := []store.K8sResourceRevision{
				{ClusterID: revisionCluster, Namespace: "default", Kind: "Deployment", Name: "api", ChangeKind: "updated", ImageSet: "latest:2", ObservedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)},
				{ClusterID: revisionCluster, Namespace: "default", Kind: "Deployment", Name: "api", ChangeKind: "updated", ImageSet: "older:1", ObservedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)},
				{ClusterID: revisionCluster, Namespace: "default", Kind: "Deployment", Name: "api", ChangeKind: "created", ImageSet: "created:3", ObservedAt: now.Format(time.RFC3339Nano)},
			}
			for _, f := range EnrichWithConfigChanges(findings, revs, now, 24*time.Hour) {
				if f.ClusterID == revisionCluster {
					if f.Severity != "high" || len(f.Evidence) != 1 || !containsSub(f.Evidence, "latest:2") {
						t.Errorf("latest same-cluster change missing: %+v", f)
					}
				} else if f.Severity != "medium" || len(f.Evidence) != 0 || len(f.Actions) != 0 {
					t.Errorf("foreign revision enriched finding: %+v", f)
				}
			}
		})
	}
}

func TestAnalyzePostDeploymentErrorsClusterIsolation(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	var revs []store.K8sResourceRevision
	var events []store.K8sEvent
	deployTimes := map[string]string{}
	for i, cluster := range []string{"prod", "dr", ""} {
		at := now.Add(-time.Duration(i+1) * time.Hour)
		deployTimes[cluster] = at.Format(time.RFC3339Nano)
		rev := store.K8sResourceRevision{ClusterID: cluster, Namespace: "default", Kind: "Deployment", Name: "api", ChangeKind: "updated", ObservedAt: deployTimes[cluster]}
		revs = append(revs, rev)
		rev.ObservedAt = at.Add(-time.Hour).Format(time.RFC3339Nano)
		revs = append(revs, rev)
		e := store.K8sEvent{ClusterID: cluster, Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api-child", Type: "Warning", Reason: "BackOff", Message: "after/" + cluster, LastSeen: at.Add(30 * time.Minute).Format(time.RFC3339Nano)}
		events = append(events, e)
		e.Message, e.LastSeen = "before", at.Add(-30*time.Minute).Format(time.RFC3339Nano)
		events = append(events, e)
		e.Message, e.LastSeen, e.Type = "normal", now.Format(time.RFC3339Nano), "Normal"
		events = append(events, e)
	}
	findings := AnalyzePostDeploymentErrors(revs, events, now, 24*time.Hour)
	seen := map[string]bool{}
	for _, f := range findings {
		key := f.ClusterID + "/" + f.Condition
		if seen[key] || f.Condition != "PostDeploymentErrors" {
			t.Errorf("unexpected finding: %+v", f)
		}
		seen[key] = true
		if len(f.Evidence) != 2 || f.Evidence[0] != "배포 시각: "+deployTimes[f.ClusterID] || f.Evidence[1] != "BackOff: after/"+f.ClusterID {
			t.Errorf("wrong revision or events: %+v", f)
		}
	}
	if len(seen) != 3 {
		t.Errorf("expected three cluster findings: %+v", findings)
	}
	// A lone revision cannot borrow another cluster's events (including the empty cluster).
	for _, rev := range revs[:1] {
		for _, cluster := range []string{"dr", ""} {
			e := store.K8sEvent{ClusterID: cluster, Namespace: "default", InvolvedName: "api", Type: "Warning", LastSeen: now.Format(time.RFC3339Nano)}
			if out := AnalyzePostDeploymentErrors([]store.K8sResourceRevision{rev}, []store.K8sEvent{e}, now, 24*time.Hour); len(out) != 0 {
				t.Errorf("foreign event generated finding: %+v", out)
			}
		}
	}
	for _, change := range []string{"created", "old"} {
		rev := revs[0]
		if change == "created" {
			rev.ChangeKind = "created"
		} else {
			rev.ObservedAt = now.Add(-48 * time.Hour).Format(time.RFC3339Nano)
		}
		if out := AnalyzePostDeploymentErrors([]store.K8sResourceRevision{rev}, events, now, 24*time.Hour); len(out) != 0 {
			t.Errorf("%s revision generated finding: %+v", change, out)
		}
	}
}
