package analyzer

import (
	"strings"
	"testing"
)

func TestDetectRestartStorms(t *testing.T) {
	pods := []RestartStormPod{
		// web Deployment: 3 of 4 pods unhealthy/high-restart → critical (>=50%)
		{Namespace: "prod", Name: "web-1", OwnerKind: "ReplicaSet", OwnerName: "web-abc", RestartCount: 9, Unhealthy: true},
		{Namespace: "prod", Name: "web-2", OwnerKind: "ReplicaSet", OwnerName: "web-abc", RestartCount: 5, Unhealthy: true},
		{Namespace: "prod", Name: "web-3", OwnerKind: "ReplicaSet", OwnerName: "web-abc", RestartCount: 4},
		{Namespace: "prod", Name: "web-4", OwnerKind: "ReplicaSet", OwnerName: "web-abc", RestartCount: 0},
		// api Deployment: only 1 pod affected → not a storm
		{Namespace: "prod", Name: "api-1", OwnerKind: "ReplicaSet", OwnerName: "api-xyz", RestartCount: 7, Unhealthy: true},
		{Namespace: "prod", Name: "api-2", OwnerKind: "ReplicaSet", OwnerName: "api-xyz", RestartCount: 0},
		// two bare pods (no owner) restarting — must NOT group into a storm
		{Namespace: "prod", Name: "loose-a", RestartCount: 10, Unhealthy: true},
		{Namespace: "prod", Name: "loose-b", RestartCount: 10, Unhealthy: true},
	}
	storms := DetectRestartStorms(pods, RestartStormOptions{})
	if len(storms) != 1 {
		t.Fatalf("expected exactly 1 storm (web), got %d: %+v", len(storms), storms)
	}
	s := storms[0]
	if s.OwnerName != "web-abc" || s.Severity != "critical" {
		t.Fatalf("web storm should be critical: %+v", s)
	}
	if s.AffectedPods != 3 || s.PodCount != 4 || s.AffectedPct != 75 {
		t.Fatalf("web storm counts wrong: %+v", s)
	}

	// A workload with affected ratio below CriticalPct is "high", not "critical".
	high := DetectRestartStorms([]RestartStormPod{
		{Namespace: "prod", Name: "w-1", OwnerKind: "ReplicaSet", OwnerName: "w", RestartCount: 5, Unhealthy: true},
		{Namespace: "prod", Name: "w-2", OwnerKind: "ReplicaSet", OwnerName: "w", RestartCount: 5, Unhealthy: true},
		{Namespace: "prod", Name: "w-3", OwnerKind: "ReplicaSet", OwnerName: "w", RestartCount: 0},
		{Namespace: "prod", Name: "w-4", OwnerKind: "ReplicaSet", OwnerName: "w", RestartCount: 0},
		{Namespace: "prod", Name: "w-5", OwnerKind: "ReplicaSet", OwnerName: "w", RestartCount: 0},
	}, RestartStormOptions{})
	if len(high) != 1 || high[0].Severity != "high" || high[0].AffectedPct != 40 {
		t.Fatalf("2/5 affected (40%%) should be a single high storm: %+v", high)
	}

	// Lowering MinAffected to 1 surfaces single-affected workloads (api-xyz, 1/2 = 50% → critical).
	storms2 := DetectRestartStorms(pods, RestartStormOptions{MinAffected: 1})
	found := false
	for _, s := range storms2 {
		if s.OwnerName == "api-xyz" {
			found = true
		}
	}
	if !found {
		t.Fatalf("api-xyz should surface with MinAffected=1: %+v", storms2)
	}
	if storms2[0].Severity != "critical" {
		t.Fatalf("critical storm should sort first: %+v", storms2)
	}
}

func TestBuildRestartStormIncidents(t *testing.T) {
	storms := []RestartStorm{
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "web", Severity: "critical", AffectedPods: 3, PodCount: 4, AffectedPct: 75, TotalRestarts: 18, SamplePods: []string{"web-1", "web-2"}, Reason: "service down"},
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "api", Severity: "high", AffectedPods: 2, PodCount: 6, AffectedPct: 33},
	}
	drafts := BuildRestartStormIncidents(storms, "c1")
	if len(drafts) != 1 {
		t.Fatalf("only the critical storm should become an incident, got %d: %+v", len(drafts), drafts)
	}
	d := drafts[0]
	if d.Condition != "RestartStorm" || d.Severity != "critical" || d.Kind != "ReplicaSet" || d.Name != "web" {
		t.Fatalf("draft fields wrong: %+v", d)
	}
	if d.Key != "c1|prod|ReplicaSet|web|RestartStorm" {
		t.Fatalf("dedup key wrong: %q", d.Key)
	}
	joined := strings.Join(d.Evidence, "\n")
	if !strings.Contains(joined, "web-1") || !strings.Contains(joined, "18") {
		t.Fatalf("evidence should include sample pods + restart total: %+v", d.Evidence)
	}
}

func TestDetectRestartStormsIgnoresHistoricalRestarts(t *testing.T) {
	storms := DetectRestartStorms([]RestartStormPod{
		{Namespace: "prod", Name: "proxy-1", OwnerKind: "ReplicaSet", OwnerName: "proxy", RestartCount: 8, RestartRecencyKnown: true, RecentRestartCount: 0},
		{Namespace: "prod", Name: "proxy-2", OwnerKind: "ReplicaSet", OwnerName: "proxy", RestartCount: 6, RestartRecencyKnown: true, RecentRestartCount: 0},
	}, RestartStormOptions{})
	if len(storms) != 0 {
		t.Fatalf("historical cumulative restarts should not create restart storm: %+v", storms)
	}

	storms = DetectRestartStorms([]RestartStormPod{
		{Namespace: "prod", Name: "proxy-1", OwnerKind: "ReplicaSet", OwnerName: "proxy", RestartCount: 8, RestartRecencyKnown: true, RecentRestartCount: 8},
		{Namespace: "prod", Name: "proxy-2", OwnerKind: "ReplicaSet", OwnerName: "proxy", RestartCount: 6, RestartRecencyKnown: true, RecentRestartCount: 6},
	}, RestartStormOptions{})
	if len(storms) != 1 || storms[0].RecentRestarts != 14 {
		t.Fatalf("recent restart signals should create storm with recent count: %+v", storms)
	}
}

func TestDetectRestartStormsIgnoresBatchPods(t *testing.T) {
	storms := DetectRestartStorms([]RestartStormPod{
		{Namespace: "batch", Name: "nightly-1", OwnerKind: "Job", OwnerName: "nightly", RecentRestartCount: 8, RestartRecencyKnown: true, Unhealthy: true},
		{Namespace: "batch", Name: "nightly-2", OwnerKind: "Job", OwnerName: "nightly", RecentRestartCount: 7, RestartRecencyKnown: true, Unhealthy: true},
	}, RestartStormOptions{})
	if len(storms) != 0 {
		t.Fatalf("finite Job attempts must not create service RestartStorm: %+v", storms)
	}
}
