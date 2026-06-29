package analyzer

import "testing"

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
