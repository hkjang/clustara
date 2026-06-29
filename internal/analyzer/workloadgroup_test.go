package analyzer

import "testing"

func TestBuildWorkloadGroups(t *testing.T) {
	pods := []WorkloadPod{
		// web (ReplicaSet): 1 critical + 1 warning + 1 healthy → band critical
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "web", Name: "web-1", HealthScore: 10, HealthBand: "critical", PrimarySymptom: "CrashLoopBackOff", RestartCount: 9, Ready: false},
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "web", Name: "web-2", HealthScore: 60, HealthBand: "warning", PrimarySymptom: "ProbeFailing", Ready: false},
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "web", Name: "web-3", HealthScore: 100, HealthBand: "healthy", PrimarySymptom: "Healthy", Ready: true},
		// api (StatefulSet): all healthy
		{Namespace: "prod", OwnerKind: "StatefulSet", OwnerName: "api", Name: "api-0", HealthScore: 100, HealthBand: "healthy", PrimarySymptom: "Healthy", Ready: true},
		{Namespace: "prod", OwnerKind: "StatefulSet", OwnerName: "api", Name: "api-1", HealthScore: 95, HealthBand: "healthy", PrimarySymptom: "Healthy", Ready: true},
	}
	groups := BuildWorkloadGroups(pods)
	if len(groups) != 2 {
		t.Fatalf("expected 2 workload groups, got %d: %+v", len(groups), groups)
	}
	// Critical workload sorts first.
	web := groups[0]
	if web.OwnerName != "web" || web.Band != "critical" {
		t.Fatalf("web should be first and critical: %+v", web)
	}
	if web.PodCount != 3 || web.ReadyPods != 1 || web.CriticalPods != 1 || web.WarningPods != 1 || web.HealthyPods != 1 {
		t.Fatalf("web counts wrong: %+v", web)
	}
	if web.MinHealth != 10 || web.TotalRestarts != 9 {
		t.Fatalf("web min health / restarts wrong: %+v", web)
	}
	// Worst symptom = most severe primary symptom among members (CrashLoop > ProbeFailing).
	if web.WorstSymptom != "CrashLoopBackOff" {
		t.Fatalf("web worst symptom should be CrashLoopBackOff: %+v", web)
	}
	if web.AvgHealth != (10+60+100)/3 {
		t.Fatalf("web avg health wrong: %d", web.AvgHealth)
	}
	api := groups[1]
	if api.OwnerName != "api" || api.Band != "healthy" || api.ReadyPods != 2 {
		t.Fatalf("api should be healthy with 2 ready: %+v", api)
	}

	// Bare pods (no owner) group per-pod.
	bare := BuildWorkloadGroups([]WorkloadPod{
		{Namespace: "x", Name: "loose-a", HealthScore: 30, HealthBand: "critical"},
		{Namespace: "x", Name: "loose-b", HealthScore: 40, HealthBand: "warning"},
	})
	if len(bare) != 2 {
		t.Fatalf("bare pods should form 2 per-pod groups, got %d", len(bare))
	}
	for _, g := range bare {
		if g.OwnerKind != "Pod" || g.PodCount != 1 {
			t.Fatalf("bare group should be Pod/1: %+v", g)
		}
	}
}
