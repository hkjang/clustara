package analyzer

import "testing"

func TestEvaluateWatchTargets(t *testing.T) {
	workloads := []WorkloadGroup{
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "web", PodCount: 3, CriticalPods: 1, WarningPods: 1, TotalRestarts: 9, MinHealth: 10, WorstSymptom: "CrashLoopBackOff", Band: "critical"},
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "api", PodCount: 2, MinHealth: 100, Band: "healthy"},
		{Namespace: "stage", OwnerKind: "Deployment", OwnerName: "web", PodCount: 1, WarningPods: 1, MinHealth: 60, WorstSymptom: "ProbeFailing", Band: "warning"},
	}

	// Namespace-wide watch on prod → aggregates web(critical) + api(healthy) → worst band critical.
	statuses := EvaluateWatchTargets([]WatchTarget{
		{ID: "w1", ClusterID: "c1", Namespace: "prod"},
	}, workloads)
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	st := statuses[0]
	if st.ClusterID != "c1" || st.Matched != 2 || st.Band != "critical" || st.CriticalPods != 1 {
		t.Fatalf("prod ns watch: %+v", st)
	}
	if st.PodCount != 5 || st.MinHealth != 10 || st.WorstSymptom != "CrashLoopBackOff" {
		t.Fatalf("prod aggregate wrong: %+v", st)
	}

	// Owner-specific watch on prod/api → only api (healthy).
	st = EvaluateWatchTargets([]WatchTarget{
		{ID: "w2", Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "api"},
	}, workloads)[0]
	if st.Matched != 1 || st.Band != "healthy" {
		t.Fatalf("api watch should be healthy: %+v", st)
	}

	// Watch with no matching workload → unknown band.
	st = EvaluateWatchTargets([]WatchTarget{
		{ID: "w3", Namespace: "ghost"},
	}, workloads)[0]
	if st.Matched != 0 || st.Band != "unknown" {
		t.Fatalf("no-match watch should be unknown: %+v", st)
	}
}
