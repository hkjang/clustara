package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestStabilityBuckets(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Deployment", Name: "a", HealthScore: 100},
		{Kind: "Deployment", Name: "b", HealthScore: 60},
		{Kind: "StatefulSet", Name: "c", HealthScore: 20},
		{Kind: "ConfigMap", Name: "cfg", HealthScore: 0}, // not a workload → ignored
	}
	r := StabilityBuckets(items)
	if r.Workloads != 3 || r.Healthy != 1 || r.Degraded != 1 || r.Critical != 1 {
		t.Fatalf("buckets wrong: %+v", r)
	}
	if r.Score != 60 { // (100+60+20)/3
		t.Fatalf("score = %d, want 60", r.Score)
	}
}

func TestStabilityBucketsEmpty(t *testing.T) {
	if r := StabilityBuckets(nil); r.Workloads != 0 || r.Score != 100 {
		t.Fatalf("empty should be 0 workloads / score 100, got %+v", r)
	}
}

func TestRCAConditionCounts(t *testing.T) {
	c := RCAConditionCounts([]RCAFinding{
		{Condition: "OOMKilled"}, {Condition: "OOMKilled"}, {Condition: "CrashLoopBackOff"},
	})
	if c["OOMKilled"] != 2 || c["CrashLoopBackOff"] != 1 {
		t.Fatalf("counts wrong: %+v", c)
	}
}
