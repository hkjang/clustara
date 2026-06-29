package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestAnalyzeCapacityHPA(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "HorizontalPodAutoscaler", Namespace: "default", Name: "api",
			Spec:         map[string]any{"minReplicas": float64(2), "maxReplicas": float64(10), "scaleTargetRef": map[string]any{"kind": "Deployment", "name": "api"}},
			StatusObject: map[string]any{"currentReplicas": float64(10), "desiredReplicas": float64(10)}},
	}
	rep := AnalyzeCapacity(items, nil)
	if len(rep.HPAs) != 1 {
		t.Fatalf("expected 1 HPA, got %d", len(rep.HPAs))
	}
	h := rep.HPAs[0]
	if h.Max != 10 || h.TargetName != "api" || !h.AtMax {
		t.Fatalf("HPA at max should be flagged: %+v", h)
	}
}

func TestAnalyzeCapacityAllocation(t *testing.T) {
	pod := func(name string, reqCPU string) store.K8sInventoryItem {
		return store.K8sInventoryItem{Kind: "Pod", Namespace: "default", Name: name,
			Spec: map[string]any{"containers": []any{map[string]any{"name": "c", "resources": map[string]any{"requests": map[string]any{"cpu": reqCPU}}}}}}
	}
	items := []store.K8sInventoryItem{
		pod("hot", "100m"),   // usage 250m > 100m -> under_provisioned
		pod("cold", "1000m"), // usage 50m << 1000m -> over_provisioned
		pod("ok", "200m"),    // usage 150m -> fine
	}
	metrics := []store.K8sMetricSample{
		{ResourceKind: "Pod", Namespace: "default", ResourceName: "hot", CPUMillicores: 250, ObservedAt: "2026-06-24T03:00:00Z"},
		{ResourceKind: "Pod", Namespace: "default", ResourceName: "cold", CPUMillicores: 50, ObservedAt: "2026-06-24T03:00:00Z"},
		{ResourceKind: "Pod", Namespace: "default", ResourceName: "ok", CPUMillicores: 150, ObservedAt: "2026-06-24T03:00:00Z"},
	}
	rep := AnalyzeCapacity(items, metrics)
	issues := map[string]string{}
	for _, a := range rep.Allocation {
		issues[a.Name] = a.Issue
	}
	if issues["hot"] != "under_provisioned" {
		t.Errorf("hot should be under_provisioned, got %q", issues["hot"])
	}
	if issues["cold"] != "over_provisioned" {
		t.Errorf("cold should be over_provisioned, got %q", issues["cold"])
	}
	if _, ok := issues["ok"]; ok {
		t.Errorf("ok pod should not be flagged, got %q", issues["ok"])
	}
}

func TestProjectNodeCapacity(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Node", Name: "node-1", StatusObject: map[string]any{"allocatable": map[string]any{"cpu": "4"}}}, // 4000m
	}
	// usage 1000m -> 2000m over 2 days => 500m/day; remaining 2000m => 4 days to full.
	metrics := []store.K8sMetricSample{
		{ResourceKind: "Node", ResourceName: "node-1", CPUMillicores: 1000, ObservedAt: "2026-06-20T00:00:00Z"},
		{ResourceKind: "Node", ResourceName: "node-1", CPUMillicores: 2000, ObservedAt: "2026-06-22T00:00:00Z"},
	}
	proj := ProjectNodeCapacity(items, metrics)
	if len(proj) != 1 {
		t.Fatalf("expected 1 projection, got %d", len(proj))
	}
	p := proj[0]
	if p.DailyGrowthCPUm != 500 || p.AllocCPUm != 4000 || p.DaysToFull != 4 {
		t.Fatalf("projection wrong: %+v", p)
	}
}

func TestSimulateScale(t *testing.T) {
	spec := map[string]any{"replicas": float64(2), "template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "c", "resources": map[string]any{"requests": map[string]any{"cpu": "500m", "memory": "1Gi"}}}}}}}
	sim := SimulateScale(spec, 2, 5)
	if sim.PerReplicaCPUm != 500 || sim.TotalCPUm != 2500 || sim.DeltaCPUm != 1500 {
		t.Fatalf("cpu sim wrong: %+v", sim)
	}
	if sim.PerReplicaMemGB != 1 || sim.TotalMemGB != 5 || sim.DeltaMemGB != 3 {
		t.Fatalf("mem sim wrong: %+v", sim)
	}
}

func TestAnalyzeCapacityNodePackingAndGPU(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Node", Name: "node-1", StatusObject: map[string]any{"allocatable": map[string]any{"cpu": "4", "nvidia.com/gpu": "2"}}},
		{Kind: "Pod", Namespace: "a", Name: "p1", Spec: map[string]any{"nodeName": "node-1",
			"containers": []any{map[string]any{"name": "c", "resources": map[string]any{"requests": map[string]any{"cpu": "1", "nvidia.com/gpu": "1"}}}}}},
		{Kind: "Pod", Namespace: "a", Name: "p2", Spec: map[string]any{"nodeName": "node-1",
			"containers": []any{map[string]any{"name": "c", "resources": map[string]any{"requests": map[string]any{"cpu": "1"}}}}}},
	}
	rep := AnalyzeCapacity(items, nil)
	if len(rep.NodePacking) != 1 {
		t.Fatalf("expected 1 node, got %d", len(rep.NodePacking))
	}
	n := rep.NodePacking[0]
	if n.Pods != 2 || n.AllocCPU != 4000 || n.ReqCPU != 2000 || n.CPUPct != 50 {
		t.Fatalf("node packing wrong: %+v", n)
	}
	if len(rep.GPU) != 1 || rep.GPU[0].Allocatable != 2 || rep.GPU[0].Requested != 1 || rep.GPU[0].Idle != 1 {
		t.Fatalf("gpu summary wrong: %+v", rep.GPU)
	}
}
