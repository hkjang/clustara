package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func rsPod(ns, name, cpu, mem string) store.K8sInventoryItem {
	return store.K8sInventoryItem{Kind: "Pod", Namespace: ns, Name: name,
		Spec: map[string]any{"containers": []any{map[string]any{"name": "c",
			"resources": map[string]any{"requests": map[string]any{"cpu": cpu, "memory": mem}}}}}}
}

func TestRecommendRightsizing(t *testing.T) {
	prices := CostPrices{CPUCoreMonthlyKRW: 30000, MemGBMonthlyKRW: 4000}
	items := []store.K8sInventoryItem{
		rsPod("p", "over", "1000m", "1Gi"),  // usage 100m → downsize
		rsPod("p", "under", "100m", "128Mi"), // usage 300m → upsize
		rsPod("p", "ok", "200m", "256Mi"),     // usage ~150m → well-sized
	}
	metrics := []store.K8sMetricSample{
		{ResourceKind: "Pod", Namespace: "p", ResourceName: "over", CPUMillicores: 100, MemoryBytes: 100 << 20},
		{ResourceKind: "Pod", Namespace: "p", ResourceName: "under", CPUMillicores: 300, MemoryBytes: 64 << 20},
		{ResourceKind: "Pod", Namespace: "p", ResourceName: "ok", CPUMillicores: 150, MemoryBytes: 200 << 20},
	}
	recs := RecommendRightsizing(items, metrics, prices)
	byName := map[string]RightsizingRec{}
	for _, r := range recs {
		byName[r.Name] = r
	}
	if byName["over"].Direction != "down" || byName["over"].MonthlySavingsKRW <= 0 {
		t.Fatalf("over-provisioned pod should be a down rec with savings: %+v", byName["over"])
	}
	// over: req 1000m, usage 100m → rec 130m → saving (1000-130)/1000*30000 = 26100 + mem
	if byName["over"].RecommendedCPUm != 130 {
		t.Fatalf("recommended cpu = %d, want 130", byName["over"].RecommendedCPUm)
	}
	if byName["under"].Direction != "up" || byName["under"].MonthlySavingsKRW != 0 {
		t.Fatalf("under-provisioned pod should be an up rec, no savings: %+v", byName["under"])
	}
	if _, ok := byName["ok"]; ok {
		t.Fatalf("well-sized pod should not appear: %+v", byName["ok"])
	}
}
