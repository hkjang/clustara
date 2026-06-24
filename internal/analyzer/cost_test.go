package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func costPod(cluster, ns, name, cpu, mem string) store.K8sInventoryItem {
	return store.K8sInventoryItem{Kind: "Pod", ClusterID: cluster, Namespace: ns, Name: name,
		Spec: map[string]any{"containers": []any{map[string]any{"name": "c",
			"resources": map[string]any{"requests": map[string]any{"cpu": cpu, "memory": mem}}}}}}
}

func TestEstimateCost(t *testing.T) {
	items := []store.K8sInventoryItem{
		costPod("c1", "payments", "p1", "1", "1Gi"),   // 1 core + 1GB
		costPod("c1", "payments", "p2", "500m", "0"),  // 0.5 core
		costPod("c1", "web", "w1", "2", "2Gi"),        // 2 core + 2GB
		{Kind: "Pod", ClusterID: "c1", Namespace: "x", Name: "norq"}, // no requests -> excluded
	}
	prices := CostPrices{CPUCoreMonthlyKRW: 10000, MemGBMonthlyKRW: 1000}
	nsTeam := map[string]string{"c1|payments": "core", "c1|web": "fe"}
	nsCC := map[string]string{"c1|payments": "CC-100"}
	clusterGroup := map[string]string{"c1": "운영망"}

	rep := EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)

	// payments: (1*10000 + 1*1000) + (0.5*10000) = 11000 + 5000 = 16000
	// web: 2*10000 + 2*1000 = 22000 ; total = 38000
	if rep.TotalMonthlyKRW != 38000 {
		t.Fatalf("total = %v, want 38000", rep.TotalMonthlyKRW)
	}
	// sorted desc → web first
	if len(rep.ByNamespace) != 2 || rep.ByNamespace[0].Key != "web" || rep.ByNamespace[0].MonthlyKRW != 22000 {
		t.Fatalf("by-namespace wrong: %+v", rep.ByNamespace)
	}
	// team rollup: core = payments (16000), fe = web (22000)
	teamByKey := map[string]float64{}
	for _, l := range rep.ByTeam {
		teamByKey[l.Key] = l.MonthlyKRW
	}
	if teamByKey["core"] != 16000 || teamByKey["fe"] != 22000 {
		t.Fatalf("team rollup wrong: %+v", rep.ByTeam)
	}
	// group rollup: 운영망 gets everything (38000)
	if len(rep.ByGroup) != 1 || rep.ByGroup[0].Key != "운영망" || rep.ByGroup[0].MonthlyKRW != 38000 {
		t.Fatalf("group rollup wrong: %+v", rep.ByGroup)
	}
	// cost center: CC-100 (payments) = 16000, web has none -> "(미지정)"
	ccByKey := map[string]float64{}
	for _, l := range rep.ByCostCenter {
		ccByKey[l.Key] = l.MonthlyKRW
	}
	if ccByKey["CC-100"] != 16000 || ccByKey["(미지정)"] != 22000 {
		t.Fatalf("cost-center rollup wrong: %+v", rep.ByCostCenter)
	}
}

func TestEstimateCostDefaultPrices(t *testing.T) {
	rep := EstimateCost([]store.K8sInventoryItem{costPod("c1", "n", "p", "1", "0")}, CostPrices{}, nil, nil, nil)
	if rep.Prices.CPUCoreMonthlyKRW != DefaultCostPrices.CPUCoreMonthlyKRW {
		t.Fatalf("zero prices should fall back to defaults, got %+v", rep.Prices)
	}
}
