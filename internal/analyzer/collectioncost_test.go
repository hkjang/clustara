package analyzer

import "testing"

func TestEstimateCollectionCost(t *testing.T) {
	e := EstimateCollectionCost(CollectionCostInput{
		ClusterID: "c1", ClusterName: "prod",
		Inventory: 2000, Events: 5000, Revisions: 500, WatchEvents: 2000, Metrics: 10000, CollectRuns: 2000,
		CollectsPerDay: 1440, // every 60s
		BudgetMB:       1.0,  // tiny budget to force over-budget
	})
	if e.TotalRows != 21500 {
		t.Fatalf("total rows: %+v", e)
	}
	// inventory 1000*4096 ≈ 3.9MB dominates → top table inventory.
	if e.TopTable != "inventory" {
		t.Fatalf("top table should be inventory: %+v", e)
	}
	if e.EstMB <= 0 || e.DailyGrowthMB <= 0 {
		t.Fatalf("estimates should be positive: %+v", e)
	}
	if !e.OverBudget {
		t.Fatalf("should be over the 1MB budget: %+v", e)
	}
}

func TestEstimateCollectionCostNoBudget(t *testing.T) {
	e := EstimateCollectionCost(CollectionCostInput{ClusterID: "c1", Inventory: 10})
	if e.OverBudget {
		t.Fatalf("no budget → never over budget: %+v", e)
	}
	if e.DailyGrowthMB != 0 {
		t.Fatalf("no cadence → no growth: %+v", e)
	}
}

func TestBuildCollectionCostReport(t *testing.T) {
	rep := BuildCollectionCostReport([]CollectionCostInput{
		{ClusterID: "small", Inventory: 10},
		{ClusterID: "big", Inventory: 5000, CollectsPerDay: 1440, BudgetMB: 0.001},
	})
	if len(rep.Clusters) != 2 {
		t.Fatalf("expected 2: %+v", rep)
	}
	// Largest footprint first.
	if rep.Clusters[0].ClusterID != "big" {
		t.Fatalf("big should sort first: %+v", rep.Clusters)
	}
	if rep.OverBudgetCount != 1 {
		t.Fatalf("big should be over budget: %+v", rep)
	}
	if rep.TotalEstMB <= 0 {
		t.Fatalf("total should be positive: %+v", rep)
	}
}
