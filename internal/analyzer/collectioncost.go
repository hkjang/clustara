package analyzer

import "sort"

// Collection Cost Guard (CLU-REQ-11).
//
// Automatic + adaptive collection (v0.9.11/v0.9.19) can grow storage fast across many clusters.
// This estimates each cluster's collection storage footprint from its row counts (weighted by
// per-table average row size) plus a projected daily growth from the append-only tables driven by
// the collect cadence, and flags clusters over a configurable budget. Pure estimation.

// Per-table average row size estimates (bytes). Inventory rows carry full spec+status JSON so they
// dominate; events/revisions are medium; metrics/collect-runs are small.
const (
	bytesInventory   = 4096
	bytesEvent       = 512
	bytesRevision    = 2048
	bytesWatchEvent  = 384
	bytesMetric      = 128
	bytesCollectRun  = 256
	collectRunPerRow = bytesCollectRun
)

// CollectionCostInput is one cluster's counts + collect cadence.
type CollectionCostInput struct {
	ClusterID      string
	ClusterName    string
	Inventory      int
	Events         int
	Revisions      int
	WatchEvents    int
	Metrics        int
	CollectRuns    int
	CollectsPerDay float64 // from the adaptive cadence (86400 / effective_secs)
	BudgetMB       float64 // per-cluster budget; 0 → no budget
}

// CollectionCostEstimate is the footprint + projection for one cluster.
type CollectionCostEstimate struct {
	ClusterID       string  `json:"cluster_id"`
	ClusterName     string  `json:"cluster_name"`
	TotalRows       int     `json:"total_rows"`
	EstMB           float64 `json:"est_mb"`
	DailyGrowthMB   float64 `json:"daily_growth_mb"`
	MonthlyGrowthMB float64 `json:"monthly_growth_mb"`
	BudgetMB        float64 `json:"budget_mb,omitempty"`
	OverBudget      bool    `json:"over_budget"`
	TopTable        string  `json:"top_table"` // largest contributor
}

// EstimateCollectionCost computes the storage footprint + growth for one cluster.
func EstimateCollectionCost(in CollectionCostInput) CollectionCostEstimate {
	bytesByTable := map[string]int64{
		"inventory":    int64(in.Inventory) * bytesInventory,
		"events":       int64(in.Events) * bytesEvent,
		"revisions":    int64(in.Revisions) * bytesRevision,
		"watch_events": int64(in.WatchEvents) * bytesWatchEvent,
		"metrics":      int64(in.Metrics) * bytesMetric,
		"collect_runs": int64(in.CollectRuns) * bytesCollectRun,
	}
	var total int64
	top, topBytes := "", int64(-1)
	for k, b := range bytesByTable {
		total += b
		if b > topBytes {
			topBytes, top = b, k
		}
	}
	est := CollectionCostEstimate{
		ClusterID: in.ClusterID, ClusterName: in.ClusterName,
		TotalRows: in.Inventory + in.Events + in.Revisions + in.WatchEvents + in.Metrics + in.CollectRuns,
		EstMB:     bytesToMB(total), BudgetMB: in.BudgetMB, TopTable: top,
	}

	// Append-only daily growth: each scheduled collect appends one collect_run row and refreshes
	// events/metrics/revisions for changed resources. Estimate churn as ~10% of inventory per collect.
	if in.CollectsPerDay > 0 {
		churnRowsPerCollect := float64(in.Inventory) * 0.10
		dailyBytes := in.CollectsPerDay * (collectRunPerRow +
			churnRowsPerCollect*(bytesEvent+bytesMetric))
		est.DailyGrowthMB = bytesToMB(int64(dailyBytes))
		est.MonthlyGrowthMB = round2(est.DailyGrowthMB * 30)
	}
	if in.BudgetMB > 0 && est.EstMB+est.MonthlyGrowthMB > in.BudgetMB {
		est.OverBudget = true
	}
	return est
}

// CollectionCostReport is the fleet rollup.
type CollectionCostReport struct {
	Clusters        []CollectionCostEstimate `json:"clusters"`
	TotalEstMB      float64                  `json:"total_est_mb"`
	TotalMonthlyMB  float64                  `json:"total_monthly_growth_mb"`
	OverBudgetCount int                      `json:"over_budget_count"`
}

// BuildCollectionCostReport estimates every cluster and sorts by footprint (largest first).
func BuildCollectionCostReport(inputs []CollectionCostInput) CollectionCostReport {
	rep := CollectionCostReport{Clusters: []CollectionCostEstimate{}}
	for _, in := range inputs {
		e := EstimateCollectionCost(in)
		rep.Clusters = append(rep.Clusters, e)
		rep.TotalEstMB = round2(rep.TotalEstMB + e.EstMB)
		rep.TotalMonthlyMB = round2(rep.TotalMonthlyMB + e.MonthlyGrowthMB)
		if e.OverBudget {
			rep.OverBudgetCount++
		}
	}
	sort.SliceStable(rep.Clusters, func(i, j int) bool { return rep.Clusters[i].EstMB > rep.Clusters[j].EstMB })
	return rep
}

func bytesToMB(b int64) float64 {
	return round2(float64(b) / (1024 * 1024))
}
