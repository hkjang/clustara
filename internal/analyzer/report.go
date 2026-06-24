package analyzer

import "clustara/internal/store"

// StabilityBuckets classifies workloads by health into healthy/degraded/critical and returns a
// 0-100 stability score (avg health) — a lightweight SLO proxy for the report center (DW-10).
type StabilityReport struct {
	Workloads int `json:"workloads"`
	Healthy   int `json:"healthy"`  // health >= 80
	Degraded  int `json:"degraded"` // 50 <= health < 80
	Critical  int `json:"critical"` // health < 50
	Score     int `json:"score"`    // average health score (0-100)
}

func StabilityBuckets(items []store.K8sInventoryItem) StabilityReport {
	r := StabilityReport{}
	sum := 0
	for _, it := range items {
		if !workloadKinds[it.Kind] {
			continue
		}
		r.Workloads++
		h := it.HealthScore
		sum += h
		switch {
		case h >= 80:
			r.Healthy++
		case h >= 50:
			r.Degraded++
		default:
			r.Critical++
		}
	}
	if r.Workloads > 0 {
		r.Score = sum / r.Workloads
	} else {
		r.Score = 100
	}
	return r
}

// RCAConditionCounts tallies RCA findings by condition (for the daily failure summary).
func RCAConditionCounts(findings []RCAFinding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[f.Condition]++
	}
	return out
}
