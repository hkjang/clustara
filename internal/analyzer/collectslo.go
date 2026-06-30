package analyzer

import (
	"sort"
	"time"
)

// Collector SLO Dashboard (CLU-REQ-02).
//
// Rolls up recorded collect-run outcomes into per-cluster SLOs — success rate, failure rate,
// p50/p95 latency, last success/failure, the dominant failure cause, and rate-limit count — so
// operators can tell collection health apart from cluster health. Pure aggregation: the handler
// reads the collect-run history rows and passes them in as samples.

// CollectRunSample is one recorded collect attempt.
type CollectRunSample struct {
	ClusterID   string
	ClusterName string
	Stage       string // ok | client | probe | collect | snapshot
	OK          bool
	Category    string // gap category for failures (auth/rbac/timeout/...)
	LatencyMS   int64
	Trigger     string // manual | scheduled | agent
	StartedAt   time.Time
}

// CollectSLO is the aggregated health of one cluster's collection over the window.
type CollectSLO struct {
	ClusterID     string         `json:"cluster_id"`
	ClusterName   string         `json:"cluster_name"`
	Attempts      int            `json:"attempts"`
	Successes     int            `json:"successes"`
	Failures      int            `json:"failures"`
	SuccessRate   float64        `json:"success_rate"` // 0..100
	RateLimited   int            `json:"rate_limited"`
	P50LatencyMS  int64          `json:"p50_latency_ms"`
	P95LatencyMS  int64          `json:"p95_latency_ms"`
	LastSuccessAt string         `json:"last_success_at,omitempty"`
	LastFailureAt string         `json:"last_failure_at,omitempty"`
	TopFailure    string         `json:"top_failure,omitempty"` // dominant failure category
	FailureBreak  map[string]int `json:"failure_breakdown,omitempty"`
	Band          string         `json:"band"` // healthy | degraded | failing
}

// CollectSLOSummary is the fleet-wide overview plus per-cluster detail.
type CollectSLOSummary struct {
	Clusters       []CollectSLO `json:"clusters"`
	TotalAttempts  int          `json:"total_attempts"`
	TotalFailures  int          `json:"total_failures"`
	OverallSuccess float64      `json:"overall_success"` // 0..100
	Healthy        int          `json:"healthy"`
	Degraded       int          `json:"degraded"`
	Failing        int          `json:"failing"`
	WindowHours    int          `json:"window_hours"`
}

const (
	sloHealthyBand  = "healthy"
	sloDegradedBand = "degraded"
	sloFailingBand  = "failing"
)

// SummarizeCollectSLO aggregates collect-run samples within the last windowHours into per-cluster
// SLOs and a fleet summary. Samples outside the window (relative to now) are ignored.
func SummarizeCollectSLO(samples []CollectRunSample, windowHours int, now time.Time) CollectSLOSummary {
	if windowHours <= 0 {
		windowHours = 24
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-time.Duration(windowHours) * time.Hour)

	type acc struct {
		name        string
		attempts    int
		successes   int
		rateLimited int
		latencies   []int64
		lastSuccess time.Time
		lastFailure time.Time
		failures    map[string]int
	}
	byCluster := map[string]*acc{}
	order := []string{}

	for _, s := range samples {
		if !s.StartedAt.IsZero() && s.StartedAt.Before(cutoff) {
			continue
		}
		a, ok := byCluster[s.ClusterID]
		if !ok {
			a = &acc{failures: map[string]int{}}
			byCluster[s.ClusterID] = a
			order = append(order, s.ClusterID)
		}
		if s.ClusterName != "" {
			a.name = s.ClusterName
		}
		a.attempts++
		if s.LatencyMS > 0 {
			a.latencies = append(a.latencies, s.LatencyMS)
		}
		if s.OK {
			a.successes++
			if s.StartedAt.After(a.lastSuccess) {
				a.lastSuccess = s.StartedAt
			}
		} else {
			cat := s.Category
			if cat == "" {
				cat = CollectGapUnknown
			}
			a.failures[cat]++
			if cat == CollectGapRateLimit {
				a.rateLimited++
			}
			if s.StartedAt.After(a.lastFailure) {
				a.lastFailure = s.StartedAt
			}
		}
	}

	out := CollectSLOSummary{WindowHours: windowHours, Clusters: []CollectSLO{}}
	for _, id := range order {
		a := byCluster[id]
		failures := a.attempts - a.successes
		slo := CollectSLO{
			ClusterID:    id,
			ClusterName:  a.name,
			Attempts:     a.attempts,
			Successes:    a.successes,
			Failures:     failures,
			RateLimited:  a.rateLimited,
			SuccessRate:  rate(a.successes, a.attempts),
			P50LatencyMS: percentile(a.latencies, 50),
			P95LatencyMS: percentile(a.latencies, 95),
			FailureBreak: a.failures,
		}
		if !a.lastSuccess.IsZero() {
			slo.LastSuccessAt = a.lastSuccess.UTC().Format(time.RFC3339)
		}
		if !a.lastFailure.IsZero() {
			slo.LastFailureAt = a.lastFailure.UTC().Format(time.RFC3339)
		}
		slo.TopFailure = topKey(a.failures)
		slo.Band = sloBand(slo.SuccessRate, slo.Attempts)
		out.Clusters = append(out.Clusters, slo)
		out.TotalAttempts += a.attempts
		out.TotalFailures += failures
		switch slo.Band {
		case sloHealthyBand:
			out.Healthy++
		case sloDegradedBand:
			out.Degraded++
		default:
			out.Failing++
		}
	}
	out.OverallSuccess = rate(out.TotalAttempts-out.TotalFailures, out.TotalAttempts)

	// Worst SLO first so the dashboard surfaces problem clusters at the top.
	sort.SliceStable(out.Clusters, func(i, j int) bool {
		return out.Clusters[i].SuccessRate < out.Clusters[j].SuccessRate
	})
	return out
}

func sloBand(successRate float64, attempts int) string {
	if attempts == 0 {
		return sloHealthyBand
	}
	switch {
	case successRate >= 95:
		return sloHealthyBand
	case successRate >= 70:
		return sloDegradedBand
	default:
		return sloFailingBand
	}
}

func rate(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return round2(float64(num) / float64(den) * 100)
}

// percentile returns the p-th percentile (nearest-rank) of the values in ms. Returns 0 when empty.
func percentile(values []int64, p int) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := (p*len(sorted) + 99) / 100 // ceil(p/100 * n)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func topKey(m map[string]int) string {
	best := ""
	bestN := 0
	// deterministic: iterate sorted keys
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if m[k] > bestN {
			bestN = m[k]
			best = k
		}
	}
	return best
}
