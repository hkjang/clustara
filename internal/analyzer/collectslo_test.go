package analyzer

import (
	"testing"
	"time"
)

func TestSummarizeCollectSLO(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	mk := func(cluster string, ok bool, cat string, lat int64, agoMin int) CollectRunSample {
		return CollectRunSample{
			ClusterID: cluster, ClusterName: cluster, OK: ok, Category: cat,
			LatencyMS: lat, StartedAt: now.Add(-time.Duration(agoMin) * time.Minute), Trigger: "scheduled",
		}
	}
	samples := []CollectRunSample{
		// cluster A: 9 ok, 1 fail → 90% → degraded
		mk("A", true, "", 100, 1), mk("A", true, "", 120, 2), mk("A", true, "", 110, 3),
		mk("A", true, "", 90, 4), mk("A", true, "", 130, 5), mk("A", true, "", 105, 6),
		mk("A", true, "", 115, 7), mk("A", true, "", 95, 8), mk("A", true, "", 125, 9),
		mk("A", false, CollectGapTimeout, 5000, 10),
		// cluster B: 1 ok, 3 fail → 25% → failing; rate-limited counted; top failure = rbac
		mk("B", true, "", 200, 1), mk("B", false, CollectGapRBAC, 300, 2),
		mk("B", false, CollectGapRBAC, 320, 3), mk("B", false, CollectGapRateLimit, 50, 4),
		// stale sample (outside 24h window) — must be ignored
		mk("A", false, CollectGapNetwork, 9000, 60*48),
	}

	sum := SummarizeCollectSLO(samples, 24, now)
	if sum.WindowHours != 24 {
		t.Fatalf("window: %+v", sum)
	}
	if len(sum.Clusters) != 2 {
		t.Fatalf("expected 2 clusters: %+v", sum.Clusters)
	}
	// Worst-first: B (25%) before A (90%).
	if sum.Clusters[0].ClusterID != "B" {
		t.Fatalf("worst cluster should be first: %+v", sum.Clusters)
	}

	var a, b CollectSLO
	for _, c := range sum.Clusters {
		if c.ClusterID == "A" {
			a = c
		} else {
			b = c
		}
	}
	if a.Attempts != 10 || a.Successes != 9 || a.Failures != 1 {
		t.Fatalf("A counts wrong (stale sample should be excluded): %+v", a)
	}
	if a.SuccessRate != 90 || a.Band != sloDegradedBand {
		t.Fatalf("A should be 90%% degraded: %+v", a)
	}
	if b.Band != sloFailingBand {
		t.Fatalf("B should be failing: %+v", b)
	}
	if b.TopFailure != CollectGapRBAC {
		t.Fatalf("B top failure should be rbac: %+v", b)
	}
	if b.RateLimited != 1 {
		t.Fatalf("B rate-limited count should be 1: %+v", b)
	}
	if a.P95LatencyMS < a.P50LatencyMS {
		t.Fatalf("p95 must be >= p50: %+v", a)
	}
	// A: 9 fast (~90-130) + 1 slow (5000); p95 nearest-rank should pick the slow outlier.
	if a.P95LatencyMS != 5000 {
		t.Fatalf("A p95 should surface the 5000ms outlier: %+v", a)
	}
	if sum.Healthy != 0 || sum.Degraded != 1 || sum.Failing != 1 {
		t.Fatalf("band tally wrong: %+v", sum)
	}
	if sum.TotalAttempts != 14 {
		t.Fatalf("total attempts should be 14 (10+4, stale excluded): %+v", sum)
	}
}

func TestPercentileEdge(t *testing.T) {
	if percentile(nil, 95) != 0 {
		t.Fatal("empty percentile should be 0")
	}
	one := []int64{42}
	if percentile(one, 50) != 42 || percentile(one, 95) != 42 {
		t.Fatal("single-value percentile should be that value")
	}
}
