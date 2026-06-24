package analyzer

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestAnalyzeLatencyRegressions(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	deployAt := now.Add(-2 * time.Hour)
	revs := []store.K8sResourceRevision{
		{ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", ChangeKind: "updated", ObservedAt: deployAt.Format(time.RFC3339Nano)},
		{ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "calm", ChangeKind: "updated", ObservedAt: deployAt.Format(time.RFC3339Nano)},
	}
	lat := func(name string, ms float64, t time.Time) store.K8sMetricSample {
		return store.K8sMetricSample{Namespace: "prod", ResourceName: name, LatencyMS: ms, ObservedAt: t.Format(time.RFC3339Nano)}
	}
	metrics := []store.K8sMetricSample{
		// api: ~100ms before, ~200ms after → regression
		lat("api", 100, deployAt.Add(-60*time.Minute)),
		lat("api", 100, deployAt.Add(-30*time.Minute)),
		lat("api", 200, deployAt.Add(30*time.Minute)),
		lat("api", 210, deployAt.Add(60*time.Minute)),
		// calm: ~100ms before & after → no regression
		lat("calm", 100, deployAt.Add(-30*time.Minute)),
		lat("calm", 105, deployAt.Add(30*time.Minute)),
	}
	out := AnalyzeLatencyRegressions(revs, metrics, now, 24*time.Hour)
	if len(out) != 1 || out[0].ResourceName != "api" || out[0].Condition != "PostDeploymentLatency" {
		t.Fatalf("expected one PostDeploymentLatency for api, got %+v", out)
	}
	if out[0].Severity != "high" {
		t.Fatalf("latency regression should be high: %+v", out[0])
	}
}

func TestAnalyzeLatencyRegressionsNeedsBothSides(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	deployAt := now.Add(-1 * time.Hour)
	revs := []store.K8sResourceRevision{{Kind: "Deployment", Namespace: "prod", Name: "api", ChangeKind: "updated", ObservedAt: deployAt.Format(time.RFC3339Nano)}}
	// Only after-deploy samples → cannot compare → no finding.
	metrics := []store.K8sMetricSample{
		{Namespace: "prod", ResourceName: "api", LatencyMS: 999, ObservedAt: deployAt.Add(10 * time.Minute).Format(time.RFC3339Nano)},
	}
	if out := AnalyzeLatencyRegressions(revs, metrics, now, 24*time.Hour); len(out) != 0 {
		t.Fatalf("should not flag without before-deploy baseline, got %+v", out)
	}
}
