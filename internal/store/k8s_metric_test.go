package store

import (
	"context"
	"testing"
)

func TestK8sMetricSamplesFilteredIncludesGPUAndScopesRows(t *testing.T) {
	db := openStackTestStore(t)
	ctx := context.Background()
	samples := []K8sMetricSample{
		{ID: "m1", ClusterID: "c1", ResourceKind: "Node", ResourceName: "n1", CPUMillicores: 100, ObservedAt: "2026-07-10T01:00:00Z"},
		{ID: "m2", ClusterID: "c1", ResourceKind: "Node", ResourceName: "n1", GPUObserved: true, GPUUtilizationPct: 72.5, GPUMemoryUsedBytes: 1024, GPUTemperatureC: 67, ObservedAt: "2026-07-10T02:00:00Z"},
		{ID: "m3", ClusterID: "c2", ResourceKind: "Node", ResourceName: "n1", CPUMillicores: 999, ObservedAt: "2026-07-10T03:00:00Z"},
		{ID: "m4", ClusterID: "c1", ResourceKind: "Pod", ResourceName: "p1", CPUMillicores: 50, ObservedAt: "2026-07-10T03:00:00Z"},
	}
	for _, sample := range samples {
		if err := db.InsertK8sMetricSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ListK8sMetricSamplesFiltered(ctx, K8sMetricSampleFilter{
		ClusterID: "c1", ResourceKind: "Node", ResourceName: "n1", Since: "2026-07-10T01:30:00Z", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].GPUObserved || got[0].GPUUtilizationPct != 72.5 || got[0].GPUTemperatureC != 67 {
		t.Fatalf("unexpected filtered GPU samples: %+v", got)
	}
}
