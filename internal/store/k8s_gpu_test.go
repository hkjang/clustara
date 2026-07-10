package store

import (
	"context"
	"testing"
)

func TestK8sGPUSampleRoundTripAndFilter(t *testing.T) {
	db := openStackTestStore(t)
	ctx := context.Background()
	for _, sample := range []K8sGPUSample{
		{ID: "g1", ClusterID: "c1", NodeName: "n1", Namespace: "ml", Pod: "p1", Container: "vllm", GPUUUID: "GPU-1", GPUModel: "H100", MIGProfile: "1g.10gb", MIGInstanceID: "2", UtilizationPct: 71, TensorActivePct: 55, FramebufferUsedBytes: 1024, TemperatureC: 67, XIDErrors: 0, ObservedAt: "2026-07-10T01:00:00Z"},
		{ID: "g2", ClusterID: "c2", NodeName: "n1", Namespace: "ml", Pod: "p1", GPUUUID: "GPU-2", ObservedAt: "2026-07-10T02:00:00Z"},
	} {
		if err := db.InsertK8sGPUSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ListK8sGPUSamples(ctx, K8sGPUSampleFilter{ClusterID: "c1", Namespace: "ml", Pod: "p1", Since: "2026-07-10T00:30:00Z", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].GPUModel != "H100" || got[0].MIGProfile != "1g.10gb" || got[0].TensorActivePct != 55 {
		t.Fatalf("unexpected GPU roundtrip: %+v", got)
	}
}

func TestPruneK8sMonitoringSamples(t *testing.T) {
	db := openStackTestStore(t)
	ctx := context.Background()
	for _, sample := range []K8sGPUSample{
		{ID: "old-gpu", ClusterID: "c1", NodeName: "n1", ObservedAt: "2026-01-01T00:00:00Z"},
		{ID: "new-gpu", ClusterID: "c1", NodeName: "n1", ObservedAt: "2026-07-10T00:00:00Z"},
	} {
		if err := db.InsertK8sGPUSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	for _, sample := range []K8sMetricSample{
		{ID: "old-node", ClusterID: "c1", ResourceKind: "Node", ResourceName: "n1", ObservedAt: "2026-01-01T00:00:00Z"},
		{ID: "new-node", ClusterID: "c1", ResourceKind: "Node", ResourceName: "n1", ObservedAt: "2026-07-10T00:00:00Z"},
	} {
		if err := db.InsertK8sMetricSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := db.PruneK8sMonitoringSamples(ctx, "2026-06-01T00:00:00Z")
	if err != nil || deleted != 2 {
		t.Fatalf("prune deleted=%d err=%v", deleted, err)
	}
	gpu, _ := db.ListK8sGPUSamples(ctx, K8sGPUSampleFilter{ClusterID: "c1", Limit: 10})
	metrics, _ := db.ListK8sMetricSamplesFiltered(ctx, K8sMetricSampleFilter{ClusterID: "c1", Limit: 10})
	if len(gpu) != 1 || gpu[0].ID != "new-gpu" || len(metrics) != 1 || metrics[0].ID != "new-node" {
		t.Fatalf("unexpected retained rows gpu=%+v metrics=%+v", gpu, metrics)
	}
}
