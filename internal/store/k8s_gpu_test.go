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
