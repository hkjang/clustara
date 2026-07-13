package analyzer

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestBuildMetricRiskIncidentsDetectsPodPressureAndForecast(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{{ClusterID: "c1", Kind: "Pod", Namespace: "prod", Name: "api", Spec: map[string]any{
		"containers": []any{map[string]any{"resources": map[string]any{"limits": map[string]any{"cpu": "1000m", "memory": "1Gi"}}}},
	}}}
	metrics := []store.K8sMetricSample{}
	for i := 0; i < 6; i++ {
		metrics = append(metrics, store.K8sMetricSample{ClusterID: "c1", Namespace: "prod", ResourceKind: "Pod", ResourceName: "api",
			CPUMillicores: 950 - float64(i*10), MemoryBytes: float64(950-i*10) * (1 << 20), ObservedAt: now.Add(-time.Duration(i) * 15 * time.Minute).Format(time.RFC3339Nano)})
	}
	drafts := BuildMetricRiskIncidents(items, metrics, nil, now)
	foundCPU, foundMemory := false, false
	for _, draft := range drafts {
		if draft.Condition == "PodCPUSaturation" {
			foundCPU = true
		}
		if draft.Condition == "PodMemorySaturation" {
			foundMemory = true
		}
		if len(draft.Key) < len("predictive:") || draft.Key[:len("predictive:")] != "predictive:" {
			t.Fatalf("unexpected key: %s", draft.Key)
		}
	}
	if !foundCPU || !foundMemory {
		t.Fatalf("expected CPU and memory pressure incidents: %+v", drafts)
	}
}
