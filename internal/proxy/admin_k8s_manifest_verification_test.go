package proxy

import (
	"testing"

	"clustara/internal/store"
)

func TestConfigChangeJobHealthUsesJobConditions(t *testing.T) {
	tests := []struct {
		name      string
		item      store.K8sInventoryItem
		unhealthy bool
		state     string
	}{
		{
			name: "completed ignores generic low score and risk",
			item: store.K8sInventoryItem{Kind: "Job", Status: "Succeeded", HealthScore: 20, RiskLevel: "high",
				StatusObject: map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}},
			state: "succeeded",
		},
		{
			name: "failed condition wins",
			item: store.K8sInventoryItem{Kind: "Job", StatusObject: map[string]any{"conditions": []any{
				map[string]any{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"},
			}}},
			unhealthy: true, state: "failed",
		},
		{
			name:  "active is healthy while observing",
			item:  store.K8sInventoryItem{Kind: "Job", StatusObject: map[string]any{"active": float64(1)}},
			state: "active",
		},
		{
			name:  "completions target reached",
			item:  store.K8sInventoryItem{Kind: "Job", Spec: map[string]any{"completions": float64(3)}, StatusObject: map[string]any{"succeeded": float64(3)}},
			state: "succeeded",
		},
		{
			name:  "successful retry is not failed by failed pod count",
			item:  store.K8sInventoryItem{Kind: "Job", Status: "Succeeded", StatusObject: map[string]any{"failed": float64(1), "succeeded": float64(1)}},
			state: "succeeded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unhealthy, state, reasons := configChangeHealth(tt.item)
			if unhealthy != tt.unhealthy || state != tt.state || len(reasons) == 0 {
				t.Fatalf("got unhealthy=%v state=%q reasons=%v", unhealthy, state, reasons)
			}
		})
	}
}

func TestManifestNamespaceEqualDefaultsEmptyNamespace(t *testing.T) {
	if !manifestNamespaceEqual("", "default") {
		t.Fatal("empty namespace must match Kubernetes default namespace")
	}
	if manifestNamespaceEqual("prod", "default") {
		t.Fatal("different namespaces must not match")
	}
}

func TestManifestLiveJobStatus(t *testing.T) {
	status := manifestLiveStatus("Job", map[string]any{"conditions": []any{
		map[string]any{"type": "Complete", "status": "True"},
	}})
	if status != "Succeeded" {
		t.Fatalf("completed live Job status = %q", status)
	}
}
