package proxy

import (
	"testing"

	"clustara/internal/store"
)

func TestScoreServiceInventoryMatchUsesStrongSignalsBeforeName(t *testing.T) {
	instance := store.K8sServiceInstance{ID: "svc-1", Name: "orders", Namespace: "prod"}
	tests := []struct {
		name string
		item store.K8sInventoryItem
		want int
	}{
		{"explicit ID", store.K8sInventoryItem{Labels: map[string]string{"clustara.io/service-instance-id": "svc-1"}}, 100},
		{"standard instance label", store.K8sInventoryItem{Labels: map[string]string{"app.kubernetes.io/instance": "orders"}}, 95},
		{"standard name label", store.K8sInventoryItem{Labels: map[string]string{"app.kubernetes.io/name": "orders"}}, 85},
		{"pod naming", store.K8sInventoryItem{Name: "orders-7db7f"}, 65},
		{"namespace only is insufficient", store.K8sInventoryItem{Name: "unrelated"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reasons := scoreServiceInventoryMatch(instance, tt.item)
			if got != tt.want || (got > 0 && len(reasons) == 0) {
				t.Fatalf("score=%d reasons=%v want=%d", got, reasons, tt.want)
			}
		})
	}
}

func TestServiceWorkloadRelatedUsesLabelsAndNaming(t *testing.T) {
	root := store.K8sInventoryItem{Kind: "Deployment", Name: "payments", Labels: map[string]string{"app.kubernetes.io/name": "payments"}}
	if !serviceWorkloadRelated(root, store.K8sInventoryItem{Kind: "Pod", Name: "random", Labels: map[string]string{"app.kubernetes.io/name": "payments"}}) {
		t.Fatal("standard app label should associate Pod")
	}
	if !serviceWorkloadRelated(root, store.K8sInventoryItem{Kind: "Pod", Name: "payments-abc"}) {
		t.Fatal("workload Pod naming should associate Pod")
	}
	if serviceWorkloadRelated(root, store.K8sInventoryItem{Kind: "Pod", Name: "unrelated"}) {
		t.Fatal("unrelated Pod must not be associated")
	}
}
