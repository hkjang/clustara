package proxy

import (
	"net/http/httptest"
	"testing"

	"clustara/internal/store"
)

func TestRolloutProgressByWorkloadKind(t *testing.T) {
	tests := []struct {
		item                        store.K8sInventoryItem
		desired, updated, available int
	}{
		{store.K8sInventoryItem{Kind: "Deployment", Spec: map[string]any{"replicas": float64(3)}, StatusObject: map[string]any{"updatedReplicas": float64(2), "availableReplicas": float64(1)}}, 3, 2, 1},
		{store.K8sInventoryItem{Kind: "DaemonSet", StatusObject: map[string]any{"desiredNumberScheduled": float64(5), "updatedNumberScheduled": float64(4), "numberAvailable": float64(3)}}, 5, 4, 3},
	}
	for _, tt := range tests {
		if rolloutDesired(tt.item) != tt.desired || rolloutUpdated(tt.item) != tt.updated || rolloutAvailable(tt.item) != tt.available {
			t.Fatalf("bad progress for %s", tt.item.Kind)
		}
	}
}

func TestRolloutSuperAdminDirectForLegacyAdminTokenMode(t *testing.T) {
	s := &Server{}
	if !s.rolloutSuperAdmin(httptest.NewRequest("POST", "/api/v1/workloads/rollout", nil)) {
		t.Fatal("auth-disabled ADMIN_TOKEN mode should retain highest-admin direct execution")
	}
}

func TestRolloutFailureAndOwnerMatching(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "prod", Spec: map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}}}
	pod := store.K8sInventoryItem{Kind: "Pod", Namespace: "prod", Labels: map[string]string{"app": "api"}}
	if !podOwnedByWorkload(pod, target) {
		t.Fatal("selector should match pod")
	}
	target.StatusObject = map[string]any{"conditions": []any{map[string]any{"type": "Progressing", "reason": "ProgressDeadlineExceeded"}}}
	if !rolloutConditionFailed(target) {
		t.Fatal("deadline failure must be detected")
	}
}
