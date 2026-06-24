package action

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestAssessImpactScale(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "api", Spec: map[string]any{"replicas": float64(2)}}
	imp := AssessImpact("scale", map[string]any{"replicas": float64(5)}, target, nil)
	if !strings.Contains(imp.Summary, "2 → 5") {
		t.Fatalf("scale summary should show replica diff, got %q", imp.Summary)
	}
	if len(imp.Blockers) != 0 {
		t.Fatalf("scale should have no blockers, got %+v", imp.Blockers)
	}
}

func TestAssessImpactDeleteStandalonePod(t *testing.T) {
	// Controller-owned pod -> no blocker.
	owned := store.K8sInventoryItem{Kind: "Pod", Namespace: "default", Name: "api-abc-1", Labels: map[string]string{"pod-template-hash": "abc"}}
	if imp := AssessImpact("delete_pod", nil, owned, nil); len(imp.Blockers) != 0 {
		t.Fatalf("controller-owned pod delete should not be blocked, got %+v", imp.Blockers)
	}
	// Standalone pod -> blocker.
	standalone := store.K8sInventoryItem{Kind: "Pod", Namespace: "default", Name: "debug", Labels: map[string]string{"app": "x"}}
	imp := AssessImpact("delete_pod", nil, standalone, nil)
	if len(imp.Blockers) == 0 {
		t.Fatalf("standalone pod delete must be blocked, got %+v", imp)
	}
}

func TestAssessImpactDrainCountsPodsAndLocalStorage(t *testing.T) {
	all := []store.K8sInventoryItem{
		{Kind: "Pod", Namespace: "a", Name: "p1", Spec: map[string]any{"nodeName": "node-1", "volumes": []any{map[string]any{"emptyDir": map[string]any{}}}}},
		{Kind: "Pod", Namespace: "b", Name: "p2", Spec: map[string]any{"nodeName": "node-1"}},
		{Kind: "Pod", Namespace: "c", Name: "p3", Spec: map[string]any{"nodeName": "node-2"}}, // other node
	}
	node := store.K8sInventoryItem{Kind: "Node", Name: "node-1"}
	imp := AssessImpact("drain", nil, node, all)
	if imp.Details["affected_pods"].(int) != 2 {
		t.Fatalf("expected 2 pods on node-1, got %v", imp.Details["affected_pods"])
	}
	if imp.Details["local_storage_pods"].(int) != 1 {
		t.Fatalf("expected 1 local-storage pod, got %v", imp.Details["local_storage_pods"])
	}
	if len(imp.Blockers) == 0 {
		t.Fatalf("drain must always carry a blocker")
	}
}

func TestAssessImpactPatchDisallowedField(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Name: "api"}
	imp := AssessImpact("patch", map[string]any{"image": "x:2", "command": []any{"sh"}}, target, nil)
	if len(imp.Blockers) == 0 {
		t.Fatalf("patch with disallowed field 'command' must be blocked, got %+v", imp)
	}
}
