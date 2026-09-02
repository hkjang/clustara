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

// TestAssessImpactScaleStringReplicasMatchesExecutor pins the impact preview to the value the
// executor will actually apply. The proxy's intFromParams parses the JSON string form, so a
// request carrying {"replicas":"5"} scales to 5 — the approval record must not say "→ 0".
func TestAssessImpactScaleStringReplicasMatchesExecutor(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "api", Spec: map[string]any{"replicas": float64(2)}}
	imp := AssessImpact("scale", map[string]any{"replicas": "5"}, target, nil)
	if !strings.Contains(imp.Summary, "2 → 5") {
		t.Fatalf("string replicas must read as 5 like the executor does, got %q", imp.Summary)
	}
	if imp.Details["desired_replicas"] != 5 {
		t.Fatalf("desired_replicas should be 5, got %v", imp.Details["desired_replicas"])
	}
	if len(imp.Blockers) != 0 {
		t.Fatalf("scale to 5 needs no blocker, got %+v", imp.Blockers)
	}
}

// TestAssessImpactScaleToZeroIsBlocked covers the one action Classify lets through without
// approval: scaling to 0 replicas is a full outage, so it must reach the approval queue.
func TestAssessImpactScaleToZeroIsBlocked(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "api", Spec: map[string]any{"replicas": float64(3)}}
	imp := AssessImpact("scale", map[string]any{"replicas": float64(0)}, target, nil)
	if len(imp.Blockers) == 0 {
		t.Fatalf("scale to zero replicas must be blocked, got %+v", imp)
	}
	if !strings.Contains(imp.Summary, "3 → 0") {
		t.Fatalf("summary should still show the diff, got %q", imp.Summary)
	}
	if d := Classify("scale"); d.RequiresApproval {
		t.Fatalf("guard assumption changed: scale is expected to be the no-approval action, got %+v", d)
	}
}

// TestAssessImpactScaleUnreadableReplicas covers the values the executor refuses. Reporting
// them as a scale to zero would put a wrong, and alarming, diff in the approval record.
func TestAssessImpactScaleUnreadableReplicas(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "api", Spec: map[string]any{"replicas": float64(3)}}
	for _, tc := range []struct {
		name   string
		params map[string]any
	}{
		{"missing", map[string]any{}},
		{"nil params", nil},
		{"non-numeric string", map[string]any{"replicas": "many"}},
		{"negative", map[string]any{"replicas": float64(-1)}},
		{"wrong type", map[string]any{"replicas": true}},
	} {
		imp := AssessImpact("scale", tc.params, target, nil)
		if len(imp.Blockers) == 0 {
			t.Fatalf("%s: unreadable replicas must be blocked, got %+v", tc.name, imp)
		}
		if strings.Contains(imp.Summary, "→ 0") {
			t.Fatalf("%s: must not claim a scale to zero, got %q", tc.name, imp.Summary)
		}
		if imp.Details["desired_replicas"] != nil {
			t.Fatalf("%s: desired_replicas must stay unset, got %v", tc.name, imp.Details["desired_replicas"])
		}
	}
}

// TestAssessImpactUncordonDoesNotDescribeCordon guards the operator-facing text on the approval
// gate: uncordon re-opens scheduling and evicts nothing, the opposite of what cordon does.
func TestAssessImpactUncordonDoesNotDescribeCordon(t *testing.T) {
	all := []store.K8sInventoryItem{
		{Kind: "Pod", Namespace: "a", Name: "p1", Spec: map[string]any{"nodeName": "node-1"}},
	}
	node := store.K8sInventoryItem{Kind: "Node", Name: "node-1"}

	up := AssessImpact("uncordon", nil, node, all)
	if strings.Contains(up.Summary, "차단") {
		t.Fatalf("uncordon summary must not say scheduling is blocked, got %q", up.Summary)
	}
	if !strings.Contains(up.Summary, "uncordon") {
		t.Fatalf("uncordon summary should name the action, got %q", up.Summary)
	}
	if up.Details["running_pods"].(int) != 1 {
		t.Fatalf("expected 1 running pod on node-1, got %v", up.Details["running_pods"])
	}

	down := AssessImpact("cordon", nil, node, all)
	if !strings.Contains(down.Summary, "차단") {
		t.Fatalf("cordon summary should say new scheduling is blocked, got %q", down.Summary)
	}
}

// TestAssessImpactPatchBlockerIsDeterministic keeps map iteration order out of the DryRunDiff
// the approval record stores: the same request must always produce the same text.
func TestAssessImpactPatchBlockerIsDeterministic(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Name: "api"}
	params := map[string]any{"image": "x:2", "command": []any{"sh"}, "nodeSelector": map[string]any{}, "tolerations": []any{}, "securityContext": map[string]any{}}
	first := AssessImpact("patch", params, target, nil)
	for i := 0; i < 50; i++ {
		got := AssessImpact("patch", params, target, nil)
		if strings.Join(got.Blockers, "|") != strings.Join(first.Blockers, "|") {
			t.Fatalf("blocker text is not stable: %q vs %q", got.Blockers, first.Blockers)
		}
		if strings.Join(got.Details["fields"].([]string), "|") != strings.Join(first.Details["fields"].([]string), "|") {
			t.Fatalf("fields detail is not stable: %v vs %v", got.Details["fields"], first.Details["fields"])
		}
	}
	if !strings.Contains(first.Blockers[0], "command, nodeSelector, securityContext, tolerations") {
		t.Fatalf("disallowed fields should be listed sorted, got %q", first.Blockers[0])
	}
}
