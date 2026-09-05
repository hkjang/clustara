package action

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// TestTargetKindIssue pins which resource kinds each action may address. The executor builds one
// fixed URL shape per action, so a record naming another kind would change a different object
// than the one the approver read.
func TestTargetKindIssue(t *testing.T) {
	for _, tc := range []struct {
		action, kind string
		wantIssue    bool
	}{
		{"delete_pod", "Pod", false},
		{"delete_pod", "pods", false},
		{"delete_pod", "po", false},
		{"delete_pod", "v1/Pod", false},
		{"delete_pod", "", false}, // a blank kind claims nothing to contradict
		{"delete_pod", "Deployment", true},
		{"delete_pod", "StatefulSet", true},
		{"delete_pod", "Node", true},
		{"scale", "Deployment", false},
		{"scale", "deploy", false},
		{"scale", "apps/v1/StatefulSet", false},
		{"scale", "DaemonSet", true}, // no /scale subresource
		{"scale", "Pod", true},
		{"rollout_restart", "DaemonSet", false},
		{"rollout_restart", "ds", false},
		{"rollout_restart", "Pod", true},
		{"cordon", "Node", false},
		{"cordon", "nodes", false},
		{"cordon", "Pod", true},
		{"uncordon", "Deployment", true},
		{"drain", "Node", false},
		{"patch", "ConfigMap", false},                   // no fixed target type
		{"jupyter_server_stop", "JupyterServer", false}, // not a Kubernetes action
	} {
		issue := TargetKindIssue(tc.action, tc.kind)
		if tc.wantIssue && issue == "" {
			t.Fatalf("%s on kind %q must be reported as a target mismatch", tc.action, tc.kind)
		}
		if !tc.wantIssue && issue != "" {
			t.Fatalf("%s on kind %q must be accepted, got %q", tc.action, tc.kind, issue)
		}
		if err := TargetKindIssueErr(tc.action, tc.kind); (err != nil) != tc.wantIssue {
			t.Fatalf("%s on kind %q: TargetKindIssueErr disagrees with TargetKindIssue (%v vs %q)", tc.action, tc.kind, err, issue)
		}
	}
}

// TestAssessImpactDeletePodOnWorkloadKindIsBlocked covers the request nothing used to check:
// delete_pod always deletes the *Pod* named resource_name, so a record approved as
// "Deployment/web delete_pod" would delete a Pod that is not the workload it names.
func TestAssessImpactDeletePodOnWorkloadKindIsBlocked(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "web", Spec: map[string]any{"replicas": float64(3)}}
	imp := AssessImpact("delete_pod", nil, target, true, nil)
	if len(imp.Blockers) == 0 {
		t.Fatalf("delete_pod against a Deployment must be blocked, got %+v", imp)
	}
	joined := strings.Join(imp.Blockers, " ")
	// Not the generic "standalone pod" blocker: the mismatch itself must be named, because the
	// object at risk is a Pod that merely shares the Deployment's name.
	if !strings.Contains(joined, "Deployment") || !strings.Contains(joined, "Pod") {
		t.Fatalf("blocker should name the requested kind and the kind the action addresses, got %+v", imp.Blockers)
	}
}

// TestAssessImpactKindMismatchOnNodeAction covers the other fixed-target action: cordon patches
// /api/v1/nodes/{resource_name} whatever kind the request claims.
func TestAssessImpactKindMismatchOnNodeAction(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Pod", Namespace: "prod", Name: "api-7d9-xyz"}
	imp := AssessImpact("cordon", nil, target, true, nil)
	if len(imp.Blockers) == 0 {
		t.Fatalf("cordon against a Pod must be blocked, got %+v", imp)
	}
	if !strings.Contains(strings.Join(imp.Blockers, " "), "Node") {
		t.Fatalf("blocker should say the action only addresses a Node, got %+v", imp.Blockers)
	}
}

// TestAssessImpactUnobservedScaleDoesNotInventCurrentReplicas covers the target the inventory has
// no row for: the handlers fall back to the zero value, whose replicas read as 0, so the approval
// record said "replicas 0 → 5 (+5)" for a workload whose real replica count was never seen.
func TestAssessImpactUnobservedScaleDoesNotInventCurrentReplicas(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "api"}
	imp := AssessImpact("scale", map[string]any{"replicas": float64(5)}, target, false, nil)
	if strings.Contains(imp.Summary, "0 → 5") || strings.Contains(imp.Summary, "+5") {
		t.Fatalf("must not claim a current replica count it never observed, got %q", imp.Summary)
	}
	if !strings.Contains(imp.Summary, "5") {
		t.Fatalf("summary should still carry the requested replicas, got %q", imp.Summary)
	}
	if imp.Details["current_replicas"] != nil {
		t.Fatalf("current_replicas must stay unset for an unobserved target, got %v", imp.Details["current_replicas"])
	}
	if len(imp.Blockers) == 0 {
		t.Fatalf("an unobserved target must reach the approval queue, got %+v", imp)
	}
}

// TestAssessImpactUnobservedDeleteDoesNotClaimStandalone covers the same zero value read through
// podControllerOwned: an absent target carries no labels, which used to render as the factual
// claim "standalone Pod, nothing recreates it".
func TestAssessImpactUnobservedDeleteDoesNotClaimStandalone(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Pod", Namespace: "default", Name: "api-123"}
	imp := AssessImpact("delete_pod", nil, target, false, nil)
	if strings.Contains(imp.Summary, "standalone") {
		t.Fatalf("must not claim the pod is standalone when it was never observed, got %q", imp.Summary)
	}
	if imp.Details["controller_owned"] != nil {
		t.Fatalf("controller_owned must stay unset for an unobserved target, got %v", imp.Details["controller_owned"])
	}
	if len(imp.Blockers) == 0 {
		t.Fatalf("an unobserved delete target must reach the approval queue, got %+v", imp)
	}
}

// TestAssessImpactObservedTargetKeepsItsCurrentState is the false-positive guard: the normal
// path — target present in the inventory, kind matching the action — reports the real diff and
// carries no extra blocker.
func TestAssessImpactObservedTargetKeepsItsCurrentState(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "default", Name: "api", Spec: map[string]any{"replicas": float64(2)}}
	imp := AssessImpact("scale", map[string]any{"replicas": float64(5)}, target, true, nil)
	if !strings.Contains(imp.Summary, "2 → 5 (+3)") {
		t.Fatalf("observed target should keep the real diff, got %q", imp.Summary)
	}
	if len(imp.Blockers) != 0 {
		t.Fatalf("observed, kind-matching scale needs no blocker, got %+v", imp.Blockers)
	}
	if imp.Details["current_replicas"] != 2 {
		t.Fatalf("current_replicas should be 2, got %v", imp.Details["current_replicas"])
	}
}
