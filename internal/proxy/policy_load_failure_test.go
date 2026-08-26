package proxy

import (
	"errors"
	"testing"

	"clustara/internal/analyzer"
)

// The premise behind every fix in this family: analysing a manifest with no
// policies loaded produces a plan that is indistinguishable from a compliant one.
// Denied and RequiresApproval are both false, so a caller that only inspects the
// plan cannot tell "policy passed" from "policy never ran".
func TestEmptyPolicySetAnalysesAsFullyCompliant(t *testing.T) {
	docs := []map[string]any{{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "risky", "namespace": "prod"},
		"spec": map[string]any{
			"hostNetwork": true,
			"containers": []any{map[string]any{
				"name": "app", "image": "app:latest",
				"securityContext": map[string]any{"privileged": true},
			}},
		},
	}}
	plan := analyzer.AnalyzeStackManifest(docs, nil)
	if plan.Denied {
		t.Fatal("precondition changed: a nil policy set now denies")
	}
	if len(plan.PolicyViolations) != 0 {
		t.Fatalf("precondition changed: a nil policy set now reports violations: %v", plan.PolicyViolations)
	}
	// Even a privileged, host-network, :latest pod clears both gates. That is why a
	// discarded ListK8sPolicies error had to be turned into a refusal rather than
	// letting the plan speak for itself.
}

// Responses that carry an analysis plan must state whether a rule set was actually
// loaded, so a clean plan produced from nothing cannot be read as a pass.
func TestPolicyCheckStatusDistinguishesUnavailableFromChecked(t *testing.T) {
	ok := policyCheckStatus(nil)
	if got := asStr(ok["status"]); got != "checked" {
		t.Errorf("successful load reported %q, want checked", got)
	}
	if _, present := ok["error"]; present {
		t.Error("successful load must not carry an error field")
	}

	failed := policyCheckStatus(errors.New("database is closed"))
	if got := asStr(failed["status"]); got != "unavailable" {
		t.Errorf("failed load reported %q, want unavailable", got)
	}
	if got := asStr(failed["error"]); got != "database is closed" {
		t.Errorf("failed load lost the cause: %q", got)
	}
}
