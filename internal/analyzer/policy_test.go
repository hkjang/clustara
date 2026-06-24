package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestEvaluatePolicies(t *testing.T) {
	policies := []Policy{
		{ID: "1", Name: "no-priv", RuleType: "disallow_privileged", Action: "Deny", Enabled: true},
		{ID: "2", Name: "no-latest", RuleType: "disallow_latest_tag", Action: "Warn", Enabled: true},
		{ID: "3", Name: "limits", RuleType: "require_resource_limits", Action: "Warn", Enabled: true},
		{ID: "4", Name: "disabled", RuleType: "disallow_host_network", Action: "Deny", Enabled: false},
	}
	spec := map[string]any{"template": map[string]any{"spec": map[string]any{
		"hostNetwork": true, // would violate #4 but it's disabled
		"containers": []any{map[string]any{"name": "c", "image": "x:latest",
			"securityContext": map[string]any{"privileged": true}}},
	}}}
	results := EvaluatePolicies("Deployment", spec, policies)
	if len(results) != 3 { // disabled policy excluded
		t.Fatalf("expected 3 results (disabled excluded), got %d", len(results))
	}
	byRule := map[string]PolicyResult{}
	for _, r := range results {
		byRule[r.RuleType] = r
	}
	if !byRule["disallow_privileged"].Violated || byRule["disallow_privileged"].Action != "Deny" {
		t.Errorf("privileged should be a Deny violation: %+v", byRule["disallow_privileged"])
	}
	if !byRule["disallow_latest_tag"].Violated {
		t.Errorf("latest tag should violate")
	}
	if !byRule["require_resource_limits"].Violated {
		t.Errorf("missing limits should violate")
	}
}

func TestEvaluatePoliciesCompliantPasses(t *testing.T) {
	policies := []Policy{{ID: "1", Name: "no-priv", RuleType: "disallow_privileged", Action: "Deny", Enabled: true}}
	spec := map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "c", "image": "x@sha256:abc"}}}}}
	for _, r := range EvaluatePolicies("Deployment", spec, policies) {
		if r.Violated {
			t.Fatalf("compliant workload should not violate: %+v", r)
		}
	}
}

func TestCheckPolicyCompliance(t *testing.T) {
	policies := []Policy{{ID: "1", Name: "wild", RuleType: "disallow_wildcard_rbac", Action: "Deny", Enabled: true}}
	items := []store.K8sInventoryItem{
		{Kind: "ClusterRole", Name: "admin", Spec: map[string]any{"rules": []any{map[string]any{"verbs": []any{"*"}, "resources": []any{"*"}}}}},
		{Kind: "ClusterRole", Name: "reader", Spec: map[string]any{"rules": []any{map[string]any{"verbs": []any{"get"}, "resources": []any{"pods"}}}}},
		{Kind: "ConfigMap", Name: "cfg"}, // not evaluated
	}
	v := CheckPolicyCompliance(items, policies)
	if len(v) != 1 || v[0].Name != "admin" || v[0].RuleType != "disallow_wildcard_rbac" {
		t.Fatalf("expected only 'admin' ClusterRole to violate, got %+v", v)
	}
}
