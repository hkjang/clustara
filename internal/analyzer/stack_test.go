package analyzer

import "testing"

func TestAnalyzeStackManifest(t *testing.T) {
	docs := []map[string]any{
		{ // Deployment with a privileged container → policy violation
			"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": "web", "namespace": "prod"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"containers": []any{map[string]any{"name": "c", "image": "x:1.0", "securityContext": map[string]any{"privileged": true}}},
			}}},
		},
		{ // Secret → approval gate
			"apiVersion": "v1", "kind": "Secret",
			"metadata": map[string]any{"name": "db", "namespace": "prod"},
		},
		{"kind": "", "metadata": map[string]any{}}, // invalid → warning
	}
	policies := []Policy{{ID: "1", Name: "no-priv", RuleType: "disallow_privileged", Action: "Deny", Enabled: true}}

	plan := AnalyzeStackManifest(docs, policies)
	if len(plan.Resources) != 2 {
		t.Fatalf("expected 2 valid resources, got %d: %+v", len(plan.Resources), plan.Resources)
	}
	if len(plan.Warnings) == 0 {
		t.Fatalf("invalid doc should produce a warning")
	}
	// Privileged Deny → denied + violation.
	if !plan.Denied || len(plan.PolicyViolations) == 0 {
		t.Fatalf("privileged container should trigger Deny violation: %+v", plan)
	}
	// Secret → approval.
	secretApproval := false
	for _, r := range plan.Resources {
		if r.Kind == "Secret" && r.Approval {
			secretApproval = true
		}
	}
	if !secretApproval {
		t.Fatalf("Secret should require approval: %+v", plan.Resources)
	}
	if !plan.RequiresApproval {
		t.Fatalf("plan should require approval (deny + secret): %+v", plan)
	}

	// Empty manifest → warning, no resources.
	empty := AnalyzeStackManifest(nil, policies)
	if len(empty.Resources) != 0 || len(empty.Warnings) == 0 {
		t.Fatalf("empty manifest should warn: %+v", empty)
	}

	// Clean manifest, no sensitive kinds, no violations → allow.
	clean := AnalyzeStackManifest([]map[string]any{
		{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "cfg", "namespace": "prod"}},
	}, policies)
	if clean.Denied || clean.RequiresApproval {
		t.Fatalf("clean configmap should not require approval: %+v", clean)
	}
}
