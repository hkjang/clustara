package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func clusterRoleDoc(rules []any) map[string]any {
	return map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": "sneaky-admin"},
		"rules":      rules,
	}
}

var wildcardRule = []any{map[string]any{
	"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"},
}}

func rbacPolicy() []Policy {
	return []Policy{{ID: "p", Name: "no wildcard rbac", RuleType: "disallow_wildcard_rbac", Action: "Deny", Enabled: true}}
}

// A Role or ClusterRole keeps its `rules` at the document root, not under `spec`.
// AnalyzeStackManifest handed every rule doc["spec"], which is absent for RBAC
// objects, so disallow_wildcard_rbac could never fire on the deploy path: a
// ClusterRole granting */*/* — cluster-admin in all but name — passed the stack
// apply gate while the live-inventory compliance scan flagged the same object.
func TestWildcardRBACIsDeniedOnTheManifestPath(t *testing.T) {
	plan := AnalyzeStackManifest([]map[string]any{clusterRoleDoc(wildcardRule)}, rbacPolicy())
	if !plan.Denied {
		t.Fatalf("wildcard ClusterRole was not denied: violations=%v warnings=%v", plan.PolicyViolations, plan.Warnings)
	}
	if len(plan.PolicyViolations) != 1 || plan.PolicyViolations[0].RuleType != "disallow_wildcard_rbac" {
		t.Fatalf("unexpected violations: %+v", plan.PolicyViolations)
	}
}

// The deploy path and the compliance scan must reach the same verdict on the same
// object; the split between them is what hid this.
func TestManifestAndInventoryAgreeOnWildcardRBAC(t *testing.T) {
	plan := AnalyzeStackManifest([]map[string]any{clusterRoleDoc(wildcardRule)}, rbacPolicy())
	item := store.K8sInventoryItem{Kind: "ClusterRole", Name: "sneaky-admin", Spec: map[string]any{"rules": wildcardRule}}
	scan := CheckPolicyCompliance([]store.K8sInventoryItem{item}, rbacPolicy())
	if got, want := len(plan.PolicyViolations), len(scan); got != want {
		t.Fatalf("manifest path found %d violations, inventory scan found %d", got, want)
	}
}

// A scoped Role must still pass, or the rule becomes noise.
func TestScopedRBACIsNotDenied(t *testing.T) {
	scoped := []any{map[string]any{
		"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get", "list"},
	}}
	doc := clusterRoleDoc(scoped)
	doc["kind"] = "Role"
	plan := AnalyzeStackManifest([]map[string]any{doc}, rbacPolicy())
	if plan.Denied {
		t.Fatalf("scoped Role must not be denied: %+v", plan.PolicyViolations)
	}
}

func TestPolicySpecOfDocResolvesPayloadLocation(t *testing.T) {
	// spec-bearing kinds keep using spec
	deployment := map[string]any{"kind": "Deployment", "spec": map[string]any{"replicas": 3}}
	if got := PolicySpecOfDoc("Deployment", deployment); got["replicas"] != 3 {
		t.Errorf("Deployment must read from spec, got %v", got)
	}
	// top-level-payload kinds read the document root
	if got := PolicySpecOfDoc("ClusterRole", clusterRoleDoc(wildcardRule)); len(asAnySlice(got["rules"])) != 1 {
		t.Errorf("ClusterRole must expose top-level rules, got %v", got)
	}
	// an unknown kind with no spec yields nothing rather than the whole document
	if got := PolicySpecOfDoc("SomeCRD", map[string]any{"kind": "SomeCRD", "foo": "bar"}); len(got) != 0 {
		t.Errorf("unknown spec-less kind must yield an empty map, got %v", got)
	}
}

// Pod-bearing workloads must be unaffected by the change.
func TestSpecBearingWorkloadsStillEvaluated(t *testing.T) {
	doc := map[string]any{
		"kind": "Deployment", "apiVersion": "apps/v1",
		"metadata": map[string]any{"name": "api"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "app", "image": "app:1.0",
				"securityContext": map[string]any{"privileged": true}}},
		}}},
	}
	plan := AnalyzeStackManifest([]map[string]any{doc},
		[]Policy{{ID: "p", Name: "no priv", RuleType: "disallow_privileged", Action: "Deny", Enabled: true}})
	if !plan.Denied {
		t.Fatalf("privileged Deployment must still be denied: %+v", plan.PolicyViolations)
	}
}
