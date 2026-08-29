package proxy

import (
	"context"
	"strings"
	"testing"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// disallow_wildcard_rbac is the only rule that reads Role/ClusterRole; every other rule
// reads a pod spec. So a cluster whose workloads were collected but whose RBAC objects
// were not still reports a healthy evaluable-resource count — the run looks complete —
// while the RBAC rule evaluates zero objects and contributes zero findings. A ClusterRole
// granting */*/* comes back compliant.
//
// This is the collector's normal behaviour, not an exceptional one: the RBAC list targets
// are Optional and an authorization failure on them is skipped silently, and the ClusterRole
// in the shipped agent install manifest does not request rbac.authorization.k8s.io at all.
func TestComplianceNamesRulesThatHadNothingToCheck(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	mustUpsertPolicy(t, db, "pol_limits", true)
	if err := db.UpsertK8sPolicy(context.Background(), store.K8sPolicy{
		ID: "pol_rbac", Name: "wildcard rbac", RuleType: "disallow_wildcard_rbac", Action: "Deny", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Workloads collected, RBAC not — exactly what a least-privilege collector produces.
	mustUpsertWorkload(t, db, "inv_api")

	body := getJSON(t, srv.URL+"/admin/k8s/policies/compliance")
	check, _ := body["policy_check"].(map[string]any)
	if check == nil {
		t.Fatalf("no policy_check: %v", body)
	}
	// The workload rule really did run over a real workload, so the run is not incomplete.
	// Declaring the whole thing unjudgeable would hide the workload findings, which are real.
	if check["status"] != "checked" {
		t.Fatalf("status = %v; the workload rule had a workload to check: %v", check["status"], check)
	}
	uncovered, _ := check["uncovered_rules"].([]any)
	if len(uncovered) != 1 {
		t.Fatalf("uncovered_rules = %v; an enabled RBAC rule with no Role/ClusterRole in the "+
			"inventory checked nothing, and 0 violations from it is not a pass: %v", check["uncovered_rules"], check)
	}
	first, _ := uncovered[0].(map[string]any)
	if first["rule_type"] != "disallow_wildcard_rbac" {
		t.Fatalf("uncovered rule = %v, want disallow_wildcard_rbac", first)
	}
	if reason, _ := check["reason"].(string); !strings.Contains(reason, "disallow_wildcard_rbac") {
		t.Fatalf("reason must name the rule that checked nothing, got %q", reason)
	}
}

// Once the RBAC objects are actually collected the rule has something to run against and
// the caveat must disappear — a warning on every report is the same as no warning.
func TestComplianceIsQuietOnceEveryRuleHasSomethingToCheck(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	if err := db.UpsertK8sPolicy(context.Background(), store.K8sPolicy{
		ID: "pol_rbac", Name: "wildcard rbac", RuleType: "disallow_wildcard_rbac", Action: "Deny", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{
		ID: "inv_cr", ClusterID: "c1", Kind: "ClusterRole", Name: "cluster-admin",
	}); err != nil {
		t.Fatal(err)
	}
	check, _ := getJSON(t, srv.URL+"/admin/k8s/policies/compliance")["policy_check"].(map[string]any)
	if _, marked := check["uncovered_rules"]; marked {
		t.Fatalf("every enabled rule had a candidate resource, yet one was reported uncovered: %v", check)
	}
}

// A disabled rule is not a gap: it was never going to run.
func TestUncoveredRulesIgnoreDisabledPolicies(t *testing.T) {
	items := []store.K8sInventoryItem{{Kind: "Deployment", Name: "api"}}
	policies := []analyzer.Policy{{ID: "p", RuleType: "disallow_wildcard_rbac", Enabled: false}}
	if got := analyzer.UncoveredPolicyRules(items, policies); len(got) != 0 {
		t.Fatalf("a disabled rule reported as uncovered: %v", got)
	}
}
