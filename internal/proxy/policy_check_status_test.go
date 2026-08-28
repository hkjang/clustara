package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

// A compliance report answering {"violations": [], "count": 0} means one of two
// very different things: every resource passed the rules, or there were no rules.
// EvaluatePolicies skips anything not enabled, so an empty — or entirely
// disabled — policy list produces a clean result for every resource.
//
// The file already stated this rule: policyCheckStatus exists because "analysing
// with no policies loaded yields a clean plan, so a response carrying one must
// say which of the two it is." It only implemented the load-failure half. The
// empty rule set, which is the case an operator actually reaches on a fresh
// install, still came back as a pass — and compliance sign-off reads this
// endpoint.
func TestComplianceReportSaysWhenNoRulesRan(t *testing.T) {
	db, srv := newPolicyStatusServer(t)

	body := getJSON(t, srv.URL+"/admin/k8s/policies/compliance")
	check, _ := body["policy_check"].(map[string]any)
	if check == nil {
		t.Fatalf("no policy_check in the compliance response: %v", body)
	}
	if check["status"] != "no_rules" {
		t.Fatalf("status = %v with no policies configured; a clean report from an empty rule set "+
			"is indistinguishable from a passing one: %v", check["status"], check)
	}

	// A disabled policy is still no rule: it never runs.
	mustUpsertPolicy(t, db, "pol_off", false)
	check, _ = getJSON(t, srv.URL+"/admin/k8s/policies/compliance")["policy_check"].(map[string]any)
	if check["status"] != "no_rules" {
		t.Fatalf("status = %v with only a disabled policy: %v", check["status"], check)
	}

	// An enabled rule is still not a check if there is nothing to examine. An
	// empty inventory — an agent that never connected, or stopped reporting —
	// produces "0 violations" from every rule.
	mustUpsertPolicy(t, db, "pol_on", true)
	check, _ = getJSON(t, srv.URL+"/admin/k8s/policies/compliance")["policy_check"].(map[string]any)
	if check["status"] != "no_resources" {
		t.Fatalf("status = %v with rules but an empty inventory; every rule trivially passes over "+
			"nothing, so this must not read as compliant: %v", check["status"], check)
	}

	// A rule and something to run it against: now it is a real check.
	mustUpsertWorkload(t, db, "inv_api")
	check, _ = getJSON(t, srv.URL+"/admin/k8s/policies/compliance")["policy_check"].(map[string]any)
	if check["status"] != "checked" {
		t.Fatalf("status = %v with an enabled policy and a workload: %v", check["status"], check)
	}
	if check["rules"] != float64(1) || check["resources"] != float64(1) {
		t.Fatalf("rules/resources = %v/%v, want 1/1: %v", check["rules"], check["resources"], check)
	}
}

// Only workloads and RBAC objects are evaluated, so the number of inventory rows
// is not the number of things examined: an inventory of nothing but Services
// yields a clean report from every rule.
func TestComplianceCountsOnlyEvaluableResources(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	mustUpsertPolicy(t, db, "pol_on", true)
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{
		ID: "inv_svc", ClusterID: "c1", Kind: "Service", Namespace: "prod", Name: "api",
	}); err != nil {
		t.Fatal(err)
	}
	check, _ := getJSON(t, srv.URL+"/admin/k8s/policies/compliance")["policy_check"].(map[string]any)
	if check["status"] != "no_resources" {
		t.Fatalf("status = %v with only a Service in the inventory; policies evaluate workloads and "+
			"RBAC objects, so nothing was examined: %v", check["status"], check)
	}
}

func mustUpsertWorkload(t *testing.T, db *store.SQLStore, id string) {
	t.Helper()
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{
		ID: id, ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api",
	}); err != nil {
		t.Fatal(err)
	}
}

// The load-failure case must keep its own distinct status; the new empty case
// must not swallow it.
func TestPolicyCheckStatusKeepsUnavailableDistinctFromNoRules(t *testing.T) {
	unavailable := policyCheckStatus(context.DeadlineExceeded, nil)
	if unavailable["status"] != "unavailable" {
		t.Fatalf("load failure reported as %v", unavailable["status"])
	}
	if policyCheckStatus(nil, nil)["status"] != "no_rules" {
		t.Fatal("an empty rule set must not report as checked")
	}
	if policyCheckStatus(nil, []store.K8sPolicy{{ID: "p", Enabled: true}})["status"] != "checked" {
		t.Fatal("an enabled policy must report as checked")
	}
}

func mustUpsertPolicy(t *testing.T, db *store.SQLStore, id string, enabled bool) {
	t.Helper()
	if err := db.UpsertK8sPolicy(context.Background(), store.K8sPolicy{
		ID: id, Name: id, RuleType: "require_resource_limits", Action: "Warn", Enabled: enabled,
	}); err != nil {
		t.Fatal(err)
	}
}

func newPolicyStatusServer(t *testing.T) (*store.SQLStore, *httptest.Server) {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "policy.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	t.Cleanup(srv.Close)
	return db, srv
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d body=%s", url, resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v body=%s", url, err, raw)
	}
	return out
}
