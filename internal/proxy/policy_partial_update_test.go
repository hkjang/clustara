package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"clustara/internal/store"
)

// POST /admin/k8s/policies upserts on id, so a request carrying an existing id
// is an edit. Every field the caller omits arrives as its Go zero value, and
// `enabled` is a bool: a request that only meant to change the action, with no
// "enabled" key, decodes as false and switches the policy off.
//
// The failure hides itself. A disabled policy is skipped by EvaluatePolicies, so
// the compliance report goes quiet — which is the reading v0.9.219 and v0.9.220
// went to some trouble to make honest.
func TestPolicyUpdateKeepsFieldsTheCallerOmitted(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	ctx := context.Background()

	if err := db.UpsertK8sPolicy(ctx, store.K8sPolicy{
		ID: "k8spol_live", Name: "no-privileged", RuleType: "require_resource_limits",
		Action: "Deny", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Change only the action, exactly as a script or a narrower form would.
	postPolicy(t, srv.URL, map[string]any{"id": "k8spol_live", "action": "Warn"})

	got := findPolicy(t, db, "k8spol_live")
	if !got.Enabled {
		t.Fatal("a partial update disabled the policy: omitting \"enabled\" decoded as false. " +
			"The policy stops being evaluated and the compliance report goes quiet, which reads as compliant")
	}
	if got.Action != "Warn" {
		t.Fatalf("action = %q, want Warn: the field that WAS sent must still apply", got.Action)
	}
	if got.Name != "no-privileged" || got.RuleType != "require_resource_limits" {
		t.Fatalf("omitted fields were overwritten: %+v", got)
	}
}

// An explicit false must still disable: merging is about absent keys, not about
// refusing to turn a policy off.
func TestPolicyUpdateHonoursAnExplicitDisable(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	if err := db.UpsertK8sPolicy(context.Background(), store.K8sPolicy{
		ID: "k8spol_live", Name: "no-privileged", RuleType: "require_resource_limits",
		Action: "Deny", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	postPolicy(t, srv.URL, map[string]any{"id": "k8spol_live", "enabled": false})

	if findPolicy(t, db, "k8spol_live").Enabled {
		t.Fatal("an explicit \"enabled\": false was ignored; the merge must only cover absent keys")
	}
}

// Creation is unaffected: a new policy still takes the body as given.
func TestPolicyCreateIsUnaffectedByTheMerge(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	postPolicy(t, srv.URL, map[string]any{
		"name": "fresh", "rule_type": "require_resource_limits", "action": "Audit", "enabled": true,
	})
	found := false
	ps, err := db.ListK8sPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.Name == "fresh" && p.Action == "Audit" && p.Enabled {
			found = true
		}
	}
	if !found {
		t.Fatalf("a newly created policy did not round-trip: %+v", ps)
	}
}

func postPolicy(t *testing.T, base string, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(base+"/admin/k8s/policies", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("POST /admin/k8s/policies = %d for %v", resp.StatusCode, body)
	}
}

func findPolicy(t *testing.T, db *store.SQLStore, id string) store.K8sPolicy {
	t.Helper()
	ps, err := db.ListK8sPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("policy %s not found", id)
	return store.K8sPolicy{}
}
