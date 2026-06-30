package proxy

import (
	"encoding/json"
	"testing"

	"clustara/internal/store"
)

func TestEvaluateMCPToolScope(t *testing.T) {
	base := store.MCPToolScope{
		Enabled: true, AllowedRoles: "admin,operator", AllowedNamespaces: "prod,staging",
		AllowedClusters: "c1", MaskingLevel: "partial", ApprovalRule: "inherit",
	}

	// Allowed call.
	if d := evaluateMCPToolScope(base, "admin", "prod", "c1"); d.Blocked {
		t.Fatalf("admin/prod/c1 should be allowed: %+v", d)
	}
	// Disallowed role.
	if d := evaluateMCPToolScope(base, "viewer", "prod", "c1"); !d.Blocked {
		t.Fatalf("viewer should be blocked")
	}
	// Disallowed namespace.
	if d := evaluateMCPToolScope(base, "admin", "dev", "c1"); !d.Blocked {
		t.Fatalf("namespace dev should be blocked")
	}
	// Disallowed cluster.
	if d := evaluateMCPToolScope(base, "admin", "prod", "c9"); !d.Blocked {
		t.Fatalf("cluster c9 should be blocked")
	}
	// Empty namespace not constrained (tool without a namespace arg).
	if d := evaluateMCPToolScope(base, "admin", "", ""); d.Blocked {
		t.Fatalf("missing namespace/cluster args should not block: %+v", d)
	}

	// Disabled scope = no enforcement.
	disabled := base
	disabled.Enabled = false
	if d := evaluateMCPToolScope(disabled, "viewer", "dev", "c9"); d.Blocked {
		t.Fatalf("disabled scope should not enforce")
	}

	// Approval rule forcing.
	always := base
	always.ApprovalRule = "always"
	if d := evaluateMCPToolScope(always, "admin", "prod", "c1"); !d.ForceApproval {
		t.Fatalf("approval_rule=always should force approval")
	}
	never := base
	never.ApprovalRule = "never"
	if d := evaluateMCPToolScope(never, "admin", "prod", "c1"); !d.SkipApproval {
		t.Fatalf("approval_rule=never should skip approval")
	}

	// Empty allow-lists = allow any.
	open := store.MCPToolScope{Enabled: true}
	if d := evaluateMCPToolScope(open, "anyone", "anywhere", "anycluster"); d.Blocked {
		t.Fatalf("empty allow-lists should allow all: %+v", d)
	}
}

func TestExtractScopeTargets(t *testing.T) {
	ns, cl := extractScopeTargets(json.RawMessage(`{"namespace":"prod","cluster_id":"c1","x":1}`))
	if ns != "prod" || cl != "c1" {
		t.Fatalf("extract got ns=%q cl=%q", ns, cl)
	}
	ns2, cl2 := extractScopeTargets(json.RawMessage(`{"cluster":"c2"}`))
	if ns2 != "" || cl2 != "c2" {
		t.Fatalf("extract alt got ns=%q cl=%q", ns2, cl2)
	}
	if ns3, cl3 := extractScopeTargets(json.RawMessage(`not json`)); ns3 != "" || cl3 != "" {
		t.Fatalf("invalid json should yield empty")
	}
}

func TestCSVAllows(t *testing.T) {
	if !csvAllows("", "anything") {
		t.Fatal("empty csv should allow all")
	}
	if !csvAllows("*", "anything") {
		t.Fatal("wildcard should allow all")
	}
	if !csvAllows("a, b ,c", "b") {
		t.Fatal("trimmed match should succeed")
	}
	if csvAllows("a,b", "z") {
		t.Fatal("non-member should be denied")
	}
	if csvAllows("a,b", "") {
		t.Fatal("empty value against non-empty list should be denied")
	}
}
