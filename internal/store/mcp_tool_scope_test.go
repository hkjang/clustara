package store

import (
	"context"
	"testing"
)

func TestMCPToolScopeStore(t *testing.T) {
	ctx := context.Background()
	db := openAgentSessionTestStore(t)

	// Upsert specific + wildcard scopes.
	if err := db.UpsertMCPToolScope(ctx, MCPToolScope{ServerLabel: "k8s", ToolName: "delete_pod", AllowedRoles: "admin", AllowedNamespaces: "prod", MaskingLevel: "strict", ApprovalRule: "always", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertMCPToolScope(ctx, MCPToolScope{ServerLabel: "*", ToolName: "*", AllowedRoles: "operator", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// Exact match wins over wildcard.
	sc, ok, err := db.MCPToolScope(ctx, "k8s", "delete_pod")
	if err != nil || !ok || sc.AllowedRoles != "admin" || sc.MaskingLevel != "strict" || sc.ApprovalRule != "always" {
		t.Fatalf("exact scope: %+v ok=%v err=%v", sc, ok, err)
	}
	// Falls back to */* wildcard.
	sc2, ok2, _ := db.MCPToolScope(ctx, "other", "whatever")
	if !ok2 || sc2.AllowedRoles != "operator" {
		t.Fatalf("wildcard fallback wrong: %+v ok=%v", sc2, ok2)
	}

	// Update via upsert (no duplicate).
	_ = db.UpsertMCPToolScope(ctx, MCPToolScope{ServerLabel: "k8s", ToolName: "delete_pod", AllowedRoles: "admin,sre", Enabled: true})
	list, _ := db.ListMCPToolScopes(ctx)
	if len(list) != 2 {
		t.Fatalf("expected 2 scopes after update, got %d", len(list))
	}

	// Delete.
	if err := db.DeleteMCPToolScope(ctx, "k8s", "delete_pod"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.MCPToolScope(ctx, "k8s", "delete_pod"); ok {
		// should now fall back to wildcard, which still exists → ok=true but role=operator
		sc3, _, _ := db.MCPToolScope(ctx, "k8s", "delete_pod")
		if sc3.AllowedRoles != "operator" {
			t.Fatalf("after delete should fall back to wildcard, got %+v", sc3)
		}
	}
}
