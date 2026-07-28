package proxy

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestMCPSuperAdminDirectExecutionIdentityAndScope(t *testing.T) {
	super := &store.AuthContext{APIKeyID: "key_root", Role: "super_admin", Scopes: []string{"admin:write"}}
	if !mcpSuperAdminDirect(super, "gateway", "k8s_apply_manifest_change") ||
		!mcpSuperAdminDirect(super, "gateway", "k8s_rollout_restart") {
		t.Fatal("super_admin write key must bypass approval for governed direct K8s changes")
	}
	if mcpSuperAdminDirect(&store.AuthContext{Role: "admin", Scopes: []string{"admin:write"}}, "gateway", "k8s_rollout_restart") {
		t.Fatal("ordinary admin MCP key must retain approval")
	}
	req := withMCPAdminIdentity(httptest.NewRequest("POST", "/api/v1/workloads/rollout", nil), "key_root", super)
	if got := adminID(req); got != "mcp_api_key:key_root" {
		t.Fatalf("MCP audit actor mismatch: %s", got)
	}
}

func TestMCPSuperAdminManifestDirectApprovalIsPersisted(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	ctx := context.Background()
	change := store.K8sManifestChangeRequest{
		ID: "mcp_direct", ClusterID: "c1", Namespace: "default", Kind: "ConfigMap", APIVersion: "v1",
		Name: "cfg", Status: "draft", RiskLevel: "high", RequiresApproval: true, CreatedBy: "mcp_api_key:key_root",
		AfterYAML: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n  namespace: default\n",
	}
	if err := db.CreateK8sManifestChangeRequest(ctx, change); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateK8sManifestChangeAnalysis(ctx, change.ID, "approval_required", "high", true, nil, nil, "validated"); err != nil {
		t.Fatal(err)
	}
	super := &store.AuthContext{APIKeyID: "key_root", Role: "super_admin", Scopes: []string{"admin:write"}}
	req := withMCPAdminIdentity(httptest.NewRequest("POST", "/mcp/gateway", nil), "key_root", super)
	if err := s.ensureMCPManifestDirectApproval(req, super, change.ID); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetK8sManifestChangeRequest(ctx, change.ID)
	if err != nil || got.Status != "approved" || got.ApprovedBy != "mcp_api_key:key_root" {
		t.Fatalf("direct approval not persisted: got=%+v err=%v", got, err)
	}
	audits, err := db.ListAdminAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, audit := range audits {
		if audit.Action == "k8s.manifest_change.mcp_super_admin_direct_approve" && strings.Contains(audit.AfterValue, "key_root") {
			found = true
		}
	}
	if !found {
		t.Fatal("super_admin MCP direct approval audit missing")
	}
}

func TestMCPRolloutRestartRequiresSuperAdminAndConfirmation(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("POST", "/mcp/gateway", nil)
	args := json.RawMessage(`{"cluster_id":"c1","namespace":"default","kind":"Deployment","name":"api","reason":"restart"}`)
	if _, err := s.runGatewayRolloutTool(req, "key_admin", &store.AuthContext{Role: "admin", Scopes: []string{"admin:write"}}, "k8s_rollout_restart", args); err == nil {
		t.Fatal("ordinary admin key must not directly rollout")
	}
	if _, err := s.runGatewayRolloutTool(req, "key_root", &store.AuthContext{Role: "super_admin", Scopes: []string{"admin:write"}}, "k8s_rollout_restart", args); err == nil {
		t.Fatal("super_admin rollout must still require confirm=true")
	}
}
