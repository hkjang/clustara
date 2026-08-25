package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/config"
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

func TestMCPManifestDirectApprovalRollsBackWhenAuditFails(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	change := store.K8sManifestChangeRequest{
		ID: "mcp_direct_atomic", ClusterID: "c1", Namespace: "default", Kind: "ConfigMap", APIVersion: "v1",
		Name: "cfg", Status: "draft", RiskLevel: "high", RequiresApproval: true, CreatedBy: "mcp_api_key:key_root",
		AfterYAML: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n  namespace: default\n",
	}
	if err := db.CreateK8sManifestChangeRequest(ctx, change); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateK8sManifestChangeAnalysis(ctx, change.ID, "approval_required", "high", true, nil, nil, "validated"); err != nil {
		t.Fatal(err)
	}
	duplicate := store.AdminAuditLog{ID: "audit_duplicate", AdminID: "seed", Action: "seed"}
	if err := db.InsertAdminAudit(ctx, duplicate); err != nil {
		t.Fatal(err)
	}
	err := db.ApproveK8sManifestChangeWithAudit(ctx, change.ID, "mcp_api_key:key_root", "direct", store.AdminAuditLog{
		ID: duplicate.ID, AdminID: "mcp_api_key:key_root", Action: "direct",
	})
	if err == nil {
		t.Fatal("duplicate mandatory audit must fail the direct approval transaction")
	}
	got, getErr := db.GetK8sManifestChangeRequest(ctx, change.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if got.Status != "approval_required" || got.ApprovedBy != "" {
		t.Fatalf("approval must roll back with its audit, got %+v", got)
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

func TestMCPForceApprovalScopeCannotBeBypassedBySuperAdmin(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	s := &Server{db: db, metrics: newMetrics(), logger: logger}
	ctx := context.Background()
	if err := db.UpsertMCPToolScope(ctx, store.MCPToolScope{
		ID: "scope_force_rollout", ServerLabel: "gateway", ToolName: "k8s_rollout_restart",
		AllowedRoles: "super_admin", ApprovalRule: "always", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	authCtx := &store.AuthContext{APIKeyID: "key_root", Role: "super_admin", Scopes: []string{"admin:write"}}
	req := withMCPAdminIdentity(httptest.NewRequest("POST", "/mcp/gateway", nil), "key_root", authCtx)
	resp := s.enforceMCPToolGovernance(req, "key_root", authCtx,
		mcpRoute{upstreamName: "gateway", bareTool: "k8s_rollout_restart"},
		"tools/call", "k8s_rollout_restart", "k8s_rollout_restart",
		json.RawMessage(`{"cluster_id":"c1","namespace":"prod","kind":"Deployment","name":"api"}`), json.RawMessage("1"))
	if resp == nil || resp.Error == nil || !strings.Contains(resp.Error.Message, "approval required") {
		t.Fatalf("force-approval scope must remain non-bypassable, got %+v", resp)
	}
	audits, err := db.ListAdminAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range audits {
		if entry.Action == "mcp.super_admin.direct_execution_authorized" {
			t.Fatalf("force-approved call must not be audited as direct execution: %+v", entry)
		}
	}
}

func TestMCPSuperAdminDirectBypassPersistsRequiredAudit(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	s := &Server{db: db, metrics: newMetrics(), logger: logger}
	if err := db.UpsertToolRiskProfile(context.Background(), store.ToolRiskProfile{
		ID: "risk_direct_rollout", ServerLabel: "gateway", ToolName: "k8s_rollout_restart",
		RiskLevel: "high", Action: "require_approval", Note: "test direct execution",
	}); err != nil {
		t.Fatal(err)
	}
	authCtx := &store.AuthContext{APIKeyID: "key_root", Role: "super_admin", Scopes: []string{"admin:write"}}
	req := withMCPAdminIdentity(httptest.NewRequest("POST", "/mcp/gateway", nil), "key_root", authCtx)
	resp := s.enforceMCPToolGovernance(req, "key_root", authCtx,
		mcpRoute{upstreamName: "gateway", bareTool: "k8s_rollout_restart"},
		"tools/call", "k8s_rollout_restart", "k8s_rollout_restart",
		json.RawMessage(`{"cluster_id":"c1","namespace":"prod","kind":"Deployment","name":"api"}`), json.RawMessage("1"))
	if resp != nil {
		t.Fatalf("super-admin direct path should pass after durable audit, got %+v", resp)
	}
	audits, err := db.ListAdminAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range audits {
		if entry.Action == "mcp.super_admin.direct_execution_authorized" && strings.Contains(entry.AfterValue, "key_root") {
			return
		}
	}
	t.Fatal("required direct-execution audit was not persisted")
}

func TestMCPDestructiveDefaultAllowStillPersistsAuthorizationAudit(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	s := &Server{db: db, metrics: newMetrics(), logger: logger}
	authCtx := &store.AuthContext{APIKeyID: "key_admin", Role: "admin", Scopes: []string{"admin:write"}}
	req := withMCPAdminIdentity(httptest.NewRequest("POST", "/mcp/gateway", nil), "key_admin", authCtx)
	resp := s.enforceMCPToolGovernance(req, "key_admin", authCtx,
		mcpRoute{upstreamName: "gateway", bareTool: "k8s_approve_manifest_change"},
		"tools/call", "k8s_approve_manifest_change", "k8s_approve_manifest_change",
		json.RawMessage(`{"request_id":"change-1"}`), json.RawMessage("1"))
	if resp != nil {
		t.Fatalf("default policy should authorize the tool after durable audit, got %+v", resp)
	}
	audits, err := db.ListAdminAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range audits {
		if entry.Action == "mcp.destructive_tool.execution_authorized" && strings.Contains(entry.AfterValue, "key_admin") {
			return
		}
	}
	t.Fatal("destructive default-allow authorization audit was not persisted")
}

func TestMCPDestructiveToolFailsClosedWhenActivePolicyLookupFails(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "policy-lookup-failure.db")
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `DROP TABLE policy_rules`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	raw.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	s := &Server{db: db, metrics: newMetrics(), logger: logger}
	authCtx := &store.AuthContext{APIKeyID: "key_root", Role: "super_admin", Scopes: []string{"admin:write"}}
	req := withMCPAdminIdentity(httptest.NewRequest("POST", "/mcp/gateway", nil), "key_root", authCtx)
	resp := s.enforceMCPToolGovernance(req, "key_root", authCtx,
		mcpRoute{upstreamName: "gateway", bareTool: "k8s_rollout_restart"},
		"tools/call", "k8s_rollout_restart", "k8s_rollout_restart",
		json.RawMessage(`{"cluster_id":"c1","namespace":"prod","kind":"Deployment","name":"api"}`), json.RawMessage("1"))
	if resp == nil || resp.Error == nil || !strings.Contains(resp.Error.Message, "active governance policy lookup failed") {
		t.Fatalf("destructive tool must fail closed on active policy lookup error, got %+v", resp)
	}
}
