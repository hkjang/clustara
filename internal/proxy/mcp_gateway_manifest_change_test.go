package proxy

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"clustara/internal/store"
)

func TestGatewayManifestChangeRequiresWriteScopeAndCreatesDraft(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "mcp-cluster", Name: "mcp", ServerURL: "https://k8s.invalid", Status: "connected"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	req := httptest.NewRequest("POST", "/mcp/gateway", nil)
	args := json.RawMessage(`{"cluster_id":"mcp-cluster","namespace":"default","kind":"ConfigMap","api_version":"v1","name":"mcp-config","operation":"create","after_yaml":"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: mcp-config\n  namespace: default\ndata:\n  mode: safe\n","reason":"MCP test","idempotency_key":"mcp-test-config"}`)
	if _, err := s.runGatewayManifestTool(req, &store.AuthContext{Scopes: []string{"admin:read"}}, "k8s_create_manifest_change", args); err == nil {
		t.Fatal("admin:read caller must not create YAML changes")
	}
	result, err := s.runGatewayManifestTool(req, &store.AuthContext{Scopes: []string{"admin:write"}}, "k8s_create_manifest_change", args)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected MCP result")
	}
	rows, err := db.ListK8sManifestChangeRequests(ctx, store.K8sManifestChangeFilter{ClusterID: "mcp-cluster", Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].Status != "draft" {
		t.Fatalf("manifest draft was not persisted: rows=%+v err=%v", rows, err)
	}
	applyArgs := json.RawMessage(`{"request_id":"` + rows[0].ID + `"}`)
	if _, err := s.runGatewayManifestTool(req, &store.AuthContext{Scopes: []string{"admin:write"}}, "k8s_apply_manifest_change", applyArgs); err == nil {
		t.Fatal("MCP apply must require explicit confirm=true")
	}
}
