package proxy

import (
	"context"
	"encoding/json"
	"testing"

	"clustara/internal/store"
)

// TestK8sGatewayToolsDispatch verifies the read-only K8s MCP tools dispatch and return the
// expected result shape. The analyzer logic is covered by its own unit tests; this guards the glue.
func TestK8sGatewayToolsDispatch(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	s := &Server{db: db}

	// k8s_list_clusters on an empty store → clusters:[], count:0.
	res, err := s.runK8sGatewayTool(ctx, "k8s_list_clusters", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("k8s_list_clusters: %v", err)
	}
	if _, ok := res["content"]; !ok {
		t.Fatalf("expected MCP content wrapper, got %#v", res)
	}

	// k8s_list_incidents defaults to status=open.
	if _, err := s.runK8sGatewayTool(ctx, "k8s_list_incidents", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("k8s_list_incidents: %v", err)
	}

	// k8s_pod_health requires cluster_id.
	if _, err := s.runK8sGatewayTool(ctx, "k8s_pod_health", json.RawMessage(`{}`)); err == nil {
		t.Fatalf("k8s_pod_health should require cluster_id")
	}
	if _, err := s.runK8sGatewayTool(ctx, "k8s_pod_health", json.RawMessage(`{"cluster_id":"c1"}`)); err != nil {
		t.Fatalf("k8s_pod_health with cluster_id: %v", err)
	}

	// Admin gate: a non-admin caller is rejected before dispatch.
	if _, err := s.runGatewayTool(ctx, nil, "", &store.AuthContext{Scopes: []string{"chat:write"}}, "k8s_list_clusters", json.RawMessage(`{}`)); err == nil {
		t.Fatalf("non-admin caller should be rejected for K8s tools")
	}
	if _, err := s.runGatewayTool(ctx, nil, "", &store.AuthContext{Scopes: []string{"admin:read"}}, "k8s_list_clusters", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("admin:read caller should be allowed: %v", err)
	}
}
