package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

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

func TestK8sGatewayMonitoringReturnsLatestPodCPUAndMemory(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, sample := range []store.K8sMetricSample{
		{ID: "pod-old", ClusterID: "c1", Namespace: "apps", ResourceKind: "Pod", ResourceName: "api-0", CPUMillicores: 100, MemoryBytes: 1024, ObservedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)},
		{ID: "pod-new", ClusterID: "c1", Namespace: "apps", ResourceKind: "Pod", ResourceName: "api-0", CPUMillicores: 250, MemoryBytes: 2048, GPUObserved: false, ObservedAt: now.Format(time.RFC3339Nano)},
	} {
		if err := db.InsertK8sMetricSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{db: db}
	result, err := s.runK8sMonitoringGatewayTool(ctx, "k8s_pod_metrics", json.RawMessage(`{"cluster_id":"c1","namespace":"apps"}`))
	if err != nil {
		t.Fatal(err)
	}
	text := gatewayResultText(result)
	if !strings.Contains(text, `"cpu_millicores": 250`) || !strings.Contains(text, `"gpu_observed": false`) || strings.Count(text, `"resource_name": "api-0"`) != 1 {
		t.Fatalf("expected one latest Pod metric with explicit GPU observation state: %s", text)
	}
}
