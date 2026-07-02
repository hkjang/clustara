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

func TestK8sActionFlowAggregatesUserNextSteps(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	ctx := context.Background()
	if err := db.InsertK8sActionRequest(ctx, store.K8sActionRequest{
		ID: "act_approval", ClusterID: "c1", Namespace: "default", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", RiskLevel: "high", Status: "approval_required", RequestedBy: "dev",
		DryRunDiff: "restart api", IdempotencyKey: "idem-flow-approval", CommandHash: "hash-flow-approval",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sActionRequest(ctx, store.K8sActionRequest{
		ID: "act_ready", ClusterID: "c1", Namespace: "default", ResourceKind: "Deployment", ResourceName: "worker",
		Action: "scale", RiskLevel: "medium", Status: "approved", RequestedBy: "operator", ApprovedBy: "approver",
		DryRunDiff: "scale worker", IdempotencyKey: "idem-flow-ready", CommandHash: "hash-flow-ready",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateK8sConfigChangeRequest(ctx, store.K8sConfigChangeRequest{
		ID: "cfg_ready", ClusterID: "c1", Namespace: "default", SourceKind: "ConfigMap", SourceName: "app-config",
		ChangeType: "update", ProposedSummary: "feature flag", RiskLevel: "low", Status: "pending",
		RequiresApproval: false, RequestedBy: "dev",
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateK8sManifestChangeRequest(ctx, store.K8sManifestChangeRequest{
		ID: "m_prepare", ClusterID: "c1", Namespace: "default", Kind: "Deployment", APIVersion: "apps/v1", Name: "api",
		Status: "draft", RiskLevel: "medium", Reason: "image update", CreatedBy: "dev",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateK8sManifestChangeRequest(ctx, store.K8sManifestChangeRequest{
		ID: "m_verify", ClusterID: "c1", Namespace: "default", Kind: "Service", APIVersion: "v1", Name: "api",
		Status: "applied", RiskLevel: "high", Reason: "selector update", CreatedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateK8sPodExecSession(ctx, &store.K8sPodExecSession{
		ID: "exec_approval", ClusterID: "c1", Namespace: "default", Pod: "api-123", Container: "app",
		Command: "ps aux", Role: "developer", RequestedBy: "dev", Status: "pending_approval", RiskLevel: "medium", RequireApproval: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sDebugSession(ctx, &store.K8sDebugSession{
		ID: "debug_approval", ClusterID: "c1", Namespace: "default", Pod: "api-123", TargetContainer: "app",
		DebugImage: "busybox:1.36", Template: "dns", Reason: "dns check", Status: "pending_approval", RiskLevel: "high", RequireApproval: true, RequestedBy: "dev",
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(proxy.URL + "/admin/k8s/action-flow?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("action flow status=%d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Summary map[string]int `json:"summary"`
		Items   []struct {
			ID         string `json:"id"`
			Kind       string `json:"kind"`
			Lane       string `json:"lane"`
			NextAction string `json:"next_action"`
			Href       string `json:"href"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Summary["total"] != 7 || out.Summary["approval"] != 3 || out.Summary["ready"] != 2 || out.Summary["verify"] != 1 || out.Summary["prepare"] != 1 {
		t.Fatalf("unexpected summary: %+v", out.Summary)
	}
	want := map[string]struct {
		lane string
		next string
	}{
		"act_approval":   {"approval", "approve"},
		"act_ready":      {"ready", "execute"},
		"cfg_ready":      {"ready", "apply"},
		"m_prepare":      {"prepare", "validate"},
		"m_verify":       {"verify", "verify"},
		"exec_approval":  {"approval", "approve"},
		"debug_approval": {"approval", "approve"},
	}
	got := map[string]struct {
		lane string
		next string
	}{}
	for _, it := range out.Items {
		got[it.ID] = struct {
			lane string
			next string
		}{it.Lane, it.NextAction}
		if it.Href == "" {
			t.Fatalf("item %s should include a destination href", it.ID)
		}
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("%s route = %+v, want %+v (all=%+v)", id, got[id], w, got)
		}
	}
}
