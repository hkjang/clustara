package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	oldApproval := time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339Nano)
	if err := db.InsertK8sActionRequest(ctx, store.K8sActionRequest{
		ID: "act_approval", ClusterID: "c1", Namespace: "default", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", RiskLevel: "high", Status: "approval_required", RequestedBy: "dev",
		DryRunDiff: "restart api", IdempotencyKey: "idem-flow-approval", CommandHash: "hash-flow-approval", CreatedAt: oldApproval,
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
		Summary        map[string]int `json:"summary"`
		HandoffSummary string         `json:"handoff_summary"`
		GeneratedAt    string         `json:"generated_at"`
		Items          []struct {
			ID         string `json:"id"`
			Kind       string `json:"kind"`
			Lane       string `json:"lane"`
			NextAction string `json:"next_action"`
			Href       string `json:"href"`
			SLAStatus  string `json:"sla_status"`
			AgeSeconds int64  `json:"age_seconds"`
			ActorHint  string `json:"actor_hint"`
			Handoff    string `json:"handoff_text"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Summary["total"] != 7 || out.Summary["approval"] != 3 || out.Summary["ready"] != 2 || out.Summary["verify"] != 1 || out.Summary["prepare"] != 1 {
		t.Fatalf("unexpected summary: %+v", out.Summary)
	}
	if out.GeneratedAt == "" {
		t.Fatal("action flow response should include generated_at for UI refresh context")
	}
	if _, err := time.Parse(time.RFC3339Nano, out.GeneratedAt); err != nil {
		t.Fatalf("generated_at should be RFC3339Nano, got %q: %v", out.GeneratedAt, err)
	}
	if out.Summary["sla_breached"] < 1 {
		t.Fatalf("expected at least one breached SLA item, summary=%+v", out.Summary)
	}
	if !strings.Contains(out.HandoffSummary, "[Clustara 운영 작업 요약]") ||
		!strings.Contains(out.HandoffSummary, "act_approval") ||
		!strings.Contains(out.HandoffSummary, "SLA 초과") ||
		!strings.Contains(out.HandoffSummary, "security/admin") ||
		!strings.Contains(out.HandoffSummary, "사유: SLA 초과") {
		t.Fatalf("handoff summary should include priority queue context, summary=%q", out.HandoffSummary)
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
		if it.ID == "act_approval" && (it.SLAStatus != "breached" || it.AgeSeconds < int64((2*time.Hour).Seconds())) {
			t.Fatalf("old approval should be SLA breached, item=%+v", it)
		}
		if it.ID == "act_approval" && it.ActorHint != "security/admin" {
			t.Fatalf("high-risk approval should point to security/admin, item=%+v", it)
		}
		if it.ID == "act_ready" && it.ActorHint != "operator/admin" {
			t.Fatalf("ready action should point to operator/admin, item=%+v", it)
		}
		if it.ID == "act_approval" && (!strings.Contains(it.Handoff, "다음 담당: security/admin") || !strings.Contains(it.Handoff, "#/k8s-actions")) {
			t.Fatalf("handoff text should include actor and destination, item=%+v", it)
		}
		if it.ID == "act_approval" && !strings.Contains(it.Handoff, "우선 사유: SLA 초과") {
			t.Fatalf("handoff text should include priority reason, item=%+v", it)
		}
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("%s route = %+v, want %+v (all=%+v)", id, got[id], w, got)
		}
	}
}
