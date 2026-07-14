package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestPlatformAgentBuildsRedisPlanWithoutPersistingOrApplying(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "platform-agent.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "cluster-dev", Name: "dev", ServerURL: "https://k8s.invalid", Status: "connected"}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/services/agent-plan", "", map[string]any{
		"prompt": "small Redis 캐시를 만들어줘", "cluster_id": "cluster-dev", "namespace": "payments", "name": "payments-cache",
	})
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("platform agent status=%d body=%s", resp.StatusCode, body)
	}
	var got struct {
		State        string               `json:"state"`
		Manifest     string               `json:"manifest"`
		Resources    []map[string]string  `json:"resources"`
		Stages       []platformAgentStage `json:"stages"`
		ServiceInput serviceInstanceInput `json:"service_input"`
		Safety       string               `json:"safety"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.State != "draft_ready" || got.ServiceInput.CatalogID != "svccat_redis" || got.ServiceInput.ProfileID != "svcprof_redis_small" {
		t.Fatalf("unexpected plan: %+v", got)
	}
	if len(got.Resources) < 3 || !strings.Contains(got.Manifest, "kind: StatefulSet") || !strings.Contains(got.Safety, "Apply") {
		t.Fatalf("plan must expose multi-resource preview and safety boundary: resources=%v safety=%q", got.Resources, got.Safety)
	}
	if len(got.Stages) != 8 || got.Stages[2].State != "draft_ready" || got.Stages[2].Status != "current" {
		t.Fatalf("unexpected lifecycle stages: %+v", got.Stages)
	}
	instances, err := db.ListK8sServiceInstances(ctx, "", "", "", 10)
	if err != nil || len(instances) != 0 {
		t.Fatalf("planning must not persist a service instance: instances=%v err=%v", instances, err)
	}

	register := postJSON(t, proxy.URL+"/admin/k8s/services/instances", "", got.ServiceInput)
	defer register.Body.Close()
	if register.StatusCode != 201 {
		body, _ := io.ReadAll(register.Body)
		t.Fatalf("register status=%d body=%s", register.StatusCode, body)
	}
	var registered struct {
		Decision         string                   `json:"decision"`
		ApprovalRequired bool                     `json:"approval_required"`
		Instance         store.K8sServiceInstance `json:"instance"`
		Plan             struct {
			Resources []any `json:"resources"`
		} `json:"plan"`
	}
	if err := json.NewDecoder(register.Body).Decode(&registered); err != nil {
		t.Fatal(err)
	}
	if registered.Decision == "" || len(registered.Plan.Resources) < 3 {
		t.Fatalf("registration must re-evaluate and expose policy decision: %+v", registered)
	}
	readiness := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+registered.Instance.ID+"/deployment-readiness", "", map[string]any{})
	defer readiness.Body.Close()
	if readiness.StatusCode != 200 {
		body, _ := io.ReadAll(readiness.Body)
		t.Fatalf("readiness status=%d body=%s", readiness.StatusCode, body)
	}
	var readinessBody struct {
		State          string `json:"state"`
		ResourceCount  int    `json:"resource_count"`
		ClientReady    bool   `json:"client_ready"`
		ApplySupported bool   `json:"server_side_apply_supported"`
		Safety         string `json:"safety"`
	}
	if err := json.NewDecoder(readiness.Body).Decode(&readinessBody); err != nil {
		t.Fatal(err)
	}
	if readinessBody.State == "" || readinessBody.ResourceCount < 3 || !readinessBody.ClientReady || !readinessBody.ApplySupported || !strings.Contains(readinessBody.Safety, "변경하지 않습니다") {
		t.Fatalf("unexpected readiness: %+v", readinessBody)
	}
}

func TestPlatformAgentBlocksUnsupportedAndUnsafeProductionPlan(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "platform-agent-blocked.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	ctx := context.Background()
	_ = db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "cluster-prod", Name: "prod", ServerURL: "https://k8s.invalid", Status: "connected"})
	server, _ := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	unsupported := postJSON(t, proxy.URL+"/admin/k8s/services/agent-plan", "", map[string]any{
		"prompt": "Kafka 3노드 클러스터 만들어줘", "cluster_id": "cluster-prod", "namespace": "data", "name": "events",
	})
	var unsupportedBody map[string]any
	_ = json.NewDecoder(unsupported.Body).Decode(&unsupportedBody)
	unsupported.Body.Close()
	if unsupportedBody["state"] != "blocked" {
		t.Fatalf("unsupported catalog must be blocked: %v", unsupportedBody)
	}

	production := postJSON(t, proxy.URL+"/admin/k8s/services/agent-plan", "", map[string]any{
		"prompt": "운영 Redis를 만들어줘", "cluster_id": "cluster-prod", "namespace": "data", "name": "prod-cache",
	})
	var productionBody struct {
		State    string   `json:"state"`
		Blockers []string `json:"blockers"`
	}
	_ = json.NewDecoder(production.Body).Decode(&productionBody)
	production.Body.Close()
	if productionBody.State != "blocked" || !strings.Contains(strings.Join(productionBody.Blockers, " "), "digest") {
		t.Fatalf("production tag-only image must be blocked: %+v", productionBody)
	}

	digestProduction := postJSON(t, proxy.URL+"/admin/k8s/services/agent-plan", "", map[string]any{
		"prompt": "운영 Redis를 만들어줘", "cluster_id": "cluster-prod", "namespace": "data", "name": "prod-cache-digest",
		"image": "harbor.internal/data/redis@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	var digestBody struct {
		State string `json:"state"`
	}
	_ = json.NewDecoder(digestProduction.Body).Decode(&digestBody)
	digestProduction.Body.Close()
	if digestBody.State != "draft_ready" {
		t.Fatalf("digest-pinned production plan should be ready: %+v", digestBody)
	}
}

func TestPlatformAgentPlanRequiresServiceCreateScope(t *testing.T) {
	req := httptest.NewRequest("POST", "/admin/k8s/services/agent-plan", nil)
	if got := adminRequiredScope(req); got != "service:create" {
		t.Fatalf("platform agent required scope=%q want service:create", got)
	}
}

func TestPlatformAgentLifecycleUsesStackAndHealthEvidence(t *testing.T) {
	instance := store.K8sServiceInstance{Status: "validating", PolicyResultJSON: `{"decision":"approval_required"}`}
	stack := store.K8sApplicationStack{Status: "saved"}
	lifecycle := platformAgentLifecycleFromEvidence(instance, stack, nil, "collecting")
	if lifecycle.State != "approval_required" || lifecycle.Decision != "approval_required" {
		t.Fatalf("approval lifecycle=%+v", lifecycle)
	}

	history := []store.K8sStackApplyHistory{{Operation: "apply", Status: "success", DryRun: false, Applied: 3}}
	stack.Status = "applied"
	lifecycle = platformAgentLifecycleFromEvidence(instance, stack, history, "ready")
	if lifecycle.State != "succeeded" || lifecycle.LastApply == nil || lifecycle.Stages[7].Status != "current" {
		t.Fatalf("succeeded lifecycle=%+v", lifecycle)
	}

	history[0].Status = "partial"
	stack.Status = "saved"
	lifecycle = platformAgentLifecycleFromEvidence(instance, stack, history, "degraded")
	if lifecycle.State != "execution_failed" || lifecycle.Stages[5].Status != "blocked" {
		t.Fatalf("failed lifecycle=%+v", lifecycle)
	}
}
