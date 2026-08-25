package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestFinishManifestApplyFailureIgnoresCanceledRequestContext(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()

	ctx := context.Background()
	change := store.K8sManifestChangeRequest{
		ID:             "manifest-preflight-cancel",
		ClusterID:      "missing-cluster",
		Namespace:      "default",
		Kind:           "ConfigMap",
		APIVersion:     "v1",
		Name:           "settings",
		Status:         "running",
		AfterYAML:      "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: default\n",
		Impact:         map[string]any{"operation": "create"},
		CreatedBy:      "requester",
		IdempotencyKey: "manifest-preflight-cancel",
	}
	if err := db.CreateK8sManifestChangeRequest(ctx, change); err != nil {
		t.Fatal(err)
	}

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	server := &Server{db: db}
	if err := server.finishManifestApplyFailure(requestCtx, change.ID, "requester", map[string]any{"error": context.Canceled.Error()}); err != nil {
		t.Fatalf("detached preflight finalization failed: %v", err)
	}

	stored, err := db.GetK8sManifestChangeRequest(ctx, change.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "failed" {
		t.Fatalf("canceled request context must not leave manifest change running: %+v", stored)
	}
	if stored.ApplyResult["status"] != "failed" {
		t.Fatalf("failure evidence was not persisted: %+v", stored.ApplyResult)
	}
}

func TestK8sManifestApplyCancellationAfterAPIAcceptFinalizesAmbiguousOutcome(t *testing.T) {
	accepted := make(chan struct{})
	releaseAPIHandler := make(chan struct{})
	var acceptedOnce sync.Once
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(releaseAPIHandler) }) }
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/namespaces/default/configmaps/settings" {
			http.NotFound(w, r)
			return
		}
		acceptedOnce.Do(func() { close(accepted) })
		<-releaseAPIHandler
	}))
	defer kubeAPI.Close()
	defer releaseHandler()

	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	cluster := store.K8sCluster{
		ID: "manifest-cancel-cluster", Name: "manifest-cancel-cluster",
		ServerURL: kubeAPI.URL, AuthMode: "kubeconfig", Status: "ready",
	}
	if err := db.UpsertK8sCluster(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	afterYAML := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: default\ndata:\n  mode: safe\n"
	change := store.K8sManifestChangeRequest{
		ID:               "manifest-cancel-after-accept",
		ClusterID:        cluster.ID,
		Namespace:        "default",
		Kind:             "ConfigMap",
		APIVersion:       "v1",
		Name:             "settings",
		Status:           "approved",
		RiskLevel:        "high",
		RequiresApproval: true,
		AfterYAML:        afterYAML,
		AfterHash:        manifestHash(afterYAML),
		Impact:           map[string]any{"operation": "create"},
		CreatedBy:        "requester",
		ApprovedBy:       "approver",
		IdempotencyKey:   "manifest-cancel-after-accept",
	}
	if err := db.CreateK8sManifestChangeRequest(ctx, change); err != nil {
		t.Fatal(err)
	}

	server := &Server{db: db}
	baseRequest := httptest.NewRequest(http.MethodPost, "/admin/k8s/manifest-changes/"+change.ID+"/apply", strings.NewReader(`{}`))
	requestCtx, cancelRequest := context.WithCancel(baseRequest.Context())
	defer cancelRequest()
	request := baseRequest.WithContext(requestCtx)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.applyK8sManifestChange(recorder, request, change.ID)
	}()

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("Kubernetes API did not receive the apply request")
	}
	cancelRequest()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("manifest apply did not finish after request cancellation")
	}
	releaseHandler()

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("canceled apply status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	stored, err := db.GetK8sManifestChangeRequest(ctx, change.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "failed" {
		t.Fatalf("cancellation after API acceptance must not leave the ledger running: %+v", stored)
	}
	if stored.ApplyResult["status"] != "failed" ||
		stored.ApplyResult["outcome"] != "ambiguous" ||
		stored.ApplyResult["outcome_ambiguous"] != true ||
		stored.ApplyResult["reconciliation_required"] != true {
		t.Fatalf("ambiguous cancellation evidence was not persisted: %+v", stored.ApplyResult)
	}
	if !strings.Contains(stored.Result, "outcome is unknown") {
		t.Fatalf("ledger result must explain the ambiguous outcome, got %q", stored.Result)
	}
}
