package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// A rollout that is failed with auto-rollback pending: reconciling it is what
// issues the restore patch to Kubernetes.
func rollbackDueFixture(t *testing.T, name string) (*Server, *store.SQLStore, *atomic.Int32, string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), name+".db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	deployment := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"prod","uid":"uid-api",` +
		`"annotations":{"deployment.kubernetes.io/revision":"4"}},` +
		`"spec":{"replicas":1,"template":{"metadata":{"labels":{"app":"api"}}}},` +
		`"status":{"replicas":1,"updatedReplicas":1,"readyReplicas":1,"availableReplicas":1,"observedGeneration":4}}`
	patches := &atomic.Int32{}
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patches.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(deployment))
	}))
	t.Cleanup(kubeAPI.Close)
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", ServerURL: kubeAPI.URL}); err != nil {
		t.Fatal(err)
	}

	spec := map[string]any{
		"replicas": float64(1),
		"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}},
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: spec, Annotations: map[string]string{"deployment.kubernetes.io/revision": "4"},
		StatusObject: map[string]any{
			"replicas": float64(1), "updatedReplicas": float64(1), "readyReplicas": float64(1),
			"availableReplicas": float64(1), "observedGeneration": float64(4),
		},
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	action := store.K8sActionRequest{
		ID: "act-" + name, ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", Action: "rollout_restart", Status: "approved", TargetUID: "uid-api",
	}
	rollout := store.K8sRolloutAction{
		ID: "roll-" + name, ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
		Status: "monitoring", AutoRollback: true, TimeoutSeconds: 600,
		PreviousRevision: "4", PreviousSpecHash: hashJSON(spec),
		PreviousTemplate: map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}},
		StartedAt:        time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano),
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, rollout, store.K8sRolloutEvent{ID: "ev-" + name}); err != nil {
		t.Fatal(err)
	}
	current, err := db.GetK8sRolloutAction(ctx, rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Status = "failed"
	current.FailureReason = "rollout failed"
	current.RollbackStatus = ""
	if err := db.UpdateK8sRolloutProgress(ctx, current); err != nil {
		t.Fatal(err)
	}
	return &Server{db: db, client: http.DefaultClient}, db, patches, rollout.ID
}

// Patching a Deployment is a cluster mutation and `rollout:rollback` is a real
// issuable scope, but the rollout detail endpoint requires only `rollout:view`.
// A read path must therefore never initiate the rollback — nor be recorded as
// the actor that did.
func TestReadPathDoesNotInitiateRollback(t *testing.T) {
	ctx := context.Background()
	server, db, patches, rolloutID := rollbackDueFixture(t, "viewer")

	roll, err := db.GetK8sRolloutAction(ctx, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/k8s/rollouts/"+rolloutID, nil)
	if _, err := server.reconcileRollout(req, roll); err != nil {
		t.Fatal(err)
	}

	if patches.Load() != 0 {
		t.Fatalf("a read path issued %d Kubernetes patches", patches.Load())
	}
	after, err := db.GetK8sRolloutAction(ctx, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RollbackStatus == "running" {
		t.Fatal("a read path claimed the rollback execution")
	}
}

// The worker still performs it, so nothing is lost by deferring.
func TestWorkerStillInitiatesRollback(t *testing.T) {
	ctx := context.Background()
	server, db, patches, rolloutID := rollbackDueFixture(t, "worker")

	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "rollback-owner"})
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if patches.Load() == 0 {
		t.Fatal("the worker did not issue the rollback patch")
	}
	after, err := db.GetK8sRolloutAction(ctx, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RollbackStatus == "" {
		t.Fatalf("worker left the rollback undecided: %+v", after)
	}
}
