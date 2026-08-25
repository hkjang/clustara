package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// terminalRollbackFixture builds a rollout whose primary status is terminal but
// which still has rollback work outstanding — the state the reconciler's due
// query explicitly selects for.
func terminalRollbackFixture(t *testing.T, name string, mutate func(*store.K8sRolloutAction)) (*Server, *store.SQLStore, *atomic.Int32, string) {
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

	// The rollback reads the live Deployment before patching it, so the fake API
	// has to return a decodable object or the attempt fails before any patch.
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
	mutate(&current)
	if err := db.UpdateK8sRolloutProgress(ctx, current); err != nil {
		t.Fatal(err)
	}
	return &Server{db: db, client: http.DefaultClient}, db, patches, rollout.ID
}

func rolloutIsDue(t *testing.T, db *store.SQLStore, id string) bool {
	t.Helper()
	due, err := db.ListK8sRolloutActionsDue(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range due {
		if item.ID == id {
			return true
		}
	}
	return false
}

// A failed rollout with auto-rollback and no rollback decision yet is exactly
// what the due query selects for, but the worker used to return early on the
// terminal primary status. The rollback was never requested and the row stayed
// due forever, re-processed every tick with no progress and no backoff.
func TestReconcilerRunsAutoRollbackOnTerminalRollout(t *testing.T) {
	server, db, patches, rolloutID := terminalRollbackFixture(t, "pending", func(roll *store.K8sRolloutAction) {
		roll.Status = "failed"
		roll.FailureReason = "failure recorded outside the reconciler"
		roll.RollbackStatus = ""
	})
	ctx := context.Background()
	if !rolloutIsDue(t, db, rolloutID) {
		t.Fatal("fixture is not selected by the due query")
	}

	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "terminal-rollback"})
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}

	after, err := db.GetK8sRolloutAction(ctx, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RollbackStatus == "" {
		t.Fatal("auto-rollback was never decided on a terminal rollout")
	}
	if patches.Load() == 0 {
		t.Fatal("the rollback never reached the Kubernetes API")
	}
	// Staying due here is correct: the restore patch is in flight and later
	// ticks monitor it. The bug was staying due while making no progress.
	if after.RollbackStartedAt == "" {
		t.Fatalf("rollback was decided but never started: %+v", after)
	}
}

// The rollback timeout lives in reconcileRolloutContext. When the worker
// short-circuited on the terminal primary status, a rollback left in
// "monitoring" could never succeed, fail, or time out.
func TestReconcilerResolvesStrandedRollbackMonitoring(t *testing.T) {
	server, db, _, rolloutID := terminalRollbackFixture(t, "monitoring", func(roll *store.K8sRolloutAction) {
		roll.Status = "failed"
		roll.FailureReason = "rollout failed"
		roll.RollbackStatus = "monitoring"
		roll.RollbackStartedAt = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	})
	ctx := context.Background()
	if !rolloutIsDue(t, db, rolloutID) {
		t.Fatal("fixture is not selected by the due query")
	}

	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "stranded-rollback"})
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}

	after, err := db.GetK8sRolloutAction(ctx, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RollbackStatus == "monitoring" {
		t.Fatal("rollback is still monitoring; its timeout can never fire")
	}
	if after.RollbackCompletedAt == "" {
		t.Fatalf("resolved rollback has no completion timestamp: %+v", after)
	}
	if !strings.Contains(after.RollbackFailureReason, "timeout") {
		t.Fatalf("rollback failure reason = %q, want the timeout to be named", after.RollbackFailureReason)
	}
	if rolloutIsDue(t, db, rolloutID) {
		t.Fatal("the rollout is still due after reconciling; it would spin on every tick")
	}
}

// A genuinely finished rollout must still take the cheap path: reconcile once,
// close out the action request, and drop out of the due queue.
func TestReconcilerLeavesSettledTerminalRolloutAlone(t *testing.T) {
	server, db, patches, rolloutID := terminalRollbackFixture(t, "settled", func(roll *store.K8sRolloutAction) {
		roll.Status = "succeeded"
		roll.RollbackStatus = ""
		roll.AutoRollback = false
		roll.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	})
	ctx := context.Background()

	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "settled"})
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := db.GetK8sRolloutAction(ctx, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "succeeded" || after.RollbackStatus != "" {
		t.Fatalf("settled rollout was mutated: %+v", after)
	}
	if patches.Load() != 0 {
		t.Fatalf("settled rollout issued %d Kubernetes patches", patches.Load())
	}
}
