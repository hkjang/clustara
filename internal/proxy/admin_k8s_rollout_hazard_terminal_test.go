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

// A rollout blocked by the execution-time hazard check must end up terminal, not
// retried forever. The reconciler has no per-item give-up, so a blocked approval
// that stayed due would be re-processed on every tick, make no progress, never
// trip the failure backoff, and — because terminal rows sort first in the due
// queue — starve live rollout work.
func TestHazardBlockedRolloutBecomesTerminal(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "hazard-terminal.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	var patches atomic.Int32
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patches.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer kubeAPI.Close()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", ServerURL: kubeAPI.URL}); err != nil {
		t.Fatal(err)
	}

	spec := map[string]any{
		"replicas": float64(2),
		"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}},
	}
	// Deleting target: an unambiguous execution-time hazard.
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: spec, DeletionTimestamp: time.Now().UTC().Format(time.RFC3339Nano),
		StatusObject: map[string]any{
			"replicas": float64(2), "updatedReplicas": float64(2), "readyReplicas": float64(2),
			"availableReplicas": float64(2), "observedGeneration": float64(4),
		},
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	action := store.K8sActionRequest{
		ID: "act-hazard", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", Action: "rollout_restart", Status: "approved", TargetUID: "uid-api",
	}
	rollout := store.K8sRolloutAction{
		ID: "roll-hazard", ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
		Status: "approved", TimeoutSeconds: 600, PreviousSpecHash: hashJSON(spec),
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, rollout, store.K8sRolloutEvent{ID: "ev-hazard"}); err != nil {
		t.Fatal(err)
	}

	server := &Server{db: db, client: http.DefaultClient}
	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "hazard-owner"})

	// The first tick reports the blocked execution; later ticks must find nothing
	// left to do rather than re-attempting it.
	_ = worker.ReconcileOnce(ctx)

	after, err := db.GetK8sRolloutAction(ctx, rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !rolloutTerminal(after.Status) {
		t.Fatalf("hazard-blocked rollout status = %q, want a terminal state", after.Status)
	}
	if patches.Load() != 0 {
		t.Fatalf("a hazard-blocked rollout issued %d Kubernetes patches", patches.Load())
	}

	for i := 0; i < 3; i++ {
		if err := worker.ReconcileOnce(ctx); err != nil {
			t.Fatalf("tick %d after the block errored: %v", i, err)
		}
	}
	due, err := db.ListK8sRolloutActionsDue(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range due {
		if item.ID == rollout.ID {
			t.Fatal("the blocked rollout is still due; the reconciler would spin on it every tick")
		}
	}
	if patches.Load() != 0 {
		t.Fatalf("later ticks issued %d Kubernetes patches for a blocked rollout", patches.Load())
	}
}
