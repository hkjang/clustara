package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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

func TestRolloutProgressByWorkloadKind(t *testing.T) {
	tests := []struct {
		item                        store.K8sInventoryItem
		desired, updated, available int
	}{
		{store.K8sInventoryItem{Kind: "Deployment", Spec: map[string]any{"replicas": float64(3)}, StatusObject: map[string]any{"updatedReplicas": float64(2), "availableReplicas": float64(1)}}, 3, 2, 1},
		{store.K8sInventoryItem{Kind: "DaemonSet", StatusObject: map[string]any{"desiredNumberScheduled": float64(5), "updatedNumberScheduled": float64(4), "numberAvailable": float64(3)}}, 5, 4, 3},
	}
	for _, tt := range tests {
		if rolloutDesired(tt.item) != tt.desired || rolloutUpdated(tt.item) != tt.updated || rolloutAvailable(tt.item) != tt.available {
			t.Fatalf("bad progress for %s", tt.item.Kind)
		}
	}
}

func TestRolloutSuperAdminDirectForLegacyAdminTokenMode(t *testing.T) {
	s := &Server{}
	if !s.rolloutSuperAdmin(httptest.NewRequest("POST", "/api/v1/workloads/rollout", nil)) {
		t.Fatal("auth-disabled ADMIN_TOKEN mode should retain highest-admin direct execution")
	}
}

func TestRolloutFailureAndOwnerMatching(t *testing.T) {
	target := store.K8sInventoryItem{Kind: "Deployment", Namespace: "prod", Spec: map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}}}
	pod := store.K8sInventoryItem{Kind: "Pod", Namespace: "prod", Labels: map[string]string{"app": "api"}}
	if !podOwnedByWorkload(pod, target) {
		t.Fatal("selector should match pod")
	}
	target.StatusObject = map[string]any{"conditions": []any{map[string]any{"type": "Progressing", "reason": "ProgressDeadlineExceeded"}}}
	if !rolloutConditionFailed(target) {
		t.Fatal("deadline failure must be detected")
	}
}

func TestRolloutObservationRequiresMutationAndControllerEvidence(t *testing.T) {
	now := time.Now().UTC()
	baseSpec := map[string]any{
		"replicas": float64(1),
		"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}},
	}
	roll := store.K8sRolloutAction{
		ID: "rollout-1", ActionRequestID: "action-1", StartedAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
		PreviousRevision: "4", PreviousSpecHash: hashJSON(baseSpec), Precheck: map[string]any{"observed_generation": float64(4)},
		DesiredReplicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1,
	}
	status := map[string]any{
		"updatedReplicas": float64(1), "readyReplicas": float64(1), "availableReplicas": float64(1),
		"observedGeneration": float64(4),
	}
	patchedSpec := map[string]any{
		"replicas": float64(1),
		"template": map[string]any{"metadata": map[string]any{
			"labels":      map[string]any{"app": "api"},
			"annotations": map[string]any{"clustara.io/actionId": "action-1", "clustara.io/restartedAt": now.Format(time.RFC3339)},
		}},
	}
	mutationOnly := store.K8sInventoryItem{
		Spec: patchedSpec, StatusObject: status, Annotations: map[string]string{"deployment.kubernetes.io/revision": "4"},
		ObservedAt: now.Format(time.RFC3339Nano),
	}
	got := observeRollout(roll, mutationOnly)
	if !got.MutationObserved || got.ControllerObserved || got.ExecutionObserved {
		t.Fatalf("mutation-only observation was misclassified: %+v", got)
	}

	controllerOnly := mutationOnly
	controllerOnly.Spec = baseSpec
	controllerOnly.Annotations = map[string]string{"deployment.kubernetes.io/revision": "5"}
	controllerOnly.StatusObject = map[string]any{
		"updatedReplicas": float64(1), "readyReplicas": float64(1), "availableReplicas": float64(1),
		"observedGeneration": float64(5),
	}
	got = observeRollout(roll, controllerOnly)
	if got.MutationObserved || !got.ControllerObserved || got.ExecutionObserved {
		t.Fatalf("controller-only observation was misclassified: %+v", got)
	}

	both := controllerOnly
	both.Spec = patchedSpec
	got = observeRollout(roll, both)
	if !got.MutationObserved || !got.ControllerObserved || !got.ExecutionObserved {
		t.Fatalf("combined rollout evidence was not accepted: %+v", got)
	}

	roll.RollbackStartedAt = now.Add(-30 * time.Second).Format(time.RFC3339Nano)
	roll.TargetRevision = "5"
	roll.TargetSpecHash = hashJSON(patchedSpec)
	roll.PreviousTemplate = baseSpec["template"].(map[string]any)
	restored := store.K8sInventoryItem{
		Spec: map[string]any{
			"replicas": float64(1),
			"template": map[string]any{"metadata": map[string]any{
				"labels": map[string]any{"app": "api"},
				"annotations": map[string]any{
					"clustara.io/actionId": roll.ID, "clustara.io/rollbackAt": now.Format(time.RFC3339),
				},
			}},
		},
		Annotations: map[string]string{"deployment.kubernetes.io/revision": "5"},
		ObservedAt:  now.Format(time.RFC3339Nano),
	}
	got = observeRollout(roll, restored)
	if !got.RollbackMutationObserved || got.RollbackControllerObserved || got.RollbackObserved {
		t.Fatalf("rollback patch acknowledgement was misclassified as recovery: %+v", got)
	}
	restored.Annotations["deployment.kubernetes.io/revision"] = "6"
	got = observeRollout(roll, restored)
	if !got.RollbackMutationObserved || !got.RollbackControllerObserved || !got.RollbackObserved {
		t.Fatalf("controller-observed rollback recovery was not accepted: %+v", got)
	}
}

func TestRolloutWorkerResumesAfterRestartWithoutAcceptingStaleHealthySnapshot(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "rollout-restart.db")
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	baseTemplate := map[string]any{
		"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
		"spec":     map[string]any{"containers": []any{map[string]any{"name": "api", "image": "example/api:1"}}},
	}
	baseSpec := map[string]any{
		"replicas": float64(1), "selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		"template": baseTemplate,
	}
	patchedSpec := map[string]any{
		"replicas": float64(1), "selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		"template": map[string]any{
			"metadata": map[string]any{
				"labels": map[string]any{"app": "api"},
				"annotations": map[string]any{
					"clustara.io/actionId": "action-1", "clustara.io/restartedAt": now.Format(time.RFC3339),
				},
			},
			"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "example/api:1"}}},
		},
	}
	if err := db.InsertK8sRolloutAction(ctx, store.K8sRolloutAction{
		ID: "rollout-1", ActionRequestID: "action-1", ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api", Reason: "restart",
		Status: "monitoring", StartedAt: now.Add(-30 * time.Second).Format(time.RFC3339Nano), TimeoutSeconds: 600,
		PreviousRevision: "4", PreviousSpecHash: hashJSON(baseSpec), PreviousTemplate: baseTemplate,
		Precheck: map[string]any{"observed_generation": float64(4)},
	}); err != nil {
		t.Fatal(err)
	}
	inventory := store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: patchedSpec, Annotations: map[string]string{"deployment.kubernetes.io/revision": "4"},
		StatusObject: map[string]any{
			"replicas": float64(1), "updatedReplicas": float64(1), "readyReplicas": float64(1),
			"availableReplicas": float64(1), "observedGeneration": float64(4),
		},
		ObservedAt: now.Add(-10 * time.Second).Format(time.RFC3339Nano),
	}
	if err := db.UpsertK8sInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	server := &Server{db: db, client: http.DefaultClient}
	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "replica-after-restart"})
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := db.GetK8sRolloutAction(ctx, "rollout-1")
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != "monitoring" {
		t.Fatalf("stale healthy snapshot completed rollout: %+v", current)
	}

	inventory.Annotations["deployment.kubernetes.io/revision"] = "5"
	inventory.StatusObject["observedGeneration"] = float64(5)
	inventory.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := db.UpsertK8sInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	current, err = db.GetK8sRolloutAction(ctx, "rollout-1")
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != "succeeded" || current.CompletedAt == "" {
		t.Fatalf("controller-observed rollout did not complete: %+v", current)
	}
}

func TestRollbackRequestUsesCASClaimBeforeExternalPatch(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollback-claim.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"uid-api"}}`))
			return
		}
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer kubeAPI.Close()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", ServerURL: kubeAPI.URL}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sRolloutAction(ctx, store.K8sRolloutAction{
		ID: "rollout-1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		ResourceUID: "uid-api", Reason: "recover", Status: "failed", AutoRollback: true,
		RollbackStatus: "requested", RollbackStartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		PreviousTemplate: map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}},
	}); err != nil {
		t.Fatal(err)
	}
	roll, _ := db.GetK8sRolloutAction(ctx, "rollout-1")
	server := &Server{db: db, client: http.DefaultClient}
	firstDone := make(chan error, 1)
	go func() {
		_, requestErr := server.requestAutoRollback(ctx, "worker-a", roll)
		firstDone <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first rollback patch did not start")
	}
	second, err := server.requestAutoRollback(ctx, "worker-b", roll)
	if err != nil {
		t.Fatal(err)
	}
	if second.RollbackStatus != "running" {
		t.Fatalf("losing claimant saw status %q, want running", second.RollbackStatus)
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate rollback patch count=%d", calls.Load())
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	final, _ := db.GetK8sRolloutAction(ctx, "rollout-1")
	if final.RollbackStatus != "monitoring" || final.RollbackCompletedAt != "" {
		t.Fatalf("rollback patch acknowledgement was treated as completion: %+v", final)
	}
	if rolloutRollbackRequestTimeout >= rolloutRollbackClaimGrace {
		t.Fatalf("rollback request timeout %s must remain below claim grace %s", rolloutRollbackRequestTimeout, rolloutRollbackClaimGrace)
	}
	if rolloutRollbackMinimumTimeout <= rolloutRollbackClaimGrace {
		t.Fatalf("rollback monitoring timeout %s must exceed claim grace %s", rolloutRollbackMinimumTimeout, rolloutRollbackClaimGrace)
	}
	if !rollbackPatchOutcomeAmbiguous(context.DeadlineExceeded) || !rollbackPatchOutcomeAmbiguous(context.Canceled) {
		t.Fatal("deadline/cancellation must retain the rollback lock as an ambiguous outcome")
	}
	if rollbackPatchOutcomeAmbiguous(errors.New("definite Kubernetes rejection")) {
		t.Fatal("definite rollback rejection was classified as ambiguous")
	}
}

func TestRolloutMutationCancellationIsRecoveredWithoutDuplicatePatch(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-cancel-recovery.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	var patches atomic.Int32
	accepted := make(chan struct{}, 1)
	// Released on cleanup so the handler can never outlive the test: net/http
	// only starts the background read that detects a client disconnect once the
	// request body hits EOF, so a handler that blocks without draining r.Body
	// would keep httptest.Server.Close waiting forever.
	handlersDone := make(chan struct{})
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			return
		}
		patches.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case accepted <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-handlersDone:
		}
	}))
	t.Cleanup(func() {
		close(handlersDone)
		kubeAPI.Close()
	})
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", ServerURL: kubeAPI.URL}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	baseSpec := map[string]any{
		"replicas": float64(1),
		"template": map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
			"spec":     map[string]any{"containers": []any{map[string]any{"name": "api", "image": "example/api:1"}}},
		},
	}
	inventory := store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: baseSpec, Annotations: map[string]string{"deployment.kubernetes.io/revision": "4"},
		StatusObject: map[string]any{
			"replicas": float64(1), "updatedReplicas": float64(1), "readyReplicas": float64(1),
			"availableReplicas": float64(1), "observedGeneration": float64(4),
		},
		ObservedAt: now.Format(time.RFC3339Nano),
	}
	if err := db.UpsertK8sInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	action := store.K8sActionRequest{
		ID: "action-cancel", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", Status: "approved", TargetUID: "uid-api",
		Parameters: map[string]any{"reason": "cancel boundary"},
	}
	rollout := store.K8sRolloutAction{
		ID: "rollout-cancel", ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api", Reason: "cancel boundary",
		Status: "approved", TimeoutSeconds: 600, PreviousRevision: "4", PreviousSpecHash: hashJSON(baseSpec),
		Precheck: map[string]any{"observed_generation": float64(4)},
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, rollout, store.K8sRolloutEvent{ID: "event-cancel"}); err != nil {
		t.Fatal(err)
	}

	requestCtx, cancelRequest := context.WithCancel(ctx)
	resultCh := make(chan k8sActionRunResult, 1)
	server := &Server{db: db, client: http.DefaultClient}
	go func() {
		resultCh <- server.runApprovedK8sAction(requestCtx, "admin-1", action)
	}()
	select {
	case <-accepted:
		cancelRequest()
	case <-time.After(5 * time.Second):
		t.Fatal("rollout mutation did not reach the API server")
	}
	var result k8sActionRunResult
	select {
	case result = <-resultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled rollout execution did not finalize")
	}
	if result.Err != nil || result.Status != "running" || result.HTTPStatus != http.StatusAccepted {
		t.Fatalf("ambiguous rollout result=%+v", result)
	}
	savedAction, _ := db.GetK8sActionRequest(ctx, action.ID)
	savedRollout, _ := db.GetK8sRolloutAction(ctx, rollout.ID)
	if savedAction.Status != "running" || savedRollout.Status != "monitoring" || savedRollout.StartedAt == "" {
		t.Fatalf("cancel boundary was not durably recoverable: action=%+v rollout=%+v", savedAction, savedRollout)
	}

	inventory.Spec = map[string]any{
		"replicas": float64(1),
		"template": map[string]any{
			"metadata": map[string]any{
				"labels": map[string]any{"app": "api"},
				"annotations": map[string]any{
					"clustara.io/actionId": action.ID, "clustara.io/restartedAt": time.Now().UTC().Format(time.RFC3339),
				},
			},
			"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "example/api:1"}}},
		},
	}
	inventory.Annotations["deployment.kubernetes.io/revision"] = "5"
	inventory.StatusObject["observedGeneration"] = float64(5)
	inventory.ObservedAt = time.Now().UTC().Add(time.Millisecond).Format(time.RFC3339Nano)
	if err := db.UpsertK8sInventory(ctx, inventory); err != nil {
		t.Fatal(err)
	}
	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "recovery-worker"})
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	savedAction, _ = db.GetK8sActionRequest(ctx, action.ID)
	savedRollout, _ = db.GetK8sRolloutAction(ctx, rollout.ID)
	if savedRollout.Status != "succeeded" || savedAction.Status != "executed" {
		t.Fatalf("inventory evidence did not resolve ambiguous mutation: action=%+v rollout=%+v", savedAction, savedRollout)
	}
	if patches.Load() != 1 {
		t.Fatalf("recovery reissued the rollout patch %d times", patches.Load())
	}
}

func TestRolloutWorkerRecoversApprovedExecutionHandoff(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-approved-handoff.db")})
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
		ID: "approved-action", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", Status: "approved", TargetUID: "uid-api",
	}
	rollout := store.K8sRolloutAction{
		ID: "approval-handoff", ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api", Reason: "approved before crash",
		Status: "approval_required", PreviousRevision: "4", PreviousSpecHash: hashJSON(spec),
		Precheck: map[string]any{"observed_generation": float64(4)},
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, rollout, store.K8sRolloutEvent{ID: "handoff-event"}); err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db, client: http.DefaultClient}
	worker := server.NewK8sRolloutReconciler(K8sRolloutReconcilerOptions{OwnerID: "handoff-worker"})
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := worker.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	savedAction, _ := db.GetK8sActionRequest(ctx, action.ID)
	savedRollout, _ := db.GetK8sRolloutAction(ctx, rollout.ID)
	if savedAction.Status != "executed" || savedRollout.Status != "monitoring" || savedRollout.StartedAt == "" {
		t.Fatalf("approved handoff was not resumed: action=%+v rollout=%+v", savedAction, savedRollout)
	}
	if patches.Load() != 1 {
		t.Fatalf("approved handoff issued %d patches", patches.Load())
	}
}

func TestAutoRollbackRefusesReplacementResourceUID(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollback-uid-guard.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var patches atomic.Int32
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"replacement-uid"}}`))
			return
		}
		if r.Method == http.MethodPatch {
			patches.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer kubeAPI.Close()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", ServerURL: kubeAPI.URL}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sRolloutAction(ctx, store.K8sRolloutAction{
		ID: "rollback-uid", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		ResourceUID: "original-uid", Reason: "recover", Status: "failed", AutoRollback: true,
		RollbackStatus: "requested", RollbackStartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		PreviousTemplate: map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}},
	}); err != nil {
		t.Fatal(err)
	}
	rollout, _ := db.GetK8sRolloutAction(ctx, "rollback-uid")
	server := &Server{db: db, client: http.DefaultClient}
	got, err := server.requestAutoRollback(ctx, "worker", rollout)
	if err != nil {
		t.Fatal(err)
	}
	if got.RollbackStatus != "failed" || !strings.Contains(got.RollbackFailureReason, "UID changed") {
		t.Fatalf("replacement UID was not fail-closed: %+v", got)
	}
	if patches.Load() != 0 {
		t.Fatalf("rollback patched a replacement object %d times", patches.Load())
	}
}

func TestRolloutKeycloakViewerDoesNotInheritLegacyAdminBypass(t *testing.T) {
	s := &Server{cfg: config.Config{Keycloak: config.KeycloakConfig{Enabled: true}}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/workloads/rollout", nil)
	cacheVerifiedAccessClaims(r, accessClaims{Subject: "viewer-1", Role: "viewer", Scopes: []string{"rollout:view"}})
	if s.rolloutSuperAdmin(r) {
		t.Fatal("Keycloak viewer was elevated to rollout super admin")
	}
	if s.rolloutScopeAllowed(r, "rollout:execute") {
		t.Fatal("Keycloak viewer inherited legacy execute bypass")
	}
	if !s.rolloutScopeAllowed(r, "rollout:view") {
		t.Fatal("explicit Keycloak scope was not honored")
	}
}

func TestRolloutFailureEvidenceWinsOverTimeoutAndHealthyCounts(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-priority.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	baseSpec := map[string]any{"replicas": float64(1), "template": map[string]any{"metadata": map[string]any{}}}
	patchedSpec := map[string]any{
		"replicas": float64(1),
		"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{
			"clustara.io/actionId": "action-1", "clustara.io/restartedAt": now.Format(time.RFC3339),
		}}},
	}
	if err := db.InsertK8sRolloutAction(ctx, store.K8sRolloutAction{
		ID: "rollout-1", ActionRequestID: "action-1", ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api", Reason: "restart",
		Status: "monitoring", StartedAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano), TimeoutSeconds: 1,
		PreviousRevision: "4", PreviousSpecHash: hashJSON(baseSpec), Precheck: map[string]any{"observed_generation": float64(4)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: patchedSpec, Annotations: map[string]string{"deployment.kubernetes.io/revision": "5"},
		StatusObject: map[string]any{
			"replicas": float64(1), "updatedReplicas": float64(1), "readyReplicas": float64(1), "availableReplicas": float64(1),
			"observedGeneration": float64(5),
			"conditions":         []any{map[string]any{"type": "Progressing", "reason": "ProgressDeadlineExceeded"}},
		},
		ObservedAt: now.Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	roll, _ := db.GetK8sRolloutAction(ctx, "rollout-1")
	server := &Server{db: db, client: http.DefaultClient}
	got, err := server.reconcileRolloutContext(ctx, "worker", roll)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" || got.FailureReason == "rollout timeout" {
		t.Fatalf("failure did not win over timeout/healthy counts: %+v", got)
	}
}

func TestRolloutExecutionDriftGuardClosesActionWithoutMutation(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-drift.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	original := map[string]any{"replicas": float64(2), "template": map[string]any{"metadata": map[string]any{}}}
	drifted := map[string]any{"replicas": float64(3), "template": map[string]any{"metadata": map[string]any{}}}
	action := store.K8sActionRequest{
		ID: "action-1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", Status: "approved", TargetUID: "uid-api", IdempotencyKey: "idem-drift",
	}
	roll := store.K8sRolloutAction{
		ID: "rollout-1", ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api", Reason: "restart",
		Status: "approved", PreviousSpecHash: hashJSON(original),
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, roll, store.K8sRolloutEvent{ID: "event-1", ActionID: roll.ID}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api", Spec: drifted,
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db, client: http.DefaultClient}
	result := server.runApprovedK8sAction(ctx, "admin-1", action)
	if result.ErrorCode != "rollout_target_drift" || result.HTTPStatus != http.StatusConflict {
		t.Fatalf("drift guard result=%+v", result)
	}
	savedAction, _ := db.GetK8sActionRequest(ctx, action.ID)
	savedRollout, _ := db.GetK8sRolloutAction(ctx, roll.ID)
	if savedAction.Status != "failed" || savedRollout.Status != "failed" || savedRollout.CompletedAt == "" {
		t.Fatalf("drifted execution was not durably closed: action=%+v rollout=%+v", savedAction, savedRollout)
	}
}

func TestRolloutRequestIdempotencyReplaysOneLedgerAndOnePatch(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-idempotency.db")})
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
	now := time.Now().UTC()
	spec := map[string]any{
		"replicas": float64(1), "selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		"template": map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
			"spec":     map[string]any{"containers": []any{map[string]any{"name": "api", "image": "example/api:1"}}},
		},
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: spec, Annotations: map[string]string{"deployment.kubernetes.io/revision": "4"},
		StatusObject: map[string]any{
			"replicas": float64(1), "updatedReplicas": float64(1), "readyReplicas": float64(1),
			"availableReplicas": float64(1), "observedGeneration": float64(4),
		},
		ObservedAt: now.Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db, client: http.DefaultClient}
	body, _ := json.Marshal(rolloutRequestInput{
		ClusterID: "c1", Namespace: "prod", Kind: "Deployment", Name: "api",
		Reason: "refresh", ExecutionMode: "IMMEDIATE",
	})
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/workloads/rollout", bytes.NewReader(body))
		req.Header.Set("Idempotency-Key", "rollout-idem-1")
		rec := httptest.NewRecorder()
		server.handleWorkloadRollout(rec, req)
		return rec
	}
	first := call()
	if first.Code != http.StatusAccepted {
		t.Fatalf("first request status=%d body=%s", first.Code, first.Body.String())
	}
	second := call()
	if second.Code != http.StatusAccepted {
		t.Fatalf("replay status=%d body=%s", second.Code, second.Body.String())
	}
	if patches.Load() != 1 {
		t.Fatalf("idempotent replay issued %d patches", patches.Load())
	}
	actions, err := db.ListK8sActionRequests(ctx, store.K8sActionFilter{ClusterID: "c1", Limit: 10})
	if err != nil || len(actions) != 1 {
		t.Fatalf("actions=%d err=%v", len(actions), err)
	}
	rollouts, err := db.ListK8sRolloutActions(ctx, "c1", "uid-api", 10)
	if err != nil || len(rollouts) != 1 {
		t.Fatalf("rollouts=%d err=%v", len(rollouts), err)
	}
}

func TestRolloutApproveRejectsSupersededRolloutState(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-stale-approval.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	action := store.K8sActionRequest{
		ID: "stale-action", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", Status: "approval_required",
	}
	rollout := store.K8sRolloutAction{
		ID: "superseded-rollout", ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api", Reason: "superseded",
		Status: "failed", RollbackStatus: "failed", FailureReason: "superseded by lock migration",
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, rollout, store.K8sRolloutEvent{ID: "stale-event"}); err != nil {
		t.Fatal(err)
	}

	server := &Server{db: db, client: http.DefaultClient}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollouts/"+rollout.ID+"/approve", nil)
	rec := httptest.NewRecorder()
	server.handleRolloutByID(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rollout_bad_state") {
		t.Fatalf("approve returned the wrong conflict: %s", rec.Body.String())
	}
	saved, err := db.GetK8sActionRequest(ctx, action.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Status != "approval_required" {
		t.Fatalf("stale approval mutated linked action: %+v", saved)
	}
}
