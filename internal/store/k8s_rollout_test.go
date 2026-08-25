package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/config"
)

func TestK8sRolloutLedgerRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a := K8sRolloutAction{ID: "r1", ActionRequestID: "a1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-1", RequestedBy: "user", Reason: "refresh", Status: "monitoring", DesiredReplicas: 3,
		UpdatedReplicas: 1, ReadyReplicas: 1, Precheck: map[string]any{"healthy": true},
		PreviousTemplate: map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "api"}}}}}
	if err := db.InsertK8sRolloutAction(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetK8sRolloutAction(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ResourceUID != "uid-1" || got.DesiredReplicas != 3 || got.Precheck["healthy"] != true || len(got.PreviousTemplate) == 0 {
		t.Fatalf("bad rollout: %+v", got)
	}
	got.Status = "succeeded"
	got.UpdatedReplicas = 3
	got.ReadyReplicas = 3
	got.AvailableReplicas = 3
	if err := db.UpdateK8sRolloutProgress(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sRolloutPodTransition(ctx, K8sRolloutPodTransition{ID: "p1", ActionID: "r1", PodUID: "pod-1", PodName: "api-new", ReadyAt: "2026-07-27T00:01:00Z"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendK8sRolloutEvent(ctx, K8sRolloutEvent{ID: "e1", ActionID: "r1", Status: "monitoring", Stage: "pod_replacement", Evidence: map[string]any{"ready": 1}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendK8sRolloutEvent(ctx, K8sRolloutEvent{ID: "e2", ActionID: "r1", Status: "succeeded", Stage: "completed"}); err != nil {
		t.Fatal(err)
	}
	events, err := db.ListK8sRolloutEvents(ctx, "r1")
	if err != nil || len(events) != 2 || events[1].SequenceNo != 2 {
		t.Fatalf("bad events=%+v err=%v", events, err)
	}
	pods, err := db.ListK8sRolloutPodTransitions(ctx, "r1")
	if err != nil || len(pods) != 1 || pods[0].ReadyAt == "" {
		t.Fatalf("bad pods=%+v err=%v", pods, err)
	}
	list, err := db.ListK8sRolloutActions(ctx, "c1", "uid-1", 10)
	if err != nil || len(list) != 1 || list[0].Status != "succeeded" {
		t.Fatalf("bad list=%+v err=%v", list, err)
	}
}

func TestK8sRolloutRejectsConcurrentActiveTarget(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-race.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	base := K8sRolloutAction{ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		ResourceUID: "uid-1", RequestedBy: "user", Reason: "refresh", Status: "monitoring"}
	base.ID = "r1"
	if err := db.InsertK8sRolloutAction(ctx, base); err != nil {
		t.Fatal(err)
	}
	base.ID = "r2"
	if err := db.InsertK8sRolloutAction(ctx, base); err == nil {
		t.Fatal("expected active rollout uniqueness violation")
	}
}

func TestK8sRolloutRequestTransactionDoesNotLeaveOrphanAction(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-tx.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sRolloutAction(ctx, K8sRolloutAction{
		ID: "existing", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-1", Reason: "first", Status: "monitoring",
	}); err != nil {
		t.Fatal(err)
	}
	action := K8sActionRequest{
		ID: "action-orphan", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", Status: "approved", IdempotencyKey: "idem-orphan",
	}
	rollout := K8sRolloutAction{
		ID: "conflict", ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-1", Reason: "second", Status: "approved",
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, rollout, K8sRolloutEvent{ID: "event-orphan"}); err == nil {
		t.Fatal("expected active-target transaction conflict")
	}
	if _, err := db.GetK8sActionRequest(ctx, action.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("action insert escaped rolled-back transaction: %v", err)
	}
	if _, err := db.GetK8sRolloutAction(ctx, rollout.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollout insert escaped rolled-back transaction: %v", err)
	}
}

func TestK8sRolloutCASAndTerminalStatusAreMonotonic(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-cas.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sRolloutAction(ctx, K8sRolloutAction{
		ID: "r1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-1", Reason: "restart", Status: "monitoring",
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.GetK8sRolloutAction(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	success := snapshot
	success.Status, success.CompletedAt = "succeeded", time.Now().UTC().Format(time.RFC3339Nano)
	updated, err := db.UpdateK8sRolloutProgressCAS(ctx, success, snapshot.Status, snapshot.RollbackStatus, snapshot.UpdatedAt)
	if err != nil || !updated {
		t.Fatalf("first CAS updated=%v err=%v", updated, err)
	}
	staleFailure := snapshot
	staleFailure.Status, staleFailure.CompletedAt = "failed", time.Now().UTC().Format(time.RFC3339Nano)
	updated, err = db.UpdateK8sRolloutProgressCAS(ctx, staleFailure, snapshot.Status, snapshot.RollbackStatus, snapshot.UpdatedAt)
	if err != nil || updated {
		t.Fatalf("stale CAS updated=%v err=%v", updated, err)
	}
	terminal, err := db.GetK8sRolloutAction(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	terminal.Status = "timed_out"
	if err := db.UpdateK8sRolloutProgress(ctx, terminal); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal rewrite error=%v, want ErrInvalidTransition", err)
	}
	got, _ := db.GetK8sRolloutAction(ctx, "r1")
	if got.Status != "succeeded" {
		t.Fatalf("terminal status regressed to %q", got.Status)
	}
}

func TestK8sRolloutActiveDueQueueAndLease(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-due.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sActionRequest(ctx, K8sActionRequest{
		ID: "handoff-action", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "handoff",
		Action: "rollout_restart", Status: "approved",
	}); err != nil {
		t.Fatal(err)
	}
	for _, rollout := range []K8sRolloutAction{
		{ID: "approval", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "approval", ResourceUID: "uid-a", Reason: "wait", Status: "approval_required"},
		{ID: "handoff", ActionRequestID: "handoff-action", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "handoff", ResourceUID: "uid-h", Reason: "resume", Status: "approval_required"},
		{ID: "monitoring", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "monitoring", ResourceUID: "uid-m", Reason: "run", Status: "monitoring", StartedAt: "2026-07-28T00:00:00Z"},
		{ID: "recovery", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "recovery", ResourceUID: "uid-r", Reason: "recover", Status: "failed", AutoRollback: true},
	} {
		if err := db.InsertK8sRolloutAction(ctx, rollout); err != nil {
			t.Fatal(err)
		}
	}
	active, err := db.ListActiveK8sRolloutActions(ctx, 10)
	if err != nil || len(active) != 4 {
		t.Fatalf("active=%v err=%v", len(active), err)
	}
	due, err := db.ListK8sRolloutActionsDue(ctx, 10)
	if err != nil || len(due) != 3 {
		t.Fatalf("due=%v err=%v", len(due), err)
	}
	handoffDue := false
	for _, rollout := range due {
		if rollout.ID == "approval" {
			t.Fatal("approval-waiting rollout must not enter worker queue")
		}
		handoffDue = handoffDue || rollout.ID == "handoff"
	}
	if !handoffDue {
		t.Fatal("approved action/rollout handoff was not recoverable by the worker")
	}
	if err := db.StartK8sRolloutExecution(ctx, "handoff-action", "handoff", "system:worker"); err != nil {
		t.Fatal(err)
	}
	startedAction, _ := db.GetK8sActionRequest(ctx, "handoff-action")
	startedRollout, _ := db.GetK8sRolloutAction(ctx, "handoff")
	if startedAction.Status != "running" || startedRollout.Status != "running" || startedRollout.StartedAt == "" {
		t.Fatalf("execution handoff was not atomic: action=%+v rollout=%+v", startedAction, startedRollout)
	}
	if err := db.StartK8sRolloutExecution(ctx, "handoff-action", "handoff", "system:duplicate"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("duplicate execution claim error=%v, want ErrInvalidTransition", err)
	}

	now := time.Now().UTC()
	acquired, err := db.TryAcquireK8sRolloutReconcileLease(ctx, "monitoring", "replica-a", now, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("first lease acquired=%v err=%v", acquired, err)
	}
	acquired, err = db.TryAcquireK8sRolloutReconcileLease(ctx, "monitoring", "replica-b", now.Add(time.Second), time.Minute)
	if err != nil || acquired {
		t.Fatalf("second owner lease acquired=%v err=%v", acquired, err)
	}
	acquired, err = db.TryAcquireK8sRolloutReconcileLease(ctx, "monitoring", "replica-b", now.Add(2*time.Minute), time.Minute)
	if err != nil || !acquired {
		t.Fatalf("expired lease takeover acquired=%v err=%v", acquired, err)
	}

	// RFC3339Nano omits the fractional component at exact seconds, so raw TEXT
	// ordering incorrectly places "...00Z" after "...00.5Z".
	exactExpiry := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	acquired, err = db.TryAcquireK8sRolloutReconcileLease(ctx, "exact-second", "replica-a", exactExpiry.Add(-time.Minute), time.Minute)
	if err != nil || !acquired {
		t.Fatalf("exact-second lease acquired=%v err=%v", acquired, err)
	}
	acquired, err = db.TryAcquireK8sRolloutReconcileLease(ctx, "exact-second", "replica-b", exactExpiry.Add(500*time.Millisecond), time.Minute)
	if err != nil || !acquired {
		t.Fatalf("fractional time did not take over exact-second expiry: acquired=%v err=%v", acquired, err)
	}
}

func TestK8sRolloutPreviousTemplateIsNotSerialized(t *testing.T) {
	raw, err := json.Marshal(K8sRolloutAction{
		ID: "r1", PreviousTemplate: map[string]any{
			"spec": map[string]any{"containers": []any{map[string]any{
				"name": "api", "env": []any{map[string]any{"name": "PASSWORD", "value": "top-secret"}},
			}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "top-secret") || strings.Contains(string(raw), "previous_template") {
		t.Fatalf("private rollback template leaked in JSON: %s", raw)
	}
}

func TestK8sRolloutRecoveryLockMigrationNormalizesLegacyDuplicates(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-lock-upgrade.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Recreate the pre-v2 schema behavior: a terminal rollout recovering in
	// rollback could coexist with one newer primary rollout for the same target.
	if _, err := db.db.ExecContext(ctx, `DROP INDEX idx_k8s_rollout_one_active_target_v2`); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sRolloutAction(ctx, K8sRolloutAction{
		ID: "legacy-recovery", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
		Reason: "recover", Status: "failed", AutoRollback: true, RollbackStatus: "requested",
		RequestedAt: "2026-07-28T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sActionRequest(ctx, K8sActionRequest{
		ID: "legacy-action", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", Status: "approval_required",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sRolloutAction(ctx, K8sRolloutAction{
		ID: "legacy-new", ActionRequestID: "legacy-action", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
		Reason: "new", Status: "monitoring", StartedAt: "2026-07-28T00:01:00Z",
		RequestedAt: "2026-07-28T00:01:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("upgrade migration failed on legacy duplicate: %v", err)
	}
	recovery, _ := db.GetK8sRolloutAction(ctx, "legacy-recovery")
	superseded, _ := db.GetK8sRolloutAction(ctx, "legacy-new")
	if recovery.RollbackStatus != "requested" {
		t.Fatalf("recovery lock was not preserved: %+v", recovery)
	}
	if superseded.Status != "failed" || superseded.RollbackStatus != "failed" {
		t.Fatalf("conflicting rollout was not safely terminalized: %+v", superseded)
	}
	linkedAction, err := db.GetK8sActionRequest(ctx, "legacy-action")
	if err != nil {
		t.Fatal(err)
	}
	if linkedAction.Status != "failed" || !strings.Contains(linkedAction.Result, k8sRolloutTargetLockMigrationReason) {
		t.Fatalf("superseded rollout action remained executable: %+v", linkedAction)
	}
	if err := db.InsertK8sRolloutAction(ctx, K8sRolloutAction{
		ID: "still-blocked", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
		Reason: "blocked", Status: "monitoring",
	}); err == nil {
		t.Fatal("recovery lock did not block a new active rollout after migration")
	}
}

func TestK8sRolloutTargetLockMigrationIsAtomicAgainstConcurrentWriter(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "rollout-lock-atomic.db")
	migrator, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrator.Close() })
	if err := migrator.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	if _, err := migrator.db.ExecContext(ctx, `DROP INDEX idx_k8s_rollout_one_active_target_v2`); err != nil {
		t.Fatal(err)
	}
	if err := migrator.InsertK8sRolloutAction(ctx, K8sRolloutAction{
		ID: "retained-recovery", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
		Reason: "recover", Status: "failed", AutoRollback: true, RollbackStatus: "requested",
	}); err != nil {
		t.Fatal(err)
	}

	writerDone := make(chan error, 1)
	completedBeforeIndex := false
	var earlyWriterErr error
	err = migrator.migrateK8sRolloutTargetLockAttempt(ctx, func() {
		go func() {
			writerDone <- writer.InsertK8sRolloutAction(ctx, K8sRolloutAction{
				ID: "concurrent-rollout", ClusterID: "c1", ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
				Reason: "concurrent", Status: "monitoring",
			})
		}()
		select {
		case earlyWriterErr = <-writerDone:
			completedBeforeIndex = true
		case <-time.After(100 * time.Millisecond):
		}
	})
	if err != nil {
		t.Fatalf("atomic migration failed: %v", err)
	}
	if completedBeforeIndex {
		t.Fatalf("concurrent writer crossed the normalize/index boundary: %v", earlyWriterErr)
	}

	select {
	case writerErr := <-writerDone:
		if writerErr == nil {
			t.Fatal("concurrent writer committed a conflicting rollout after index creation")
		}
		if !strings.Contains(strings.ToLower(writerErr.Error()), "unique") {
			t.Fatalf("concurrent writer failed for an unexpected reason: %v", writerErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent writer did not resume after migration commit")
	}

	active, err := migrator.ListActiveK8sRolloutActions(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != "retained-recovery" {
		t.Fatalf("migration left conflicting active target locks: %+v", active)
	}
}
