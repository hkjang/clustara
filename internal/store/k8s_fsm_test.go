package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func openK8sFSMTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    filepath.Join(t.TempDir(), "k8s-fsm.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestK8sActionRequestFSMAndIdempotencyMetadata(t *testing.T) {
	ctx := context.Background()
	db := openK8sFSMTestStore(t)
	defer db.Close()

	req := K8sActionRequest{
		ID: "act_1", ClusterID: "k8scl_1", Namespace: "default", ResourceKind: "Pod", ResourceName: "api-1",
		Action: "delete_pod", Status: "approval_required", RequestedBy: "operator",
		IdempotencyKey: "idem_1", TargetUID: "pod-uid", TargetResourceVersion: "rv-10", CommandHash: "hash-1",
	}
	if err := db.InsertK8sActionRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetK8sActionRequestByIdempotencyKey(ctx, "idem_1")
	if err != nil || got.ID != req.ID || got.TargetUID != "pod-uid" || got.CommandHash != "hash-1" {
		t.Fatalf("idempotency lookup = %+v err=%v", got, err)
	}
	if err := db.UpdateK8sActionStatus(ctx, req.ID, "executed", "admin", "too early"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("executed before approval should be invalid, got %v", err)
	}
	if err := db.UpdateK8sActionStatus(ctx, req.ID, "approved", "admin", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := db.UpdateK8sActionStatus(ctx, req.ID, "approved", "admin", "again"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("double approve should be invalid, got %v", err)
	}
	if err := db.UpdateK8sActionStatus(ctx, req.ID, "running", "admin", "run"); err != nil {
		t.Fatalf("running: %v", err)
	}
	if err := db.UpdateK8sActionStatus(ctx, req.ID, "running", "admin", "again"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("double running should be invalid, got %v", err)
	}
	if err := db.UpdateK8sActionStatus(ctx, req.ID, "executed", "admin", "done"); err != nil {
		t.Fatalf("executed: %v", err)
	}
	if err := db.UpdateK8sActionStatus(ctx, req.ID, "failed", "admin", "late"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal action should not be rewritten, got %v", err)
	}
}

func TestK8sPodExecSessionFSM(t *testing.T) {
	ctx := context.Background()
	db := openK8sFSMTestStore(t)
	defer db.Close()

	sess := K8sPodExecSession{
		ID: "exec_1", ClusterID: "k8scl_1", Namespace: "default", Pod: "api-1",
		Container: "app", Command: "ls /app", Role: "viewer", RequestedBy: "operator",
		Status: "pending_approval", RequireApproval: true, AuditEnabled: true,
	}
	if err := db.CreateK8sPodExecSession(ctx, &sess); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateK8sPodExecSessionExecution(ctx, sess.ID, "completed", "admin", "", "", 0); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("execution before running should be invalid, got %v", err)
	}
	ready, err := db.UpdateK8sPodExecSessionDecision(ctx, sess.ID, "ready", "admin", "ok")
	if err != nil || ready.Status != "ready" {
		t.Fatalf("approve exec = %+v err=%v", ready, err)
	}
	if _, err := db.UpdateK8sPodExecSessionDecision(ctx, sess.ID, "rejected", "admin", "late"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("decision after ready should be invalid, got %v", err)
	}
	running, err := db.MarkK8sPodExecSessionRunning(ctx, sess.ID, "admin")
	if err != nil || running.Status != "running" {
		t.Fatalf("mark running = %+v err=%v", running, err)
	}
	if _, err := db.MarkK8sPodExecSessionRunning(ctx, sess.ID, "admin"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("double running should be invalid, got %v", err)
	}
	done, err := db.UpdateK8sPodExecSessionExecution(ctx, sess.ID, "completed", "admin", "ok", "", 0)
	if err != nil || done.Status != "completed" {
		t.Fatalf("complete exec = %+v err=%v", done, err)
	}
	if _, err := db.UpdateK8sPodExecSessionExecution(ctx, sess.ID, "failed", "admin", "", "late", 1); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal exec should not be rewritten, got %v", err)
	}
}
