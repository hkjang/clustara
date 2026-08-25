package proxy

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"

	_ "modernc.org/sqlite"
)

func reaperHeartbeatFixture(t *testing.T) (*Server, *store.SQLStore, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "reaper-heartbeat.db")
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return &Server{db: db}, db, raw
}

func createReaperSession(t *testing.T, db *store.SQLStore, id string) {
	t.Helper()
	sess := store.K8sPodExecSession{
		ID: id, ClusterID: "c1", Namespace: "prod", Pod: "api-1", Container: "app",
		Command: "sh", Role: "super_admin", RequestedBy: "op", Status: "ready",
		AuditEnabled: true, MaxSessionMinutes: 1, PolicyResult: `{"access_mode":"terminal"}`,
	}
	if err := db.CreateK8sPodExecSession(context.Background(), &sess); err != nil {
		t.Fatal(err)
	}
}

// A session whose updated_at cannot be parsed can never become parseable on its
// own. Treating it as a retryable failure made the reaper fail on every tick,
// which pinned its exponential backoff at the maximum and left the row at the
// head of the recovery queue — so genuinely orphaned terminals waited out that
// backoff before being closed.
func TestReaperDoesNotPoisonItselfOnUnreadableHeartbeat(t *testing.T) {
	ctx := context.Background()
	server, db, raw := reaperHeartbeatFixture(t)
	createReaperSession(t, db, "sess-stale")
	createReaperSession(t, db, "sess-unreadable")

	stale := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := raw.ExecContext(ctx,
		`UPDATE k8s_pod_exec_sessions SET status='running', updated_at=? WHERE id='sess-stale'`, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx,
		`UPDATE k8s_pod_exec_sessions SET status='running', updated_at='' WHERE id='sess-unreadable'`); err != nil {
		t.Fatal(err)
	}

	reaper := server.NewK8sTerminalSessionReaper(K8sTerminalSessionReaperOptions{BatchSize: 100})
	reaped, err := reaper.reapBatch(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("an unreadable heartbeat must not fail the tick: %v", err)
	}
	if reaped != 2 {
		t.Fatalf("reaped = %d, want both the stale and the unreadable session", reaped)
	}

	remaining, err := db.ListK8sPodExecSessionsForRecovery(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("recovery queue still holds %d sessions; the reaper would spin on them", len(remaining))
	}

	closed, err := db.GetK8sPodExecSession(ctx, "sess-unreadable")
	if err != nil {
		t.Fatal(err)
	}
	if closed.Status != "failed" || closed.ExitCode != 124 {
		t.Fatalf("unreadable session = status %q exit %d, want a closed session", closed.Status, closed.ExitCode)
	}
	if closed.ErrorMessage == "" {
		t.Fatal("the closed session must say why it was closed")
	}

	// A second pass must stay clean rather than re-reporting the same rows.
	if reaped, err := reaper.reapBatch(ctx, time.Now().UTC()); err != nil || reaped != 0 {
		t.Fatalf("second pass reaped=%d err=%v, want a quiet tick", reaped, err)
	}
}

// Fencing is a compare-and-swap on the exact stored value, so an owner that is
// still alive and writes a real timestamp keeps its session.
func TestReaperFencingLosesToALiveOwner(t *testing.T) {
	ctx := context.Background()
	server, db, raw := reaperHeartbeatFixture(t)
	createReaperSession(t, db, "sess-live")
	if _, err := raw.ExecContext(ctx,
		`UPDATE k8s_pod_exec_sessions SET status='running', updated_at='' WHERE id='sess-live'`); err != nil {
		t.Fatal(err)
	}

	sessions, err := db.ListK8sPodExecSessionsForRecovery(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("fixture selected %d sessions, want 1", len(sessions))
	}

	// The owner heartbeats between the reaper's read and its write.
	fresh := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := raw.ExecContext(ctx,
		`UPDATE k8s_pod_exec_sessions SET updated_at=? WHERE id='sess-live'`, fresh); err != nil {
		t.Fatal(err)
	}

	expired, err := db.ExpireStaleK8sPodExecSession(ctx, sessions[0].ID, sessions[0].Status, sessions[0].UpdatedAt,
		"terminal session heartbeat is unreadable")
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		t.Fatal("the reaper closed a session that its owner had just refreshed")
	}
	live, err := db.GetK8sPodExecSession(ctx, "sess-live")
	if err != nil {
		t.Fatal(err)
	}
	if live.Status != "running" {
		t.Fatalf("live session status = %q, want it untouched", live.Status)
	}
	_ = server
}
