package proxy

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"clustara/internal/store"
)

func newLifecycleTestServer(t *testing.T) *Server {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// The schedulers NewServer starts must stop before the store closes; otherwise
// they keep issuing queries against a closed database for the process lifetime.
func TestServerShutdownStopsSchedulers(t *testing.T) {
	server := newLifecycleTestServer(t)

	stopped := make(chan struct{})
	server.startBackground("probe", time.Minute, func(ctx context.Context, _ *backgroundWorker) {
		<-ctx.Done()
		close(stopped)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Shutdown returned before the scheduler observed cancellation")
	}
}

func TestServerShutdownIsIdempotent(t *testing.T) {
	server := newLifecycleTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		if err := server.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown() call %d error = %v", i+1, err)
		}
	}
}

// A scheduler stuck in a tick must not block shutdown forever: the caller's
// deadline wins and the failure is reported rather than swallowed.
func TestServerShutdownReportsSchedulersThatDoNotStop(t *testing.T) {
	server := newLifecycleTestServer(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	server.startBackground("stuck", time.Minute, func(context.Context, *backgroundWorker) { <-release })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := server.Shutdown(ctx)
	if err == nil {
		t.Fatal("Shutdown should report schedulers that outlived the deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want a deadline-exceeded cause", err)
	}
}

// A panicking scheduler must not take the process down, and must still be
// accounted for so Shutdown does not hang waiting on a dead goroutine.
func TestStartBackgroundContainsPanics(t *testing.T) {
	server := newLifecycleTestServer(t)
	var ran atomic.Bool
	server.startBackground("panicky", time.Minute, func(context.Context, *backgroundWorker) {
		ran.Store(true)
		panic("scheduler exploded")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if !ran.Load() {
		t.Fatal("the panicking scheduler never ran")
	}
}

func TestWaitForSchedulerTickStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	cancel()
	if waitForSchedulerTick(ctx, ticker.C) {
		t.Fatal("a cancelled scheduler must not run another tick")
	}
}

// Tick contexts have to inherit the shutdown signal, or an in-flight tick keeps
// writing after Shutdown returns.
func TestSchedulerTickContextInheritsCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	tick, tickCancel := schedulerTickContext(parent, time.Hour)
	defer tickCancel()
	cancel()
	select {
	case <-tick.Done():
	case <-time.After(time.Second):
		t.Fatal("tick context did not observe the parent cancellation")
	}
}

// The ops page used to hardcode text2sql_report_scheduler as a running, healthy
// worker. It self-disables without an execute DB, so that claim was false
// exactly when an operator most needed to know.
func TestOpsWorkersReportsSchedulersFromMeasuredState(t *testing.T) {
	server := newLifecycleTestServer(t)
	byName := fetchWorkerStatuses(t, server)

	for _, name := range []string{
		"clickhouse_fact_loop", "k8s_report_scheduler", "k8s_collect_scheduler",
		"k8s_node_metric_scheduler", "k8s_cost_snapshot_scheduler", "service_reconcile_scheduler",
	} {
		ws, ok := byName[name]
		if !ok {
			t.Fatalf("%s is missing from /admin/ops/workers", name)
		}
		if !ws.Running {
			t.Fatalf("%s should be running on a live server, got %+v", name, ws)
		}
	}

	// Both of these self-disable under testConfig — Text2SQL has no execute DSN
	// and the settings-reload interval is zero. Reporting them as running, which
	// the page previously hardcoded for the Text2SQL scheduler, is exactly the
	// lie an operator cannot afford here.
	for _, name := range []string{"text2sql_report_scheduler", "runtime_reload_loop"} {
		ws, ok := byName[name]
		if !ok {
			t.Fatalf("%s is missing from /admin/ops/workers", name)
		}
		if ws.Running || ws.Status != "idle" {
			t.Fatalf("self-disabled %s = %+v, want a non-running idle worker", name, ws)
		}
	}
}

func TestSchedulerWorkerStatusEscalatesByHealth(t *testing.T) {
	tests := []struct {
		name   string
		status backgroundWorkerStatus
		want   string
	}{
		{"self-disabled", backgroundWorkerStatus{Name: "w"}, "idle"},
		{"exited after an error", backgroundWorkerStatus{Name: "w", LastError: "boom"}, "warn"},
		{"healthy", backgroundWorkerStatus{Name: "w", Running: true, LastSuccess: "t"}, "ok"},
		{"one failed tick", backgroundWorkerStatus{Name: "w", Running: true, LastError: "boom", ConsecutiveFailures: 1}, "warn"},
		{"repeatedly failing", backgroundWorkerStatus{Name: "w", Running: true, LastError: "boom", ConsecutiveFailures: 4}, "critical"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := schedulerWorkerStatus(tc.status).Status; got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

// Shutdown must clear the running flag on every scheduler it stops, so the ops
// page cannot keep reporting a stopped server's workers as alive.
func TestShutdownClearsSchedulerRunningState(t *testing.T) {
	server := newLifecycleTestServer(t)
	before := server.schedulerStatuses()
	if len(before) == 0 {
		t.Fatal("no schedulers were registered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	for _, st := range server.schedulerStatuses() {
		if st.Running {
			t.Fatalf("%s still reports running after Shutdown", st.Name)
		}
	}
}
