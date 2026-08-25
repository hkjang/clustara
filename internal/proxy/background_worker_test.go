package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBackgroundWorkerBacksOffExponentiallyAndResets(t *testing.T) {
	worker := newBackgroundWorker("test", 2*time.Second, 20*time.Second)

	if got := worker.nextDelay(); got != 2*time.Second {
		t.Fatalf("healthy worker delay = %s, want 2s", got)
	}
	for _, want := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 20 * time.Second, 20 * time.Second} {
		worker.consecutive.Add(1)
		if got := worker.nextDelay(); got != want {
			t.Fatalf("after %d consecutive failures delay = %s, want %s", worker.consecutive.Load(), got, want)
		}
	}
	worker.consecutive.Store(0)
	if got := worker.nextDelay(); got != 2*time.Second {
		t.Fatalf("delay after recovery = %s, want the base interval 2s", got)
	}
}

func TestBackgroundWorkerCapsBackoffAtTheInternalWhenNoBackoffConfigured(t *testing.T) {
	worker := newBackgroundWorker("test", 5*time.Second, 0)
	worker.consecutive.Store(10)
	if got := worker.nextDelay(); got != 5*time.Second {
		t.Fatalf("delay = %s, want the interval 5s when max backoff is unset", got)
	}
}

func TestBackgroundWorkerContainsPanicAsAFailedTick(t *testing.T) {
	worker := newBackgroundWorker("panicky", time.Second, time.Second)
	worker.runTick(context.Background(), func(context.Context, time.Time) (int, error) {
		panic("boom")
	})

	status := worker.status()
	if status.Failures != 1 || status.ConsecutiveFailures != 1 {
		t.Fatalf("failures=%d consecutive=%d, want 1/1", status.Failures, status.ConsecutiveFailures)
	}
	if !strings.Contains(status.LastError, "panicked") || !strings.Contains(status.LastError, "boom") {
		t.Fatalf("last_error = %q, want it to name the panic", status.LastError)
	}
	if status.LastSuccess != "" {
		t.Fatalf("last_success = %q, want empty after a panicking tick", status.LastSuccess)
	}
}

func TestBackgroundWorkerRecordsThroughputAndClearsLastError(t *testing.T) {
	worker := newBackgroundWorker("counting", time.Second, time.Second)
	worker.runTick(context.Background(), func(context.Context, time.Time) (int, error) {
		return 0, errors.New("db down")
	})
	worker.runTick(context.Background(), func(context.Context, time.Time) (int, error) {
		return 3, nil
	})

	status := worker.status()
	if status.Ticks != 2 {
		t.Fatalf("ticks = %d, want 2", status.Ticks)
	}
	if status.Processed != 3 {
		t.Fatalf("processed = %d, want 3", status.Processed)
	}
	if status.Failures != 1 {
		t.Fatalf("failures = %d, want 1", status.Failures)
	}
	if status.ConsecutiveFailures != 0 {
		t.Fatalf("consecutive_failures = %d, want 0 after a success", status.ConsecutiveFailures)
	}
	if status.LastError != "" {
		t.Fatalf("last_error = %q, want it cleared after a success", status.LastError)
	}
	if status.LastSuccess == "" {
		t.Fatal("want a last_success timestamp after a successful tick")
	}
}

// A tick that fails only because the process is shutting down must not trip the
// backoff, or every restart would look like a broken worker.
func TestBackgroundWorkerIgnoresFailuresCausedByShutdown(t *testing.T) {
	worker := newBackgroundWorker("shutdown", time.Second, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	worker.runTick(ctx, func(context.Context, time.Time) (int, error) {
		cancel()
		return 0, context.Canceled
	})

	status := worker.status()
	if status.Failures != 0 || status.ConsecutiveFailures != 0 {
		t.Fatalf("failures=%d consecutive=%d, want 0/0 for a shutdown-cancelled tick", status.Failures, status.ConsecutiveFailures)
	}
}

func TestBackgroundWorkerStopWaitsForTheInFlightTick(t *testing.T) {
	worker := newBackgroundWorker("slow", 10*time.Millisecond, 10*time.Millisecond)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker.start(ctx, func(context.Context, time.Time) (int, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return 1, nil
	})

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never started its first tick")
	}

	cancel()
	if worker.wait(50 * time.Millisecond) {
		t.Fatal("wait reported a clean stop while a tick was still running")
	}
	close(release)
	if !worker.wait(2 * time.Second) {
		t.Fatal("worker did not stop after the in-flight tick finished")
	}
	if worker.status().Running {
		t.Fatal("status still reports running after the loop returned")
	}
}

// wait must not block when the worker was never started, so shutdown code can
// call Stop unconditionally on a disabled worker.
func TestBackgroundWorkerWaitReturnsWhenNeverStarted(t *testing.T) {
	worker := newBackgroundWorker("idle", time.Second, time.Second)
	if !worker.wait(0) {
		t.Fatal("wait on an unstarted worker should return immediately")
	}
}

func TestBackgroundWorkerStartIsIdempotent(t *testing.T) {
	worker := newBackgroundWorker("once", time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ticks := make(chan struct{}, 4)
	tick := func(context.Context, time.Time) (int, error) {
		ticks <- struct{}{}
		return 0, nil
	}
	worker.start(ctx, tick)
	worker.start(ctx, tick)

	select {
	case <-ticks:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never ran")
	}
	select {
	case <-ticks:
		t.Fatal("a second loop started; the interval is an hour so only one tick is possible")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDurableWorkerStatusEscalatesByHealth(t *testing.T) {
	tests := []struct {
		name    string
		status  backgroundWorkerStatus
		enabled bool
		want    string
	}{
		{"disabled", backgroundWorkerStatus{Name: "w"}, false, "idle"},
		{"enabled but stopped", backgroundWorkerStatus{Name: "w"}, true, "critical"},
		{"running, no success yet", backgroundWorkerStatus{Name: "w", Running: true}, true, "warn"},
		{"one failed tick", backgroundWorkerStatus{Name: "w", Running: true, LastSuccess: "t", LastError: "boom", ConsecutiveFailures: 1}, true, "warn"},
		{"backing off", backgroundWorkerStatus{Name: "w", Running: true, LastSuccess: "t", LastError: "boom", ConsecutiveFailures: 3}, true, "critical"},
		{"healthy", backgroundWorkerStatus{Name: "w", Running: true, LastSuccess: "t"}, true, "ok"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := durableWorkerStatus(tc.status, tc.enabled, "detail").Status; got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBackgroundWorkerPrometheusRendersLabelledSeries(t *testing.T) {
	body := backgroundWorkerPrometheus([]backgroundWorkerStatus{
		{Name: "k8s_rollout_reconciler", Running: true, Ticks: 7, Failures: 2, Processed: 5, ConsecutiveFailures: 1},
		{Name: "k8s_terminal_session_reaper"},
	})
	for _, want := range []string{
		`clustara_worker_running{worker="k8s_rollout_reconciler"} 1`,
		`clustara_worker_running{worker="k8s_terminal_session_reaper"} 0`,
		`clustara_worker_ticks_total{worker="k8s_rollout_reconciler"} 7`,
		`clustara_worker_failures_total{worker="k8s_rollout_reconciler"} 2`,
		`clustara_worker_processed_total{worker="k8s_rollout_reconciler"} 5`,
		`clustara_worker_consecutive_failures{worker="k8s_rollout_reconciler"} 1`,
		"# TYPE clustara_worker_last_success_seconds gauge",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q\n%s", want, body)
		}
	}
}
