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
	server.startBackground("probe", func(ctx context.Context) {
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
	server.startBackground("stuck", func(context.Context) { <-release })

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
	server.startBackground("panicky", func(context.Context) {
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
