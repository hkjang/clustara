package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"clustara/internal/config"
)

// Retention is what bounds the store's growth. A run whose purges all failed
// used to stamp lastRun anyway, and the operations page reported that stamp as
// the last success — so a worker failing for weeks looked healthy.
func TestRetentionRunSeparatesLastRunFromLastSuccess(t *testing.T) {
	db := openStoreForTest(t)
	worker := NewRetentionWorker(db, config.RetentionConfig{Interval: time.Hour, RequestDays: 1})

	if worker.LastRun() != "" || worker.LastSuccess() != "" || worker.LastError() != "" {
		t.Fatal("a fresh worker must report no run, no success and no error")
	}

	worker.RunOnce(context.Background())
	if worker.LastRun() == "" {
		t.Fatal("a completed run must stamp LastRun")
	}
	if worker.LastSuccess() == "" {
		t.Fatal("a clean run must stamp LastSuccess")
	}
	if worker.LastError() != "" || worker.ErrorCount() != 0 {
		t.Fatalf("clean run reported error %q count=%d", worker.LastError(), worker.ErrorCount())
	}

	// Closing the store makes every purge fail. The run still completes, so
	// LastRun advances — but LastSuccess must not.
	lastSuccess := worker.LastSuccess()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	worker.RunOnce(context.Background())

	if worker.LastSuccess() != lastSuccess {
		t.Fatalf("LastSuccess advanced past a failing run: %q", worker.LastSuccess())
	}
	if worker.LastError() == "" {
		t.Fatal("a failing run must record what failed")
	}
	if worker.ErrorCount() == 0 {
		t.Fatal("a failing run must increment the error count")
	}
	if !strings.Contains(worker.LastError(), "purge") && !strings.Contains(worker.LastError(), "rollup") {
		t.Fatalf("LastError = %q, want it to name the failing step", worker.LastError())
	}
}

// A clean run after a failing one has to clear the error, or the ops page would
// warn forever about a problem that already resolved.
func TestRetentionClearsLastErrorAfterRecovery(t *testing.T) {
	db := openStoreForTest(t)
	worker := NewRetentionWorker(db, config.RetentionConfig{Interval: time.Hour, RequestDays: 1})

	worker.lastError.Store("purge request_logs: disk full")
	worker.errorCount.Add(1)

	worker.RunOnce(context.Background())
	if worker.LastError() != "" {
		t.Fatalf("LastError = %q, want it cleared by a clean run", worker.LastError())
	}
	if worker.LastSuccess() == "" {
		t.Fatal("the recovering run must stamp LastSuccess")
	}
	// The cumulative count is history and must survive recovery.
	if worker.ErrorCount() != 1 {
		t.Fatalf("ErrorCount = %d, want the cumulative 1 to be retained", worker.ErrorCount())
	}
}
