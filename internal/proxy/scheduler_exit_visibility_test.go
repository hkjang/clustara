package proxy

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Nothing restarts a scheduler. One that returns on its own is gone until the process is
// restarted — and the status board rendered that exactly like a scheduler the configuration
// had switched off: both were "idle", with the same detail text and an empty last error.
//
// Measured before the fix: a scheduler started and immediately returned, and one never
// enabled, produced byte-identical rows.
//
// durableWorkerStatus already calls the same condition critical. The two mechanisms
// disagreed about the same fact, and the scheduler side was the one under-reporting.
func TestDeadSchedulerIsNotReportedAsIdle(t *testing.T) {
	server := newLifecycleTestServer(t)
	server.startBackground("gave-up", time.Minute, func(context.Context, *backgroundWorker) {})
	server.registerBackground("switched-off", time.Minute, false, func(context.Context, *backgroundWorker) {})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	dead, off := waitForSchedulerRows(t, server, "gave-up", "switched-off")

	if dead.Status != "critical" {
		t.Fatalf("a scheduler that exited on its own reports %q; nothing will restart it, so it "+
			"must not read as an ordinary idle state (detail=%q)", dead.Status, dead.Detail)
	}
	if dead.LastError == "" {
		t.Fatal("a scheduler that exited left no error text; the board says something is wrong " +
			"but not what")
	}
	if off.Status != "idle" {
		t.Fatalf("a scheduler that was never enabled reports %q; being switched off is not a "+
			"failure", off.Status)
	}
	if dead.Detail == off.Detail {
		t.Fatalf("a dead scheduler and a disabled one render the same detail: %q", dead.Detail)
	}
}

// Shutdown cancels the base context and every scheduler returns. That is an ordinary stop,
// not an exit, and must not paint the whole board critical on the way out — the same
// distinction runTick already makes for a cancelled tick.
func TestShutdownIsNotRecordedAsASchedulerExit(t *testing.T) {
	server := newLifecycleTestServer(t)
	ran := make(chan struct{})
	server.startBackground("polite", time.Minute, func(ctx context.Context, _ *backgroundWorker) {
		close(ran)
		<-ctx.Done()
	})
	<-ran

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	for _, st := range server.schedulerStatuses() {
		if st.Name != "polite" {
			continue
		}
		if st.LastError != "" {
			t.Fatalf("stopping for shutdown was recorded as a failure: %q", st.LastError)
		}
	}
}

// A panicking scheduler keeps its own, more specific message rather than the generic exit
// one — the recover branch returns before the exit branch can overwrite it.
func TestPanickingSchedulerKeepsItsPanicMessage(t *testing.T) {
	server := newLifecycleTestServer(t)
	server.startBackground("boom", time.Minute, func(context.Context, *backgroundWorker) {
		panic("scheduler exploded")
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	row := waitForSchedulerRow(t, server, "boom")
	if row.Status != "critical" {
		t.Fatalf("a panicked scheduler reports %q", row.Status)
	}
	if got := row.LastError; got == "" || strings.Contains(got, "returned before shutdown") {
		t.Fatalf("the panic message was lost: %q", got)
	}
}

func waitForSchedulerRow(t *testing.T, server *Server, name string) workerStatus {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var row workerStatus
	for time.Now().Before(deadline) {
		row = workerStatus{}
		for _, st := range server.schedulerStatuses() {
			if st.Name == name {
				row = schedulerWorkerStatus(st)
			}
		}
		if row.Name != "" && !row.Running {
			return row
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("scheduler %q did not settle: %+v", name, row)
	return row
}

func waitForSchedulerRows(t *testing.T, server *Server, first, second string) (workerStatus, workerStatus) {
	t.Helper()
	return waitForSchedulerRow(t, server, first), waitForSchedulerRow(t, server, second)
}

// A scheduler that turns itself off for a stated reason is inert on purpose, not dead. It
// must stay idle and say why — otherwise the exit detection above reports a perfectly
// healthy configuration (no Text2SQL execute DB, no reload interval) as a failure.
func TestSelfDisabledSchedulerStaysIdleWithAReason(t *testing.T) {
	server := newLifecycleTestServer(t)
	server.startBackground("inert", time.Minute, func(_ context.Context, observed *backgroundWorker) {
		observed.disable("테스트 사유")
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	row := waitForSchedulerRow(t, server, "inert")
	if row.Status != "idle" {
		t.Fatalf("a scheduler that disabled itself reports %q; being deliberately inert is not "+
			"a failure (detail=%q)", row.Status, row.Detail)
	}
	if !strings.Contains(row.Detail, "테스트 사유") {
		t.Fatalf("the stated reason is not shown: %q", row.Detail)
	}
	if row.LastError != "" {
		t.Fatalf("a deliberate self-disable was recorded as an error: %q", row.LastError)
	}
}
