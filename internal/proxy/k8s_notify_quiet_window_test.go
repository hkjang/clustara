package proxy

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"clustara/internal/store"
)

// setQuietWindow puts the scan inside its quiet window on the server's local clock, which is the
// clock notifyLocation("") keeps for an unconfigured timezone. The flag is read straight from the
// store on every scan, so writing it is enough — no cache to invalidate.
func setQuietWindow(t *testing.T, db *store.SQLStore, window string) {
	t.Helper()
	if err := db.SetFlag(context.Background(), store.RuntimeFlag{
		Key: "k8s_quiet_hours", Value: window, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

// The quiet-hours branch returned before the window map was ever built, so every diagnostic the
// fan-out loop had already paid for — clusters_error, events_error, revisions_error, truncated and
// the per-cluster truncation list — was computed and thrown away. The fleet-wide cron scan the admin
// guide recommends runs mostly at night, which is exactly when an operator's quiet window is open:
// during those hours a scan whose cluster registry could not be read answered byte for byte like a
// healthy installation's.
//
// Both halves run the production wiring over the same workload; the only difference is whether the
// registry can be listed at all.
func TestNotifyScanQuietHoursStillReportsAFailedClusterListing(t *testing.T) {
	ctx := context.Background()
	window := quietWindowAround(time.Now().Hour())

	// Path A: nothing registered, every lookup healthy. The documented fallback, suppressed.
	healthyDB, _, healthyProxy := newNotifyScanServerAt(t)
	setQuietWindow(t, healthyDB, window)
	if err := healthyDB.UpsertK8sInventory(ctx, privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	healthy := notifyScan(t, healthyProxy.URL, "")

	// Path B: the registry cannot be listed. A second connection to the same file removes the table
	// notifyScanTargets reads; the inventory is untouched, so this is the partial failure the quiet
	// branch used to hide completely.
	brokenDB, dsn, brokenProxy := newNotifyScanServerAt(t)
	setQuietWindow(t, brokenDB, window)
	if err := brokenDB.UpsertK8sInventory(ctx, privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `DROP TABLE k8s_clusters`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	raw.Close()
	broken := notifyScan(t, brokenProxy.URL, "")

	// Both must still be suppressed: this change reports what the scan already learned, it does not
	// change what quiet hours mean.
	for name, out := range map[string]map[string]any{"healthy": healthy, "broken": broken} {
		if out["suppressed"] != "quiet_hours" {
			t.Fatalf("the %s scan is inside quiet window %q and must stay suppressed: %v", name, window, out)
		}
		if out["sent"] != float64(0) {
			t.Fatalf("a suppressed %s scan must send nothing: %v", name, out)
		}
		if out["quiet_hours"] != window {
			t.Fatalf("the %s scan must keep reporting the window it judged: %v", name, out)
		}
	}

	// The point of the change: a quiet-hours scan that could not enumerate the fleet must not answer
	// like one that had no fleet to enumerate.
	if fmt.Sprint(healthy) == fmt.Sprint(broken) {
		t.Fatalf("during quiet hours a failed cluster listing answers identically to a healthy scan: %v", broken)
	}
	if msg, _ := broken["clusters_error"].(string); msg == "" {
		t.Fatalf("a quiet-hours scan must report the failed cluster listing: %v", broken)
	}
	// The operator-facing wording must be the one the non-quiet path uses, or the same fault reads as
	// two different ones depending on the hour it was noticed.
	if broken["clusters_notice"] != notifyClustersNotice {
		t.Fatalf("the quiet path must reuse the non-quiet cluster notice: %v", broken["clusters_notice"])
	}
}

// The counterpart contract: a scan whose lookups all succeeded must not grow error or notice keys
// just because it ran during quiet hours. A healthy installation's response stays quiet in both
// senses.
func TestNotifyScanQuietHoursLeavesAHealthyScanUnannotated(t *testing.T) {
	db, _, proxy := newNotifyScanServerAt(t)
	setQuietWindow(t, db, quietWindowAround(time.Now().Hour()))
	if err := db.UpsertK8sInventory(context.Background(), privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}

	out := notifyScan(t, proxy.URL, "")
	if out["suppressed"] != "quiet_hours" {
		t.Fatalf("the scan must be suppressed: %v", out)
	}
	for _, key := range []string{"clusters_error", "events_error", "revisions_error", "clusters_notice", "window_notice", "truncation_notice"} {
		if _, ok := out[key]; ok {
			t.Fatalf("a healthy quiet-hours scan must not carry %q: %v", key, out)
		}
	}
	if out["truncated"] != false {
		t.Fatalf("nothing was dropped, so the quiet response must say so plainly: %v", out)
	}
}
