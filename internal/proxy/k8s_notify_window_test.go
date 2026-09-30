package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"clustara/internal/config"
	"clustara/internal/store"
)

// warningEvent builds a real store.K8sEvent the way the collector writes them, so the rows the scan
// reads back go through the same query and clamp the production path uses.
func warningEvent(clusterID, name string, seen time.Time) store.K8sEvent {
	ts := seen.UTC().Format(time.RFC3339Nano)
	return store.K8sEvent{
		ID: "ev_" + clusterID + "_" + name, ClusterID: clusterID, Namespace: "edge",
		InvolvedKind: "Pod", InvolvedName: name, Reason: "BackOff", Type: "Warning",
		Message: "back-off restarting failed container", Count: 3, Source: "kubelet",
		FirstSeen: ts, LastSeen: ts, CreatedAt: ts,
	}
}

// insertEvents writes n warning events with descending last_seen so the ORDER BY last_seen DESC
// window the scan reads is deterministic.
func insertEvents(t *testing.T, db *store.SQLStore, clusterID string, n int) {
	t.Helper()
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		if err := db.InsertK8sEvent(context.Background(), warningEvent(clusterID, fmt.Sprintf("pod-%d", i), base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
}

// The scan correlates findings against an event window and a revision window. Both lookups threw
// their error away and neither reported how much of the window came back, so a database failure and
// a window too small to hold the cluster's events both produced the response of a healthy cluster:
// `sent: 0`, `truncated: false`, nothing else. Nobody reads this endpoint's output, so the only
// symptom was an alert that never fired.
func TestNotifyScanReportsASaturatedEventWindow(t *testing.T) {
	db, _, proxy, _ := newNotifyScanServer(t)

	originalEvents := notifyScanEventBudget
	notifyScanEventBudget = 2
	t.Cleanup(func() { notifyScanEventBudget = originalEvents })

	insertEvents(t, db, "c1", 5)

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["events_truncated"] != true {
		t.Fatalf("5 events read through a window of 2 must report a saturated event window: %v", out)
	}
	if out["events"] != float64(2) {
		t.Fatalf("the scan must report how many events it actually correlated against: %v", out)
	}
	if notice, _ := out["window_notice"].(string); notice == "" {
		t.Fatalf("a saturated correlation window needs the same kind of notice inventory truncation gets: %v", out)
	}
	// The point of the change: this response must not be mistakable for a clean cluster's.
	clean := notifyScan(t, proxy.URL, "?cluster_id=c-empty")
	if fmt.Sprint(out) == fmt.Sprint(clean) {
		t.Fatalf("a scan whose event window overflowed answers identically to a clean cluster: %v", out)
	}
}

// Revisions feed EnrichWithConfigChanges, which is what attributes a failure to a recent config
// change. A saturated revision window silently drops the oldest changes out of that correlation.
func TestNotifyScanReportsASaturatedRevisionWindow(t *testing.T) {
	db, _, proxy, _ := newNotifyScanServer(t)
	ctx := context.Background()

	originalRevisions := notifyScanRevisionBudget
	notifyScanRevisionBudget = 2
	t.Cleanup(func() { notifyScanRevisionBudget = originalRevisions })

	for i := 0; i < 4; i++ {
		if _, err := db.RecordK8sRevision(ctx, store.K8sResourceRevision{
			ClusterID: "c1", Kind: "Deployment", Namespace: "edge", Name: fmt.Sprintf("app-%d", i),
			SpecHash: fmt.Sprintf("hash-%d", i), Spec: map[string]any{"replicas": i},
			Replica: i, ImageSet: "app:1", ChangeKind: "updated",
			ObservedAt: time.Date(2026, 9, 20, 0, i, 0, 0, time.UTC).Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatal(err)
		}
	}

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["revisions_truncated"] != true {
		t.Fatalf("4 revisions read through a window of 2 must report a saturated revision window: %v", out)
	}
	if out["revisions"] != float64(2) {
		t.Fatalf("the scan must report how many revisions it actually correlated against: %v", out)
	}
	if notice, _ := out["window_notice"].(string); notice == "" {
		t.Fatalf("a saturated revision window needs a notice: %v", out)
	}
}

// Regression guard for the quiet case: a scan whose windows both fit must report them as complete
// and must not grow a notice, or the new flags carry no information. The pre-existing inventory
// `truncated` key keeps its own meaning.
func TestNotifyScanReportsCompleteWindowsWhenTheyFit(t *testing.T) {
	db, _, proxy, _ := newNotifyScanServer(t)

	insertEvents(t, db, "c1", 2)

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["events_truncated"] != false || out["revisions_truncated"] != false {
		t.Fatalf("both windows fit, so neither may report saturation: %v", out)
	}
	if out["events"] != float64(2) {
		t.Fatalf("the scan must report the events it read even when the window fits: %v", out)
	}
	if out["revisions"] != float64(0) {
		t.Fatalf("a cluster with no recorded revisions must report zero, not omit the count: %v", out)
	}
	if _, ok := out["window_notice"]; ok {
		t.Fatalf("a complete scan must not carry a window notice: %v", out)
	}
	if _, ok := out["events_error"]; ok {
		t.Fatalf("a successful lookup must not report an error: %v", out)
	}
	if out["truncated"] != false {
		t.Fatalf("the inventory truncation flag must keep its own meaning: %v", out)
	}
}

// The event lookup's error was assigned to `_`. AnalyzeRCA then ran against an empty event slice and
// the scan answered 200 with a clean cluster's body, so a broken events table looked like a healthy
// fleet. Reproduced against the real store by removing the table underneath it — the inventory the
// security analysis reads is untouched, which is exactly the partial failure the discarded error hid.
func TestNotifyScanReportsAFailedEventLookup(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "gateway.db")

	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hook.Close)

	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 32, filepath.Join(dir, "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)
	for k, v := range map[string]string{"mattermost_enabled": "true", "mattermost_webhook_url": hook.URL} {
		if err := db.SetFlag(ctx, store.RuntimeFlag{Key: k, Value: v, UpdatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	server.invalidateMattermostCache()

	if err := db.UpsertK8sInventory(ctx, privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}

	// A second connection to the same file removes the table the event lookup reads.
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `DROP TABLE k8s_events`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	raw.Close()

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if msg, _ := out["events_error"].(string); msg == "" {
		t.Fatalf("a failed event lookup must be reported, not answered as a clean correlation window: %v", out)
	}
	if notice, _ := out["window_notice"].(string); notice == "" {
		t.Fatalf("a failed lookup needs the operator-facing notice: %v", out)
	}
	// The inventory-driven security analysis is still valid, so the scan keeps working.
	if out["sent"] != float64(1) {
		t.Fatalf("the security half of the scan must still notify when only the event window failed: %v", out)
	}

	// The audit record must say the same thing the response does.
	entries, err := db.ListAdminAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{}
	for _, e := range entries {
		if e.Action != "k8s.notify.scan" {
			continue
		}
		if err := json.Unmarshal([]byte(e.AfterValue), &meta); err != nil {
			t.Fatalf("audit metadata %q: %v", e.AfterValue, err)
		}
		break
	}
	if len(meta) == 0 {
		t.Fatalf("the scan recorded no k8s.notify.scan audit entry: %v", entries)
	}
	if msg, _ := meta["events_error"].(string); msg == "" {
		t.Fatalf("the audit entry must carry the same failure the response reports: %v", meta)
	}
}
