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

// newNotifyScanServerAt wires the notify scan exactly as newNotifyScanServer does, but over a
// database file whose path the caller knows. Removing a table underneath a running store needs a
// second connection to that same file, and openTestStore does not expose its DSN.
func newNotifyScanServerAt(t *testing.T) (*store.SQLStore, string, *httptest.Server) {
	t.Helper()
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
	return db, dsn, proxy
}

// notifyScanTargets answers a failed cluster listing with []string{""} — byte for byte the target
// list a fleet-wide scan uses on an installation that has registered no clusters. The error was
// dropped on the floor, so the fleet-wide cron scan the admin guide recommends could regress all the
// way back to the shared single window v0.9.295 removed — every cluster sharing one query budget, the
// quiet ones never evaluated — and still answer `clusters_scanned: 1` with no error key, identical to
// a healthy unregistered installation's response.
//
// Both halves run against the same production wiring and the same workload. The only difference is
// whether the cluster registry can be read at all.
func TestNotifyScanDistinguishesAClusterListFailureFromAnEmptyRegistry(t *testing.T) {
	ctx := context.Background()

	// Path A: nothing registered. The documented fallback, and a clean run.
	emptyDB, _, emptyProxy := newNotifyScanServerAt(t)
	if err := emptyDB.UpsertK8sInventory(ctx, privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	empty := notifyScan(t, emptyProxy.URL, "")

	// Path B: the registry cannot be listed. A second connection to the same file removes the table
	// notifyScanTargets reads; the inventory the security analysis needs is untouched, which is the
	// partial failure the discarded error hid.
	brokenDB, dsn, brokenProxy := newNotifyScanServerAt(t)
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

	// The point of the change: a scan that could not enumerate the fleet must not answer like one
	// that had no fleet to enumerate.
	if fmt.Sprint(empty) == fmt.Sprint(broken) {
		t.Fatalf("a failed cluster listing answers identically to an empty registry: %v", broken)
	}
	if msg, _ := broken["clusters_error"].(string); msg == "" {
		t.Fatalf("a failed cluster listing must be reported, not answered as an unregistered install: %v", broken)
	}
	if notice, _ := broken["clusters_notice"].(string); notice == "" {
		t.Fatalf("a fleet-wide scan degraded to one shared window needs the operator-facing notice: %v", broken)
	}

	// Reporting only: the scan keeps running on the same single shared window it always fell back to,
	// because failing the request outright would stop the cron scan from notifying at all.
	if broken["clusters_scanned"] != float64(1) {
		t.Fatalf("the degraded scan must still read the single shared window: %v", broken)
	}
	if broken["sent"] != float64(1) {
		t.Fatalf("the security half of the scan must still notify when only the cluster listing failed: %v", broken)
	}
	if broken["resources"] != float64(1) {
		t.Fatalf("the degraded scan must still read the workload rows: %v", broken)
	}

	// The audit entry must say the same thing the response does.
	entries, err := brokenDB.ListAdminAudit(ctx, 50)
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
	if msg, _ := meta["clusters_error"].(string); msg == "" {
		t.Fatalf("the audit entry must carry the same failure the response reports: %v", meta)
	}
}

// The counterpart contract, asserted on its own so a future change cannot buy the distinction above
// by annotating the healthy fallback too: an installation with no registered clusters is not
// degraded, and its response must not grow either new key. The event and revision windows stay
// clean, so no window notice either.
func TestNotifyScanLeavesTheEmptyRegistryFallbackUnannotated(t *testing.T) {
	db, _, proxy := newNotifyScanServerAt(t)
	if err := db.UpsertK8sInventory(context.Background(), privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}

	out := notifyScan(t, proxy.URL, "")
	if _, ok := out["clusters_error"]; ok {
		t.Fatalf("a readable but empty registry is not a lookup failure: %v", out)
	}
	if _, ok := out["clusters_notice"]; ok {
		t.Fatalf("the documented single-window fallback must not be reported as degraded: %v", out)
	}
	if out["clusters_scanned"] != float64(1) {
		t.Fatalf("an empty registry means one shared window, as before: %v", out)
	}
	if out["sent"] != float64(1) {
		t.Fatalf("the privileged pod must still page: %v", out)
	}
}
