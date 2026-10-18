package proxy

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"clustara/internal/config"
	"clustara/internal/store"
)

// newCapacityServerAt is newPolicyStatusServer with the database path handed back, so a
// second connection can break one table while the rest of the store keeps working. That
// is the only way to make the metric lookup fail through the production wiring.
func newCapacityServerAt(t *testing.T) (*store.SQLStore, string, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "gateway.db")
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(dir, "capacity.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	t.Cleanup(srv.Close)
	return db, dsn, srv
}

// dropMetricSamples removes the table the metric lookup reads, from a connection the
// server does not own. The inventory tables are untouched, so this is a partial store
// failure and not a dead database.
func dropMetricSamples(t *testing.T, dsn string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(context.Background(), `DROP TABLE k8s_metrics_samples`); err != nil {
		t.Fatal(err)
	}
}

// seedCapacityCluster puts one Node and one Pod in the window — enough for node_packing,
// while allocation and projections stay empty until metric samples exist.
func seedCapacityCluster(t *testing.T, db *store.SQLStore, cluster string) {
	t.Helper()
	putCapacityInventory(t, db, cluster, "Node", "worker-1", "2026-01-02T00:00:00Z", nil, map[string]any{
		"allocatable": map[string]any{"cpu": "4"},
	})
	putCapacityInventory(t, db, cluster, "Pod", "trainer", "2026-01-01T00:00:00Z", map[string]any{
		"nodeName":   "worker-1",
		"containers": []any{map[string]any{"name": "trainer", "resources": map[string]any{"requests": map[string]any{"cpu": "1"}}}},
	}, nil)
}

// The capacity handler threw the metric lookup's error away. Allocation findings
// (SCALE-03/04) and node projections (SCALE-05) are computed from those samples alone, so
// a failing metric query answers with the same empty allocation and projections as a
// cluster whose collectors simply have not reported yet — and the UI turns that into
// "과소 할당 0 · 30일 내 소진 0", the reassurance an operator acts on.
//
// Both halves run the production wiring over the same inventory; the only difference is
// whether the metric samples can be read at all.
func TestCapacityScanDistinguishesAMetricsFailureFromNoSamples(t *testing.T) {
	healthyDB, _, healthySrv := newCapacityServerAt(t)
	seedCapacityCluster(t, healthyDB, "c1")
	healthy := getJSON(t, healthySrv.URL+"/admin/k8s/capacity?cluster_id=c1")

	brokenDB, dsn, brokenSrv := newCapacityServerAt(t)
	seedCapacityCluster(t, brokenDB, "c1")
	dropMetricSamples(t, dsn)
	broken := getJSON(t, brokenSrv.URL+"/admin/k8s/capacity?cluster_id=c1")

	healthyScan, _ := healthy["scan"].(map[string]any)
	brokenScan, _ := brokenScanOf(t, broken)
	if healthyScan == nil {
		t.Fatalf("the healthy capacity report carries no scan block: %v", healthy)
	}
	if healthyScan["status"] != "checked" {
		t.Errorf("status = %v with every lookup healthy: an empty metric feed is not a failed one: %v",
			healthyScan["status"], healthyScan)
	}
	if _, ok := healthyScan["metrics_error"]; ok {
		t.Errorf("a healthy scan must not claim a metric failure: %v", healthyScan)
	}

	if brokenScan["status"] != "partial" {
		t.Errorf("status = %v with the metric samples unreadable: allocation and projections were "+
			"computed over nothing and must not read as complete: %v", brokenScan["status"], brokenScan)
	}
	if reason, _ := brokenScan["reason"].(string); reason == "" {
		t.Errorf("a capacity scan that lost its metrics must explain itself to the operator: %v", brokenScan)
	}
	if _, ok := brokenScan["metrics_error"]; !ok {
		t.Errorf("the scan block must name the failed lookup, as the notify window names its own: %v", brokenScan)
	}

	// The inventory half of the report is unaffected and must still answer: this reports a
	// partial failure, it does not turn one into a dead endpoint.
	report, _ := broken["report"].(map[string]any)
	if report == nil {
		t.Fatalf("a metric failure must still answer with the inventory-derived report: %v", broken)
	}
	if packing, _ := report["node_packing"].([]any); len(packing) != 1 {
		t.Errorf("node_packing = %v, want the one node worker-1: the metric failure must not cost "+
			"the inventory-derived findings", report["node_packing"])
	}
}

// brokenScanOf fails loudly rather than letting a missing scan block pass as an empty map.
func brokenScanOf(t *testing.T, body map[string]any) (map[string]any, bool) {
	t.Helper()
	scan, ok := body["scan"].(map[string]any)
	if !ok {
		t.Fatalf("the capacity report carries no scan block: %v", body)
	}
	return scan, ok
}

// Truncation and a metric failure are separate losses, and a scan hit by both has to
// report both: the truncation reason alone would send the operator to look at the budget
// while the allocation and projection tables are empty for a different reason.
func TestCapacityScanReportsTruncationAndMetricsFailureTogether(t *testing.T) {
	db, dsn, srv := newCapacityServerAt(t)

	original := capacityScanBudget
	capacityScanBudget = 1
	t.Cleanup(func() { capacityScanBudget = original })

	seedCapacityCluster(t, db, "c1")
	dropMetricSamples(t, dsn)

	body := getJSON(t, srv.URL+"/admin/k8s/capacity?cluster_id=c1")
	scan, _ := brokenScanOf(t, body)
	if scan["status"] != "partial" {
		t.Fatalf("status = %v with a truncated window and unreadable metrics: %v", scan["status"], scan)
	}
	if _, ok := scan["metrics_error"]; !ok {
		t.Errorf("the metric failure disappeared behind the truncation notice: %v", scan)
	}
	reason, _ := scan["reason"].(string)
	if reason == "" {
		t.Fatalf("a doubly partial scan must explain itself: %v", scan)
	}
	if reason == capacityTruncationReason {
		t.Errorf("reason names only the truncation and not the lost metrics: %q", reason)
	}
}
