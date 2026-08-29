package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"clustara/internal/store"
)

// Each capability lists the workers it depends on, and the admin UI shows that list so an
// operator can go and check whether the engine behind a feature is alive. Nothing verified
// the names were ones /admin/ops/workers can ever produce.
//
// Measured: the k8s_operations capability pointed at k8s_snapshot_ingest,
// k8s_agent_delta_ingest and k8s_analyzer. The board emits collector rows as
// "k8s_collector:<kind>@<cluster>", so those three matched nothing and never could — the
// pointer led nowhere for the capability with the most moving parts.
//
// The board is driven with every conditional row present (retention attached, ClickHouse
// configured, one collector row per kind) so a name is only reported missing when it is
// genuinely unproducible, not merely absent from one configuration.
func TestCapabilityWorkerNamesExistOnTheOpsBoard(t *testing.T) {
	board := opsBoardWorkerNames(t)

	for _, capability := range capabilityRegistry {
		for _, want := range capability.Workers {
			if board[want] {
				continue
			}
			// Collector rows are cluster-qualified, so a capability may name the family.
			qualified := false
			for name := range board {
				if strings.HasPrefix(name, want+"@") {
					qualified = true
					break
				}
			}
			if !qualified {
				t.Errorf("capability %q depends on worker %q, which /admin/ops/workers never "+
					"emits; an operator following that pointer finds nothing. Board: %s",
					capability.Key, want, strings.Join(sortedBoardNames(board), " "))
			}
		}
	}
}

// opsBoardWorkerNames returns every worker name the board produces when every conditional
// row is present.
func opsBoardWorkerNames(t *testing.T) map[string]bool {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "workers.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.ClickHouse.URL = "http://clickhouse.invalid:8123"
	retention := store.NewRetentionWorker(db, cfg.Retention)
	server, err := NewServer(cfg, db, logger, retention)
	if err != nil {
		t.Fatal(err)
	}
	// One row per collector kind the ingest paths write, so the cluster-qualified rows exist.
	for _, kind := range []string{"snapshot", "agent", "analyzer", "revision", "agent_auth"} {
		if err := db.UpsertK8sCollectorStatus(context.Background(), store.K8sCollectorStatus{
			ID: "col_" + kind, ClusterID: "c1", Collector: kind, Status: "ok",
		}); err != nil {
			t.Fatal(err)
		}
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)

	resp, err := http.Get(proxy.URL + "/admin/ops/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/ops/workers = %d: %s", resp.StatusCode, raw)
	}
	var body struct {
		Workers []struct {
			Name string `json:"name"`
		} `json:"workers"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode workers: %v", err)
	}
	if len(body.Workers) == 0 {
		t.Fatal("the ops board returned no workers; the scan is looking at the wrong place")
	}
	out := map[string]bool{}
	for _, w := range body.Workers {
		out[w.Name] = true
	}
	// The conditional rows must actually be present, or this test would pass by accident on
	// a board that is missing them.
	for _, required := range []string{"retention", "clickhouse_fact_retry"} {
		if !out[required] {
			t.Fatalf("the harness did not produce the conditional row %q, so absent names "+
				"cannot be judged", required)
		}
	}
	return out
}

func sortedBoardNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
