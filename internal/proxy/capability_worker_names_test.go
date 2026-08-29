package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"clustara/internal/config"
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

// The Workers field was not the only pointer the registry got wrong. Tables and Scopes hold
// exact identifiers too — the table names tell an auditor where a capability's data lives
// (retention review, export, DR) and the scope names tell an administrator what to grant —
// and nothing checked either.
//
// Measured: five table names and four scope names referred to nothing. Four of the tables
// were near-misses of real ones (policy_decisions vs policy_decision_events, okf_entries and
// okf_frames vs okf_documents and okf_links, personalization_recommendations vs
// personal_recommendations) and one, admin_settings_history, existed nowhere in the
// codebase at all. Three scopes on the vulnerability capability (security:policy,
// security:exception, security:runtime) can never be granted: role and key creation both
// validate against allScopes, so an administrator following that list gets "unknown scope".
//
// APIs and SettingKeys are deliberately excluded: both use non-literal notation elsewhere in
// the registry ("GET/POST /admin/okf/*", "clickhouse.*", "GET .../leaderboard"), so they are
// documentation strings rather than exact identifiers and cannot be checked this way.
func TestCapabilityTableAndScopeNamesResolve(t *testing.T) {
	tables := migratedTableNames(t)
	scopes := map[string]bool{}
	for _, s := range allScopes {
		scopes[s] = true
	}

	for _, capability := range capabilityRegistry {
		for _, table := range capability.Tables {
			if !tables[table] {
				t.Errorf("capability %q lists table %q, which the migrated schema does not "+
					"contain; anyone tracing where this capability's data lives is sent nowhere",
					capability.Key, table)
			}
		}
		for _, scope := range capability.Scopes {
			// "self" is deliberate notation for /me routes, which authorize on the caller's
			// own identity and require no scope at all. It is not a grantable scope and is
			// not meant to be.
			if scope == "self" {
				continue
			}
			if !scopes[scope] {
				t.Errorf("capability %q lists scope %q, which is not in allScopes; role and key "+
					"creation validate against that list, so an administrator following this "+
					"cannot grant it", capability.Key, scope)
			}
		}
	}
}

func migratedTableNames(t *testing.T) map[string]bool {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "schema.db")
	db, err := store.Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	if len(out) < 20 {
		t.Fatalf("only %d tables found after migration; the scan is looking at the wrong place", len(out))
	}
	return out
}

// UITabs is the registry's last reference field: it tells an operator which admin screen a
// capability lives on, and the capability card renders the names as chips.
//
// Measured: the okf capability claimed a tab named "okf" and the admin SPA has no such
// route — no case label, no render function, not one occurrence of the string anywhere in
// the UI. The backend is real (eight registered routes, a store layer, okf_documents and
// okf_links), so the catalog pointed at the one part of the feature that does not exist.
//
// Checked against the router switch specifically rather than every "case 'x':" in the file,
// so an unrelated switch elsewhere cannot make a dead tab look alive. All 54 tab names
// resolve there; only okf did not.
func TestCapabilityUITabsExistInTheAdminRouter(t *testing.T) {
	labels := adminRouterTabLabels(t)

	for _, capability := range capabilityRegistry {
		for _, tab := range capability.UITabs {
			if !labels[tab] {
				t.Errorf("capability %q lists UI tab %q, which the admin SPA router does not "+
					"dispatch; the card sends an operator to a screen that does not exist",
					capability.Key, tab)
			}
		}
	}
}

// adminRouterTabLabels returns the tab names the admin SPA's route switch handles. The
// router is identified by the case label for this very screen, so the anchor cannot drift
// to some other switch.
func adminRouterTabLabels(t *testing.T) map[string]bool {
	t.Helper()
	const anchor = "case 'capabilities':"
	idx := strings.Index(adminHTML, anchor)
	if idx < 0 {
		t.Fatal("the admin router anchor is gone; this scan is looking at the wrong place")
	}
	start := strings.LastIndex(adminHTML[:idx], "switch (tab) {")
	if start < 0 {
		t.Fatal("no route switch found before the anchor")
	}
	depth, end := 0, -1
	for i := start; i < len(adminHTML); i++ {
		switch adminHTML[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		t.Fatal("route switch is unbalanced")
	}
	labels := map[string]bool{}
	for _, m := range routerCaseLabel.FindAllStringSubmatch(adminHTML[start:end], -1) {
		labels[m[1]] = true
	}
	if len(labels) < 50 {
		t.Fatalf("only %d route labels found; the scan is looking at the wrong place", len(labels))
	}
	return labels
}

var routerCaseLabel = regexp.MustCompile(`case '([a-z0-9\-_]+)':`)
