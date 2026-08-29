package proxy

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

// The compliance report runs the rules over whatever the collectors last wrote into the
// inventory. Nothing in the response said when that was. An agent that stopped reporting
// an hour ago leaves an hour-old photograph in the table, and "checked / 위반 없음" over it
// is a statement about the past wearing the exact face of a live pass — the same failure
// v0.9.219/220/225 removed for empty rule sets, empty inventories and truncated windows,
// left standing for stale ones.
//
// The score for this already existed: analyzer.ScoreFreshness, plus a clusterFreshnessBadge
// helper documented as the way "other screens attach the same per-cluster score as a
// stale-warning badge". It had no callers anywhere — freshness lived only on its own page.
func TestComplianceVerdictSaysWhenItsInventoryIsStale(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	mustUpsertPolicy(t, db, "pol_on", true)

	// A workload the collectors last saw two hours ago, and the agent that was streaming
	// it has been silent just as long: the classic "the dashboard is green because nothing
	// is updating it" shape.
	old := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{
		ID: "inv_api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api",
		ObservedAt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sAgentHeartbeat(context.Background(), store.K8sAgentHeartbeat{
		ClusterID: "c1", AgentID: "agent-1", LastSeen: old,
	}); err != nil {
		t.Fatal(err)
	}

	body := getJSON(t, srv.URL+"/admin/k8s/policies/compliance")
	check, _ := body["policy_check"].(map[string]any)
	if check == nil {
		t.Fatalf("no policy_check in the compliance response: %v", body)
	}
	// The check genuinely ran over a real rule and a real resource — the status is not the
	// thing that is wrong. What was missing is that the resource is two hours cold.
	if check["status"] != "checked" {
		t.Fatalf("status = %v; the run had an enabled rule and an evaluable workload: %v", check["status"], check)
	}
	if check["stale"] != true {
		t.Fatalf("a verdict over inventory nobody has refreshed for two hours reported no staleness; "+
			"0 violations then reads as a live pass: %v", check)
	}
	age, ok := check["data_age_seconds"].(float64)
	if !ok || age < 3600 {
		t.Fatalf("data_age_seconds = %v, want the real age of the inventory (>1h): %v", check["data_age_seconds"], check)
	}
	if reason, _ := check["reason"].(string); !strings.Contains(reason, "현재 상태를 보장하지 않습니다") {
		t.Fatalf("reason must say the verdict is not about the cluster now, got %q", reason)
	}
	fresh, _ := body["freshness"].(map[string]any)
	if fresh == nil || fresh["band"] != "stale" {
		t.Fatalf("freshness detail missing or not stale: %v", body["freshness"])
	}
}

// Freshly collected inventory must stay silent — a staleness banner on every report is
// the same as no banner at all.
func TestComplianceVerdictIsQuietWhenInventoryIsCurrent(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	mustUpsertPolicy(t, db, "pol_on", true)
	mustUpsertWorkload(t, db, "inv_api")

	check, _ := getJSON(t, srv.URL+"/admin/k8s/policies/compliance")["policy_check"].(map[string]any)
	if check["status"] != "checked" {
		t.Fatalf("status = %v over just-collected inventory: %v", check["status"], check)
	}
	if _, marked := check["stale"]; marked {
		t.Fatalf("just-collected inventory flagged as stale: %v", check)
	}
}

// A report spanning several clusters is only as trustworthy as its worst feed: one live
// cluster must not average away a dead one.
func TestInventoryFreshnessReportsTheWorstCluster(t *testing.T) {
	db, _ := newPolicyStatusServer(t)
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339Nano)
	old := now.Add(-3 * time.Hour).Format(time.RFC3339Nano)
	items := []store.K8sInventoryItem{
		{ClusterID: "live", Kind: "Deployment", Namespace: "prod", Name: "a", ObservedAt: fresh, UpdatedAt: fresh},
		{ClusterID: "dead", Kind: "Deployment", Namespace: "prod", Name: "b", ObservedAt: old, UpdatedAt: old},
	}
	got := server.inventoryFreshness(httptest.NewRequest("GET", "/admin/k8s/policies/compliance", nil), items, now)
	if got.ClusterID != "dead" || !got.Stale {
		t.Fatalf("worst-cluster freshness = %+v; a live cluster must not mask a dead one", got)
	}
}

// clusterFreshnessBadge shipped with the freshness page and was never called by anything —
// not a handler, not a test, not even the file that declared it. Its doc comment named four
// screens as consumers. Nothing enforced that, so the stale-warning capability sat unused
// through eighty-odd releases while the screens it was written for kept presenting
// inventory-derived judgements as current.
//
// This pins the general shape: a helper in the freshness module has to be reachable from
// somewhere in the package's real code. A file-local helper is fine — an unreferenced one
// is the rot.
func TestFreshnessHelpersAreNotDeadCode(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	uses := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				if name == "admin_k8s_freshness.go" {
					declared[v.Name.Name] = true
				}
				return true
			case *ast.Ident:
				uses[v.Name]++
			}
			return true
		})
	}
	if len(declared) == 0 {
		t.Fatal("no functions found in admin_k8s_freshness.go; the scan is looking at the wrong place")
	}
	for fn := range declared {
		// The declaration itself contributes one Ident; anything reachable has more.
		if uses[fn] < 2 {
			t.Errorf("%s is declared in admin_k8s_freshness.go and referenced nowhere in the package — "+
				"a stale-warning helper nothing calls warns nobody", fn)
		}
	}
}
