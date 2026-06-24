package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func TestK8sFactRowBuilders(t *testing.T) {
	ts := "2026-06-24T05:00:00Z"

	chg := k8sChangeRows(ts, []store.K8sResourceRevision{
		{ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "api", ChangeKind: "updated", ImageSet: "x:2", Replica: 3, SpecHash: "abc"},
	})
	if len(chg) != 1 || chg[0]["change_kind"] != "updated" || chg[0]["image_set"] != "x:2" || chg[0]["cluster_id"] != "c1" {
		t.Fatalf("change row wrong: %+v", chg)
	}

	// workload_health only includes workload kinds.
	wh := k8sWorkloadHealthRows(ts, []store.K8sInventoryItem{
		{ClusterID: "c1", Kind: "Deployment", Name: "api", HealthScore: 80, RiskLevel: "medium"},
		{ClusterID: "c1", Kind: "ConfigMap", Name: "cfg"}, // excluded
	})
	if len(wh) != 1 || wh[0]["health_score"] != 80 {
		t.Fatalf("workload_health rows wrong: %+v", wh)
	}

	// security rows skip restricted-level pods.
	sec := analyzer.SecurityReport{
		RBAC:        []analyzer.SecFinding{{Namespace: "ns", ResourceKind: "ClusterRole", ResourceName: "admin", Rule: "rbac-cluster-admin", Severity: "critical"}},
		PodSecurity: []analyzer.PodSecurityResult{{Namespace: "ns", Kind: "Deployment", Name: "ok", Level: "restricted"}, {Namespace: "ns", Kind: "Deployment", Name: "bad", Level: "privileged", Violations: []string{"hostNetwork"}}},
	}
	sr := k8sSecurityRows(ts, "c1", sec)
	rules := map[string]bool{}
	for _, r := range sr {
		rules[r["rule"].(string)] = true
	}
	if !rules["rbac-cluster-admin"] || !rules["pod-security-privileged"] {
		t.Fatalf("expected rbac + privileged rows, got %+v", sr)
	}
	if rules["pod-security-restricted"] {
		t.Fatalf("restricted pods must not be emitted: %+v", sr)
	}

	cost := analyzer.CostReport{ByNamespace: []analyzer.CostLine{{Key: "web", MonthlyKRW: 1000}}}
	cr := k8sCostRows(ts, "c1", cost)
	if len(cr) != 1 || cr[0]["dimension"] != "namespace" || cr[0]["monthly_krw"] != 1000.0 {
		t.Fatalf("cost row wrong: %+v", cr)
	}
}

func TestK8sFactTableNameDefault(t *testing.T) {
	if got := k8sFactTable("change"); got != "k8s_change_fact" {
		t.Fatalf("default table = %q, want k8s_change_fact", got)
	}
}

func TestK8sDWReport(t *testing.T) {
	// Fake ClickHouse that returns a valid JSON result for SELECT queries.
	var gotQuery string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"meta":[{"name":"day"},{"name":"value"}],"data":[{"day":"2026-06-24","value":42}]}`))
	}))
	defer ch.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "dw.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.ClickHouse.URL = ch.URL
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	// Happy path: kind=cost → aggregation query + parsed data.
	resp, err := http.Get(srv.URL + "/admin/k8s/dw/report?kind=cost&days=7")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body["available"] != true || body["data"] == nil {
		t.Fatalf("expected available report with data, got %+v", body)
	}
	if !strings.Contains(gotQuery, "avg(monthly_krw)") || !strings.Contains(gotQuery, "dimension='namespace'") {
		t.Fatalf("cost report query wrong: %s", gotQuery)
	}

	// Bad cluster_id is rejected (SQL-injection guard).
	resp2, _ := http.Get(srv.URL + "/admin/k8s/dw/report?kind=cost&cluster_id=a%27b")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("malicious cluster_id should be 400, got %d", resp2.StatusCode)
	}
}

func TestK8sDWSinkNoClickHouse(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "dw.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/admin/k8s/dw/sink", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Sinked bool `json:"sinked"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Sinked {
		t.Fatal("without CLICKHOUSE_URL, sink should be a no-op (sinked=false)")
	}
}
