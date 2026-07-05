package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func TestFinOpsOverview(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)

	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod-1", Status: "ready", LastConnectedAt: nowText}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sNamespaceOwnership(ctx, store.K8sNamespaceOwnership{
		ID: "own1", ClusterID: "c1", Namespace: "prod", Team: "platform", Owner: "sre", ServiceName: "api", CostCenter: "cc-100",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "pod1", ClusterID: "c1", Kind: "Pod", Namespace: "prod", Name: "api-1", Status: "Running", HealthScore: 95, RiskLevel: "low",
		Spec: map[string]any{"containers": []any{map[string]any{"name": "api", "resources": map[string]any{"requests": map[string]any{"cpu": "1000m", "memory": "1Gi"}}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sMetricSample(ctx, store.K8sMetricSample{
		ID: "metric1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Pod", ResourceName: "api-1",
		CPUMillicores: 100, MemoryBytes: 128 << 20, ObservedAt: nowText,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertBudget(ctx, store.Budget{ID: "budget1", Scope: "team", ScopeValue: "platform", MonthlyKRW: 1000, Note: "tight budget"}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordK8sCostSnapshot(ctx, store.K8sCostSnapshot{
		ClusterID: "c1", Dimension: "namespace", Key: "prod", Day: now.AddDate(0, 0, -1).Format("2006-01-02"), MonthlyKRW: 100000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordK8sCostSnapshot(ctx, store.K8sCostSnapshot{
		ClusterID: "c1", Dimension: "namespace", Key: "prod", Day: now.Format("2006-01-02"), MonthlyKRW: 160000,
	}); err != nil {
		t.Fatal(err)
	}

	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "finops.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/finops/overview?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/finops/overview = %d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Summary struct {
			EstimatedMonthlyKRW float64 `json:"estimated_monthly_krw"`
			BudgetViolations    int     `json:"budget_violations"`
			Anomalies           int     `json:"anomalies"`
		} `json:"summary"`
		Budgets     []finOpsBudgetLine `json:"budgets"`
		Anomalies   []finOpsAnomaly    `json:"anomalies"`
		Rightsizing struct {
			Recommendations []analyzer.RightsizingRec `json:"recommendations"`
		} `json:"rightsizing"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary.EstimatedMonthlyKRW <= 1000 || out.Summary.BudgetViolations != 1 || len(out.Budgets) != 1 || out.Budgets[0].Status != "critical" {
		t.Fatalf("budget summary mismatch: %+v budgets=%+v", out.Summary, out.Budgets)
	}
	if out.Summary.Anomalies != 1 || len(out.Anomalies) != 1 || out.Anomalies[0].Severity != "critical" {
		t.Fatalf("anomaly mismatch: summary=%+v anomalies=%+v", out.Summary, out.Anomalies)
	}
	if len(out.Rightsizing.Recommendations) != 1 || out.Rightsizing.Recommendations[0].Direction != "down" {
		t.Fatalf("rightsizing mismatch: %+v", out.Rightsizing.Recommendations)
	}
}
