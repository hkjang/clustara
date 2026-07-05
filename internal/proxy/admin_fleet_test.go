package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestFleetOpsOverviewAndSearch(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := db.UpsertK8sClusterGroup(ctx, store.K8sClusterGroup{ID: "grp_prod", Name: "prod-apac", Kind: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{
		ID: "c1", Name: "prod-1", GroupID: "grp_prod", Status: "ready", LastConnectedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sNamespaceOwnership(ctx, store.K8sNamespaceOwnership{
		ID: "own1", ClusterID: "c1", Namespace: "payments", Team: "team_platform", Owner: "sre", ServiceName: "payments-api",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "inv1", ClusterID: "c1", Kind: "Deployment", Namespace: "payments", Name: "payments-api",
		Status: "Running", HealthScore: 70, RiskLevel: "medium", Labels: map[string]string{"app": "payments"},
		Spec: map[string]any{"image": "registry.local/payments-api:v1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sSecurityFinding(ctx, store.K8sSecurityFinding{
		ID: "find1", ClusterID: "c1", Namespace: "payments", ResourceKind: "Deployment", ResourceName: "payments-api",
		Rule: "mutable-image", Severity: "medium", Status: "open",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sActionRequest(ctx, store.K8sActionRequest{
		ID: "act1", ClusterID: "c1", Namespace: "payments", ResourceKind: "Deployment", ResourceName: "payments-api",
		Action: "rollout_restart", Status: "pending_approval", RiskLevel: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sEvent(ctx, store.K8sEvent{
		ID: "evt1", ClusterID: "c1", Namespace: "payments", InvolvedKind: "Pod", InvolvedName: "payments-api-1",
		Type: "Warning", Reason: "BackOff", Message: "restart backoff", LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fleet.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	overviewResp, err := http.Get(srv.URL + "/admin/fleet/overview")
	if err != nil {
		t.Fatal(err)
	}
	var overview struct {
		Groups   []fleetGroupHealth   `json:"groups"`
		Clusters []fleetClusterHealth `json:"clusters"`
	}
	if err := json.NewDecoder(overviewResp.Body).Decode(&overview); err != nil {
		t.Fatal(err)
	}
	overviewResp.Body.Close()
	if overviewResp.StatusCode != http.StatusOK || len(overview.Groups) != 1 || len(overview.Clusters) != 1 {
		t.Fatalf("overview mismatch status=%d overview=%+v", overviewResp.StatusCode, overview)
	}
	if overview.Clusters[0].UnhealthyCount != 1 || overview.Clusters[0].OpenFindings != 1 || overview.Clusters[0].PendingActions != 1 || overview.Clusters[0].WarningEvents24 != 1 {
		t.Fatalf("cluster rollup mismatch: %+v", overview.Clusters[0])
	}

	searchResp, err := http.Get(srv.URL + "/admin/fleet/search?q=payments&owner=platform")
	if err != nil {
		t.Fatal(err)
	}
	var search struct {
		Count   int                 `json:"count"`
		Results []fleetSearchResult `json:"results"`
	}
	if err := json.NewDecoder(searchResp.Body).Decode(&search); err != nil {
		t.Fatal(err)
	}
	searchResp.Body.Close()
	if searchResp.StatusCode != http.StatusOK || search.Count != 1 || search.Results[0].ServiceName != "payments-api" {
		t.Fatalf("search mismatch status=%d search=%+v", searchResp.StatusCode, search)
	}
}
