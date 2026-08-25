package proxy

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestFleetSearchRanksBeforeApplyingResponseLimit(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID:        fmt.Sprintf("recent-%02d", i),
			ClusterID: "c1",
			Kind:      "Deployment",
			Namespace: "default",
			Name:      fmt.Sprintf("recent-%02d", i),
			UpdatedAt: fmt.Sprintf("2026-07-28T02:%02d:00Z", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []store.K8sInventoryItem{
		{ID: "substring", ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "old-needle", UpdatedAt: "2020-01-01T00:00:02Z"},
		{ID: "prefix", ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "needle-worker", UpdatedAt: "2020-01-01T00:00:01Z"},
		{ID: "exact", ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "needle", UpdatedAt: "2020-01-01T00:00:00Z"},
	} {
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fleet-search.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/fleet/search?q=needle&limit=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload struct {
		Count     int                 `json:"count"`
		Truncated bool                `json:"truncated"`
		Results   []fleetSearchResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || payload.Count != 2 || !payload.Truncated {
		t.Fatalf("fleet search status/count/truncated = %d/%d/%v: %+v", resp.StatusCode, payload.Count, payload.Truncated, payload.Results)
	}
	if payload.Results[0].Name != "needle" || payload.Results[1].Name != "needle-worker" {
		t.Fatalf("fleet search ranking = %+v, want exact then prefix", payload.Results)
	}
}

func TestFleetSearchEnrichesCatalogBeyondGeneralListCap(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "runtime-only", ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "runtime-only",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if err := db.UpsertCatalogEntity(ctx, store.CatalogEntity{
			ID: fmt.Sprintf("catalog-%04d", i), Kind: "service", Name: fmt.Sprintf("aaaa-%04d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertCatalogEntity(ctx, store.CatalogEntity{
		ID:         "catalog-deep",
		Kind:       "service",
		Name:       "zzzz-deep-catalog-token",
		RuntimeRef: "c1/default/Deployment/runtime-only",
	}); err != nil {
		t.Fatal(err)
	}

	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fleet-catalog.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/fleet/search?q=deep-catalog-token&limit=5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload struct {
		Results []fleetSearchResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(payload.Results) != 1 {
		t.Fatalf("fleet catalog boundary search status/results = %d/%+v", resp.StatusCode, payload.Results)
	}
	if payload.Results[0].Name != "runtime-only" || payload.Results[0].CatalogID != "catalog-deep" {
		t.Fatalf("catalog boundary enrichment = %+v", payload.Results[0])
	}
}

func TestFleetSearchUsesEveryCatalogSharingRuntimeRef(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "shared-runtime", ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "shared-runtime",
	}); err != nil {
		t.Fatal(err)
	}
	runtimeRef := "c1/default/Deployment/shared-runtime"
	for _, catalog := range []store.CatalogEntity{
		{ID: "catalog-a", Kind: "service", Name: "alpha-catalog", ProjectID: "alpha", RuntimeRef: runtimeRef},
		{ID: "catalog-b", Kind: "service", Name: "beta-unique-token", ProjectID: "beta", RuntimeRef: runtimeRef},
	} {
		if err := db.UpsertCatalogEntity(ctx, catalog); err != nil {
			t.Fatal(err)
		}
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fleet-shared-catalog.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/fleet/search?q=beta-unique-token&limit=5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload struct {
		Results []fleetSearchResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(payload.Results) != 1 {
		t.Fatalf("shared runtime-ref search status/results = %d/%+v", resp.StatusCode, payload.Results)
	}
	if payload.Results[0].CatalogID != "catalog-b" {
		t.Fatalf("query-matching catalog was not selected: %+v", payload.Results[0])
	}
}
