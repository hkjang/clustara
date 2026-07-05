package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

func TestCatalogScorecardsAndSelfServiceActions(t *testing.T) {
	ctx := context.Background()
	db := openTestStore(t)
	defer db.Close()
	if err := db.UpsertAuthTeam(ctx, store.AuthTeam{ID: "team_platform", Name: "Platform"}); err != nil {
		t.Fatal(err)
	}
	org := store.EnterpriseOrganization{ID: "org_acme", Name: "Acme"}
	if err := db.UpsertEnterpriseOrganization(ctx, org); err != nil {
		t.Fatal(err)
	}
	ws := store.EnterpriseWorkspace{ID: "ws_core", OrganizationID: org.ID, Name: "Core"}
	if err := db.UpsertEnterpriseWorkspace(ctx, ws); err != nil {
		t.Fatal(err)
	}
	project := store.EnterpriseProject{ID: "proj_payments", WorkspaceID: ws.ID, Name: "payments", Environment: "prod", OwnerTeamID: "team_platform", Criticality: "high"}
	if err := db.UpsertEnterpriseProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	entity := store.CatalogEntity{
		ID:          "cat_payments_api",
		Kind:        "Service",
		Name:        "payments-api",
		ProjectID:   project.ID,
		OwnerTeamID: "team_platform",
		RuntimeRef:  "c1/prod/Deployment/payments",
		RepoURL:     "https://git.example/payments",
		DocsURL:     "https://docs.example/payments",
		Criticality: "high",
	}
	if err := db.UpsertCatalogEntity(ctx, entity); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "cluster-one", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID:          "inv_payments_deploy",
		ClusterID:   "c1",
		Kind:        "Deployment",
		Namespace:   "prod",
		Name:        "payments",
		Status:      "Running",
		HealthScore: 80,
		RiskLevel:   "medium",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID:          "inv_orders_deploy",
		ClusterID:   "c1",
		Kind:        "Deployment",
		Namespace:   "prod",
		Name:        "orders",
		Status:      "Running",
		HealthScore: 95,
		RiskLevel:   "low",
		Labels:      map[string]string{"app.kubernetes.io/name": "orders-api"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sNamespaceOwnership(ctx, store.K8sNamespaceOwnership{
		ID:          "own_prod",
		ClusterID:   "c1",
		Namespace:   "prod",
		Team:        "team_platform",
		Owner:       "platform@example.com",
		ServiceName: "payments",
		Criticality: "high",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.UpsertK8sIncidentByKey(ctx, store.K8sIncident{
		DedupKey:  "c1/prod/Deployment/payments/crashloop",
		ClusterID: "c1",
		Namespace: "prod",
		Kind:      "Deployment",
		Name:      "payments",
		Condition: "CrashLoopBackOff",
		Severity:  "high",
		Title:     "payments crashloop",
	}, newID); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sSecurityFinding(ctx, store.K8sSecurityFinding{
		ID:           "find_payments_wildcard",
		ClusterID:    "c1",
		Namespace:    "prod",
		ResourceKind: "Deployment",
		ResourceName: "payments",
		Rule:         "run-as-root",
		Severity:     "critical",
		Status:       "open",
		Message:      "container runs as root",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sActionRequest(ctx, store.K8sActionRequest{
		ID:           "k8sact_restart_payments",
		ClusterID:    "c1",
		Namespace:    "prod",
		ResourceKind: "Deployment",
		ResourceName: "payments",
		Action:       "rollout_restart",
		RiskLevel:    "medium",
		Status:       "pending_approval",
		RequestedBy:  "tester",
	}); err != nil {
		t.Fatal(err)
	}

	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "catalog-plus.ndjson"))
	logger.Start()
	defer logger.Stop(ctx)
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	scoreResp, err := http.Get(srv.URL + "/admin/catalog/scorecards?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	var scoreOut struct {
		Scorecards []map[string]any `json:"scorecards"`
		Count      int              `json:"count"`
	}
	_ = json.NewDecoder(scoreResp.Body).Decode(&scoreOut)
	scoreResp.Body.Close()
	if scoreResp.StatusCode != http.StatusOK || scoreOut.Count != 1 {
		t.Fatalf("scorecard response mismatch status=%d out=%+v", scoreResp.StatusCode, scoreOut)
	}
	if scoreOut.Scorecards[0]["entity_id"] != entity.ID {
		t.Fatalf("scorecard entity mismatch: %+v", scoreOut.Scorecards[0])
	}
	if got, _ := scoreOut.Scorecards[0]["open_incidents"].(float64); got < 1 {
		t.Fatalf("scorecard should include incident signal: %+v", scoreOut.Scorecards[0])
	}
	if got, _ := scoreOut.Scorecards[0]["open_security_findings"].(float64); got < 1 {
		t.Fatalf("scorecard should include security signal: %+v", scoreOut.Scorecards[0])
	}

	detailResp, err := http.Get(srv.URL + "/admin/catalog/entities/" + entity.ID + "/runtime")
	if err != nil {
		t.Fatal(err)
	}
	var detailOut struct {
		Entity    store.CatalogEntity      `json:"entity"`
		Inventory []store.K8sInventoryItem `json:"inventory"`
		Actions   []store.K8sActionRequest `json:"k8s_actions"`
		Summary   map[string]any           `json:"summary"`
	}
	_ = json.NewDecoder(detailResp.Body).Decode(&detailOut)
	detailResp.Body.Close()
	if detailResp.StatusCode != http.StatusOK || detailOut.Entity.ID != entity.ID || len(detailOut.Inventory) != 1 || len(detailOut.Actions) != 1 {
		t.Fatalf("runtime detail mismatch status=%d out=%+v", detailResp.StatusCode, detailOut)
	}

	fleetResp, err := http.Get(srv.URL + "/admin/fleet/search?cluster_id=c1&q=payments-api")
	if err != nil {
		t.Fatal(err)
	}
	var fleetOut struct {
		Results []struct {
			Name      string `json:"name"`
			CatalogID string `json:"catalog_id"`
			ProjectID string `json:"project_id"`
		} `json:"results"`
	}
	_ = json.NewDecoder(fleetResp.Body).Decode(&fleetOut)
	fleetResp.Body.Close()
	if fleetResp.StatusCode != http.StatusOK || len(fleetOut.Results) != 1 || fleetOut.Results[0].CatalogID != entity.ID || fleetOut.Results[0].ProjectID != project.ID {
		t.Fatalf("fleet search catalog enrichment mismatch status=%d out=%+v", fleetResp.StatusCode, fleetOut)
	}

	unlinkedFleetResp, err := http.Get(srv.URL + "/admin/fleet/search?cluster_id=c1&q=orders")
	if err != nil {
		t.Fatal(err)
	}
	var unlinkedFleetOut struct {
		Results []struct {
			Name          string `json:"name"`
			CatalogStatus string `json:"catalog_status"`
			CatalogGapKey string `json:"catalog_gap_key"`
			RuntimeRef    string `json:"runtime_ref"`
		} `json:"results"`
	}
	_ = json.NewDecoder(unlinkedFleetResp.Body).Decode(&unlinkedFleetOut)
	unlinkedFleetResp.Body.Close()
	if unlinkedFleetResp.StatusCode != http.StatusOK ||
		len(unlinkedFleetOut.Results) != 1 ||
		unlinkedFleetOut.Results[0].CatalogStatus != "unlinked_runtime" ||
		unlinkedFleetOut.Results[0].CatalogGapKey != "unlinked_runtime|c1/prod/Deployment/orders" ||
		unlinkedFleetOut.Results[0].RuntimeRef != "c1/prod/Deployment/orders" {
		t.Fatalf("fleet search unlinked catalog status mismatch status=%d out=%+v", unlinkedFleetResp.StatusCode, unlinkedFleetOut)
	}

	candidateResp, err := http.Get(srv.URL + "/admin/catalog/runtime-candidates?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	var candidateOut struct {
		Candidates []struct {
			RuntimeRef          string `json:"runtime_ref"`
			SuggestedName       string `json:"suggested_name"`
			SuggestedTeam       string `json:"suggested_team"`
			SuggestedTeamID     string `json:"suggested_team_id"`
			SuggestedProjectID  string `json:"suggested_project_id"`
			SuggestedProject    string `json:"suggested_project"`
			SuggestedEnviroment string `json:"suggested_environment"`
		} `json:"candidates"`
		Count int `json:"count"`
	}
	_ = json.NewDecoder(candidateResp.Body).Decode(&candidateOut)
	candidateResp.Body.Close()
	if candidateResp.StatusCode != http.StatusOK || candidateOut.Count != 1 ||
		candidateOut.Candidates[0].RuntimeRef != "c1/prod/Deployment/orders" ||
		candidateOut.Candidates[0].SuggestedName != "orders-api" ||
		candidateOut.Candidates[0].SuggestedTeamID != "team_platform" ||
		candidateOut.Candidates[0].SuggestedProjectID != project.ID ||
		candidateOut.Candidates[0].SuggestedProject != project.Name ||
		candidateOut.Candidates[0].SuggestedEnviroment != project.Environment {
		t.Fatalf("runtime candidates mismatch status=%d out=%+v", candidateResp.StatusCode, candidateOut)
	}

	coverageResp, err := http.Get(srv.URL + "/admin/catalog/coverage?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	var coverageOut struct {
		Summary map[string]any `json:"summary"`
		Buckets []struct {
			ClusterID   string `json:"cluster_id"`
			Namespace   string `json:"namespace"`
			Kind        string `json:"kind"`
			Total       int    `json:"total"`
			Linked      int    `json:"linked"`
			Unlinked    int    `json:"unlinked"`
			CoveragePct int    `json:"coverage_pct"`
		} `json:"buckets"`
	}
	_ = json.NewDecoder(coverageResp.Body).Decode(&coverageOut)
	coverageResp.Body.Close()
	if coverageResp.StatusCode != http.StatusOK || int(coverageOut.Summary["total_runtime"].(float64)) != 2 || int(coverageOut.Summary["linked_runtime"].(float64)) != 1 || int(coverageOut.Summary["unlinked_runtime"].(float64)) != 1 {
		t.Fatalf("catalog coverage summary mismatch status=%d out=%+v", coverageResp.StatusCode, coverageOut)
	}
	if len(coverageOut.Buckets) != 1 || coverageOut.Buckets[0].CoveragePct != 50 {
		t.Fatalf("catalog coverage bucket mismatch: %+v", coverageOut.Buckets)
	}

	gapResp, err := http.Get(srv.URL + "/admin/catalog/gaps?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	var gapOut struct {
		Gaps []struct {
			Type     string `json:"type"`
			Target   string `json:"target"`
			Severity string `json:"severity"`
		} `json:"gaps"`
		Summary map[string]int `json:"summary"`
	}
	_ = json.NewDecoder(gapResp.Body).Decode(&gapOut)
	gapResp.Body.Close()
	if gapResp.StatusCode != http.StatusOK || len(gapOut.Gaps) == 0 || gapOut.Gaps[0].Type != "unlinked_runtime" || gapOut.Gaps[0].Target != "c1/prod/Deployment/orders" || gapOut.Summary["medium"] < 1 {
		t.Fatalf("catalog gaps mismatch status=%d out=%+v", gapResp.StatusCode, gapOut)
	}

	gapKey := "unlinked_runtime|c1/prod/Deployment/orders"
	exceptionResp := postJSON(t, srv.URL+"/admin/catalog/gap-exceptions", "", map[string]any{
		"scope_type": "catalog_gap",
		"scope_id":   gapKey,
		"name":       "gap exception · orders",
		"status":     "active",
		"source_ref": "c1/prod/Deployment/orders",
		"payload": map[string]any{
			"gap_key":    gapKey,
			"gap_type":   "unlinked_runtime",
			"target":     "c1/prod/Deployment/orders",
			"reason":     "managed by external catalog during migration",
			"expires_at": "2099-01-01T00:00:00Z",
		},
	})
	if exceptionResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(exceptionResp.Body)
		exceptionResp.Body.Close()
		t.Fatalf("gap exception create status=%d body=%s", exceptionResp.StatusCode, body)
	}
	exceptionResp.Body.Close()
	suppressedResp, err := http.Get(srv.URL + "/admin/catalog/gaps?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	var suppressedOut struct {
		Gaps            []map[string]any `json:"gaps"`
		SuppressedCount int              `json:"suppressed_count"`
	}
	_ = json.NewDecoder(suppressedResp.Body).Decode(&suppressedOut)
	suppressedResp.Body.Close()
	if suppressedResp.StatusCode != http.StatusOK || len(suppressedOut.Gaps) != 0 || suppressedOut.SuppressedCount != 1 {
		t.Fatalf("catalog gap exception suppression mismatch status=%d out=%+v", suppressedResp.StatusCode, suppressedOut)
	}

	reportResp, err := http.Get(srv.URL + "/admin/governance/executive-report")
	if err != nil {
		t.Fatal(err)
	}
	var reportOut struct {
		Summary map[string]any `json:"summary"`
	}
	_ = json.NewDecoder(reportResp.Body).Decode(&reportOut)
	reportResp.Body.Close()
	if reportResp.StatusCode != http.StatusOK ||
		int(reportOut.Summary["catalog_gap_exceptions"].(float64)) != 1 ||
		int(reportOut.Summary["governance_debt"].(float64)) < 1 {
		t.Fatalf("governance report should include catalog gap exceptions status=%d out=%+v", reportResp.StatusCode, reportOut)
	}

	auditResp, err := http.Get(srv.URL + "/admin/governance/audit-search?q=catalog_gap_exception")
	if err != nil {
		t.Fatal(err)
	}
	var auditOut struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.NewDecoder(auditResp.Body).Decode(&auditOut)
	auditResp.Body.Close()
	if auditResp.StatusCode != http.StatusOK || len(auditOut.Events) == 0 {
		t.Fatalf("audit search should include catalog gap exception ledger status=%d out=%+v", auditResp.StatusCode, auditOut)
	}

	actionResp := postJSON(t, srv.URL+"/admin/catalog/self-service-actions", "", map[string]any{
		"scope_type":    "catalog_entity",
		"scope_id":      entity.ID,
		"name":          "scale_request · payments-api",
		"owner_team_id": "team_platform",
		"source_ref":    entity.RuntimeRef,
		"payload": map[string]any{
			"action_type": "scale_request",
			"risk_level":  "medium",
			"reason":      "capacity test",
		},
	})
	if actionResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(actionResp.Body)
		actionResp.Body.Close()
		t.Fatalf("self-service action create status=%d body=%s", actionResp.StatusCode, body)
	}
	actionResp.Body.Close()

	listResp, err := http.Get(srv.URL + "/admin/catalog/self-service-actions?scope_id=" + entity.ID)
	if err != nil {
		t.Fatal(err)
	}
	var listOut struct {
		Actions []store.EnterpriseRecord `json:"actions"`
		Count   int                      `json:"count"`
	}
	_ = json.NewDecoder(listResp.Body).Decode(&listOut)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK || listOut.Count != 1 || listOut.Actions[0].Status != "draft" {
		t.Fatalf("self-service action list mismatch status=%d out=%+v", listResp.StatusCode, listOut)
	}
}
