package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestEnterpriseFoundationAdminAPIs(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	if err := db.UpsertAuthTeam(context.Background(), store.AuthTeam{ID: "team_platform", Name: "Platform"}); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "enterprise.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	orgResp := postJSON(t, srv.URL+"/admin/orgs", "", map[string]string{"name": "Acme", "description": "tenant"})
	if orgResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(orgResp.Body)
		t.Fatalf("org create status=%d body=%s", orgResp.StatusCode, body)
	}
	var orgOut struct {
		Organization store.EnterpriseOrganization `json:"organization"`
	}
	_ = json.NewDecoder(orgResp.Body).Decode(&orgOut)
	orgResp.Body.Close()
	if orgOut.Organization.ID == "" {
		t.Fatal("organization id should be generated")
	}

	wsResp := postJSON(t, srv.URL+"/admin/workspaces", "", map[string]string{"organization_id": orgOut.Organization.ID, "name": "Core"})
	if wsResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(wsResp.Body)
		t.Fatalf("workspace create status=%d body=%s", wsResp.StatusCode, body)
	}
	var wsOut struct {
		Workspace store.EnterpriseWorkspace `json:"workspace"`
	}
	_ = json.NewDecoder(wsResp.Body).Decode(&wsOut)
	wsResp.Body.Close()

	badProject := postJSON(t, srv.URL+"/admin/projects", "", map[string]string{"workspace_id": wsOut.Workspace.ID, "name": "bad", "owner_team_id": "team_missing"})
	badProject.Body.Close()
	if badProject.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown owner team should be rejected, got %d", badProject.StatusCode)
	}

	projectResp := postJSON(t, srv.URL+"/admin/projects", "", map[string]string{
		"workspace_id": wsOut.Workspace.ID, "name": "payments", "environment": "prod", "owner_team_id": "team_platform", "cost_center": "cc-100",
	})
	if projectResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(projectResp.Body)
		t.Fatalf("project create status=%d body=%s", projectResp.StatusCode, body)
	}
	var projectOut struct {
		Project store.EnterpriseProject `json:"project"`
	}
	_ = json.NewDecoder(projectResp.Body).Decode(&projectOut)
	projectResp.Body.Close()

	entityResp := postJSON(t, srv.URL+"/admin/catalog/entities", "", map[string]any{
		"kind": "Service", "name": "payments-api", "project_id": projectOut.Project.ID, "owner_team_id": "team_platform", "runtime_ref": "c1/prod/Deployment/payments", "tags": []string{"payments", "api"},
	})
	if entityResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(entityResp.Body)
		t.Fatalf("entity create status=%d body=%s", entityResp.StatusCode, body)
	}
	entityResp.Body.Close()

	bindingResp := postJSON(t, srv.URL+"/admin/access-bindings", "", map[string]any{
		"subject_type": "team", "subject_id": "team_platform", "resource_type": "project", "resource_id": projectOut.Project.ID, "role": "operator", "conditions": map[string]any{"environment": "prod"},
	})
	if bindingResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(bindingResp.Body)
		t.Fatalf("binding create status=%d body=%s", bindingResp.StatusCode, body)
	}
	bindingResp.Body.Close()

	evalResp := postJSON(t, srv.URL+"/admin/access-bindings/evaluate", "", map[string]any{
		"subject_type": "team", "subject_id": "team_platform", "resource_type": "project", "resource_id": projectOut.Project.ID, "role": "operator", "context": map[string]any{"environment": "prod"},
	})
	if evalResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(evalResp.Body)
		t.Fatalf("binding evaluate status=%d body=%s", evalResp.StatusCode, body)
	}
	var evalOut struct {
		Decision store.AccessBindingDecision `json:"decision"`
	}
	_ = json.NewDecoder(evalResp.Body).Decode(&evalOut)
	evalResp.Body.Close()
	if !evalOut.Decision.Allowed || evalOut.Decision.Decision != "allow" {
		t.Fatalf("binding evaluate mismatch: %+v", evalOut.Decision)
	}
	badEval := postJSON(t, srv.URL+"/admin/access-bindings/evaluate", "", map[string]any{
		"subject_type": "team", "subject_id": "team_platform", "resource_type": "project", "resource_id": projectOut.Project.ID,
	})
	badEval.Body.Close()
	if badEval.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing role should be rejected, got %d", badEval.StatusCode)
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/catalog/entities?owner_team_id=team_platform", nil)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	var listOut struct {
		Entities []store.CatalogEntity `json:"entities"`
	}
	_ = json.NewDecoder(listResp.Body).Decode(&listOut)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK || len(listOut.Entities) != 1 || listOut.Entities[0].Name != "payments-api" {
		t.Fatalf("catalog list mismatch status=%d entities=%+v", listResp.StatusCode, listOut.Entities)
	}

	audits, err := db.ListAdminAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range audits {
		if strings.HasPrefix(row.Action, "enterprise.") || row.Action == "catalog.entity.upsert" || row.Action == "access.binding.upsert" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("enterprise audit event missing: %+v", audits)
	}
}
