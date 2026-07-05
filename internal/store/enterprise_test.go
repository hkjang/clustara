package store

import (
	"context"
	"testing"
)

func TestEnterpriseFoundationCRUD(t *testing.T) {
	db := openAggTestStore(t)
	defer db.Close()
	ctx := context.Background()

	if err := db.UpsertAuthTeam(ctx, AuthTeam{ID: "team_platform", Name: "Platform"}); err != nil {
		t.Fatal(err)
	}
	org := EnterpriseOrganization{ID: "org_acme", Name: "Acme", Description: "enterprise tenant", SourceIDP: "keycloak"}
	if err := db.UpsertEnterpriseOrganization(ctx, org); err != nil {
		t.Fatal(err)
	}
	ws := EnterpriseWorkspace{ID: "ws_core", OrganizationID: org.ID, Name: "Core"}
	if err := db.UpsertEnterpriseWorkspace(ctx, ws); err != nil {
		t.Fatal(err)
	}
	project := EnterpriseProject{ID: "prj_payments", WorkspaceID: ws.ID, Name: "payments", Environment: "prod", OwnerTeamID: "team_platform", CostCenter: "cc-100", Criticality: "critical"}
	if err := db.UpsertEnterpriseProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	entity := CatalogEntity{ID: "cat_payments_api", Kind: "Service", Name: "payments-api", ProjectID: project.ID, OwnerTeamID: "team_platform", RuntimeRef: "c1/prod/Deployment/payments", Tags: []string{"payments", "api"}}
	if err := db.UpsertCatalogEntity(ctx, entity); err != nil {
		t.Fatal(err)
	}
	binding := AccessBinding{ID: "bind_platform_prod", SubjectType: "team", SubjectID: "team_platform", ResourceType: "project", ResourceID: project.ID, Role: "operator", Effect: "allow", Conditions: map[string]any{"environment": "prod", "risk_level": "medium"}}
	if err := db.UpsertAccessBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}

	orgs, err := db.ListEnterpriseOrganizations(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].SyncStatus != "manual" {
		t.Fatalf("organizations mismatch orgs=%+v err=%v", orgs, err)
	}
	workspaces, err := db.ListEnterpriseWorkspaces(ctx, EnterpriseWorkspaceFilter{OrganizationID: org.ID})
	if err != nil || len(workspaces) != 1 || workspaces[0].ID != ws.ID {
		t.Fatalf("workspaces mismatch workspaces=%+v err=%v", workspaces, err)
	}
	projects, err := db.ListEnterpriseProjects(ctx, EnterpriseProjectFilter{OwnerTeamID: "team_platform", Environment: "prod"})
	if err != nil || len(projects) != 1 || projects[0].CostCenter != "cc-100" {
		t.Fatalf("projects mismatch projects=%+v err=%v", projects, err)
	}
	entities, err := db.ListCatalogEntities(ctx, CatalogEntityFilter{OwnerTeamID: "team_platform"})
	if err != nil || len(entities) != 1 || len(entities[0].Tags) != 2 || entities[0].Tags[0] != "payments" {
		t.Fatalf("entities mismatch entities=%+v err=%v", entities, err)
	}
	bindings, err := db.ListAccessBindings(ctx, AccessBindingFilter{SubjectType: "team", ResourceType: "project"})
	if err != nil || len(bindings) != 1 || bindings[0].Conditions["environment"] != "prod" {
		t.Fatalf("bindings mismatch bindings=%+v err=%v", bindings, err)
	}
	allowDecision, err := db.EvaluateAccessBinding(ctx, AccessBindingEvaluateInput{
		SubjectType:  "team",
		SubjectID:    "team_platform",
		ResourceType: "project",
		ResourceID:   project.ID,
		Role:         "operator",
		Context:      map[string]any{"environment": "prod", "risk_level": "medium"},
	})
	if err != nil || !allowDecision.Allowed || allowDecision.Decision != "allow" || allowDecision.MatchedBindingID != binding.ID {
		t.Fatalf("allow decision mismatch decision=%+v err=%v", allowDecision, err)
	}
	deny := AccessBinding{ID: "bind_platform_critical_deny", SubjectType: "team", SubjectID: "team_platform", ResourceType: "project", ResourceID: project.ID, Role: "operator", Effect: "deny", Conditions: map[string]any{"risk_level": "critical"}}
	if err := db.UpsertAccessBinding(ctx, deny); err != nil {
		t.Fatal(err)
	}
	denyDecision, err := db.EvaluateAccessBinding(ctx, AccessBindingEvaluateInput{
		SubjectType:  "team",
		SubjectID:    "team_platform",
		ResourceType: "project",
		ResourceID:   project.ID,
		Role:         "operator",
		Context:      map[string]any{"environment": "prod", "risk_level": "critical"},
	})
	if err != nil || denyDecision.Allowed || denyDecision.Decision != "deny" || denyDecision.MatchedBindingID != deny.ID {
		t.Fatalf("deny decision mismatch decision=%+v err=%v", denyDecision, err)
	}
	noMatch, err := db.EvaluateAccessBinding(ctx, AccessBindingEvaluateInput{
		SubjectType:  "team",
		SubjectID:    "team_platform",
		ResourceType: "project",
		ResourceID:   project.ID,
		Role:         "operator",
		Context:      map[string]any{"environment": "prod"},
	})
	if err != nil || noMatch.Allowed || noMatch.Decision != "no_match" || len(noMatch.MissingConditions) == 0 {
		t.Fatalf("no-match decision mismatch decision=%+v err=%v", noMatch, err)
	}
}
