package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// EnterpriseOrganization is the top-level tenant/governance boundary.
type EnterpriseOrganization struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SourceIDP   string `json:"source_idp"`
	SyncStatus  string `json:"sync_status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// EnterpriseWorkspace groups projects inside one organization.
type EnterpriseWorkspace struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// EnterpriseProject maps services, runtime resources, cost and policy scope to ownership.
type EnterpriseProject struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Environment string `json:"environment"`
	CostCenter  string `json:"cost_center"`
	OwnerTeamID string `json:"owner_team_id"`
	Criticality string `json:"criticality"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// CatalogEntity is the enterprise service/resource catalog entry used by IDP, FinOps and AIOps.
type CatalogEntity struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	ProjectID   string   `json:"project_id"`
	OwnerTeamID string   `json:"owner_team_id"`
	RuntimeRef  string   `json:"runtime_ref"`
	RepoURL     string   `json:"repo_url"`
	DocsURL     string   `json:"docs_url"`
	Criticality string   `json:"criticality"`
	Tags        []string `json:"tags"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// AccessBinding is the ABAC/RBAC bridge: a subject receives a role over a scoped resource
// with optional JSON conditions such as cluster, namespace, risk_level or business_hours.
type AccessBinding struct {
	ID           string         `json:"id"`
	SubjectType  string         `json:"subject_type"`
	SubjectID    string         `json:"subject_id"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Role         string         `json:"role"`
	Effect       string         `json:"effect"`
	Conditions   map[string]any `json:"conditions"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
}

type AccessBindingEvaluateInput struct {
	SubjectType  string         `json:"subject_type"`
	SubjectID    string         `json:"subject_id"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Role         string         `json:"role"`
	Context      map[string]any `json:"context"`
}

type AccessBindingDecision struct {
	Allowed            bool            `json:"allowed"`
	Decision           string          `json:"decision"`
	Reason             string          `json:"reason"`
	MatchedBindingID   string          `json:"matched_binding_id"`
	MatchedBindings    []AccessBinding `json:"matched_bindings"`
	MissingConditions  []string        `json:"missing_conditions"`
	EvaluatedSubject   string          `json:"evaluated_subject"`
	EvaluatedResource  string          `json:"evaluated_resource"`
	EvaluatedRole      string          `json:"evaluated_role"`
	EvaluatedCondition map[string]any  `json:"evaluated_condition"`
}

type EnterpriseWorkspaceFilter struct {
	OrganizationID string
}

type EnterpriseProjectFilter struct {
	WorkspaceID string
	OwnerTeamID string
	Environment string
}

type CatalogEntityFilter struct {
	Kind        string
	ProjectID   string
	OwnerTeamID string
	Limit       int
}

type AccessBindingFilter struct {
	SubjectType  string
	SubjectID    string
	ResourceType string
	ResourceID   string
	Role         string
	Limit        int
}

func (s *SQLStore) UpsertEnterpriseOrganization(ctx context.Context, org EnterpriseOrganization) error {
	now := nowString()
	if org.CreatedAt == "" {
		org.CreatedAt = now
	}
	org.UpdatedAt = now
	if org.SyncStatus == "" {
		org.SyncStatus = "manual"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO enterprise_organizations
		(id, name, description, source_idp, sync_status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name, description = excluded.description, source_idp = excluded.source_idp,
			sync_status = excluded.sync_status, updated_at = excluded.updated_at`),
		org.ID, org.Name, org.Description, org.SourceIDP, org.SyncStatus, org.CreatedAt, org.UpdatedAt)
	return err
}

func (s *SQLStore) ListEnterpriseOrganizations(ctx context.Context) ([]EnterpriseOrganization, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, COALESCE(description,''), COALESCE(source_idp,''), COALESCE(sync_status,''), created_at, updated_at
		FROM enterprise_organizations ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnterpriseOrganization{}
	for rows.Next() {
		var org EnterpriseOrganization
		if err := rows.Scan(&org.ID, &org.Name, &org.Description, &org.SourceIDP, &org.SyncStatus, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, org)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertEnterpriseWorkspace(ctx context.Context, ws EnterpriseWorkspace) error {
	now := nowString()
	if ws.CreatedAt == "" {
		ws.CreatedAt = now
	}
	ws.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO enterprise_workspaces
		(id, organization_id, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			organization_id = excluded.organization_id, name = excluded.name,
			description = excluded.description, updated_at = excluded.updated_at`),
		ws.ID, ws.OrganizationID, ws.Name, ws.Description, ws.CreatedAt, ws.UpdatedAt)
	return err
}

func (s *SQLStore) ListEnterpriseWorkspaces(ctx context.Context, f EnterpriseWorkspaceFilter) ([]EnterpriseWorkspace, error) {
	query := `SELECT id, organization_id, name, COALESCE(description,''), created_at, updated_at FROM enterprise_workspaces WHERE 1=1`
	args := []any{}
	if f.OrganizationID != "" {
		query += ` AND organization_id = ?`
		args = append(args, f.OrganizationID)
	}
	query += ` ORDER BY organization_id, name ASC`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnterpriseWorkspace{}
	for rows.Next() {
		var ws EnterpriseWorkspace
		if err := rows.Scan(&ws.ID, &ws.OrganizationID, &ws.Name, &ws.Description, &ws.CreatedAt, &ws.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, ws)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertEnterpriseProject(ctx context.Context, p EnterpriseProject) error {
	now := nowString()
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO enterprise_projects
		(id, workspace_id, name, environment, cost_center, owner_team_id, criticality, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			workspace_id = excluded.workspace_id, name = excluded.name, environment = excluded.environment,
			cost_center = excluded.cost_center, owner_team_id = excluded.owner_team_id,
			criticality = excluded.criticality, updated_at = excluded.updated_at`),
		p.ID, p.WorkspaceID, p.Name, p.Environment, p.CostCenter, p.OwnerTeamID, p.Criticality, p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *SQLStore) ListEnterpriseProjects(ctx context.Context, f EnterpriseProjectFilter) ([]EnterpriseProject, error) {
	query := `SELECT id, workspace_id, name, COALESCE(environment,''), COALESCE(cost_center,''), COALESCE(owner_team_id,''), COALESCE(criticality,''), created_at, updated_at
		FROM enterprise_projects WHERE 1=1`
	args := []any{}
	if f.WorkspaceID != "" {
		query += ` AND workspace_id = ?`
		args = append(args, f.WorkspaceID)
	}
	if f.OwnerTeamID != "" {
		query += ` AND owner_team_id = ?`
		args = append(args, f.OwnerTeamID)
	}
	if f.Environment != "" {
		query += ` AND environment = ?`
		args = append(args, f.Environment)
	}
	query += ` ORDER BY workspace_id, name ASC`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnterpriseProject{}
	for rows.Next() {
		var p EnterpriseProject
		if err := rows.Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Environment, &p.CostCenter, &p.OwnerTeamID, &p.Criticality, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertCatalogEntity(ctx context.Context, e CatalogEntity) error {
	now := nowString()
	if e.CreatedAt == "" {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO catalog_entities
		(id, kind, name, project_id, owner_team_id, runtime_ref, repo_url, docs_url, criticality, tags, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind, name = excluded.name, project_id = excluded.project_id,
			owner_team_id = excluded.owner_team_id, runtime_ref = excluded.runtime_ref,
			repo_url = excluded.repo_url, docs_url = excluded.docs_url, criticality = excluded.criticality,
			tags = excluded.tags, updated_at = excluded.updated_at`),
		e.ID, e.Kind, e.Name, e.ProjectID, e.OwnerTeamID, e.RuntimeRef, e.RepoURL, e.DocsURL, e.Criticality, joinTags(e.Tags), e.CreatedAt, e.UpdatedAt)
	return err
}

func (s *SQLStore) ListCatalogEntities(ctx context.Context, f CatalogEntityFilter) ([]CatalogEntity, error) {
	query := `SELECT id, kind, name, COALESCE(project_id,''), COALESCE(owner_team_id,''), COALESCE(runtime_ref,''), COALESCE(repo_url,''), COALESCE(docs_url,''), COALESCE(criticality,''), COALESCE(tags,''), created_at, updated_at
		FROM catalog_entities WHERE 1=1`
	args := []any{}
	if f.Kind != "" {
		query += ` AND lower(kind) = lower(?)`
		args = append(args, f.Kind)
	}
	if f.ProjectID != "" {
		query += ` AND project_id = ?`
		args = append(args, f.ProjectID)
	}
	if f.OwnerTeamID != "" {
		query += ` AND owner_team_id = ?`
		args = append(args, f.OwnerTeamID)
	}
	query += ` ORDER BY kind, name ASC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 200, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CatalogEntity{}
	for rows.Next() {
		var e CatalogEntity
		var tags string
		if err := rows.Scan(&e.ID, &e.Kind, &e.Name, &e.ProjectID, &e.OwnerTeamID, &e.RuntimeRef, &e.RepoURL, &e.DocsURL, &e.Criticality, &tags, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.Tags = parseTags(tags)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertAccessBinding(ctx context.Context, b AccessBinding) error {
	now := nowString()
	if b.CreatedAt == "" {
		b.CreatedAt = now
	}
	b.UpdatedAt = now
	if b.Effect == "" {
		b.Effect = "allow"
	}
	conditions, _ := json.Marshal(b.Conditions)
	if b.Conditions == nil {
		conditions = []byte("{}")
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO access_bindings
		(id, subject_type, subject_id, resource_type, resource_id, role, effect, conditions_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			subject_type = excluded.subject_type, subject_id = excluded.subject_id,
			resource_type = excluded.resource_type, resource_id = excluded.resource_id,
			role = excluded.role, effect = excluded.effect, conditions_json = excluded.conditions_json,
			updated_at = excluded.updated_at`),
		b.ID, b.SubjectType, b.SubjectID, b.ResourceType, b.ResourceID, b.Role, b.Effect, string(conditions), b.CreatedAt, b.UpdatedAt)
	return err
}

func (s *SQLStore) ListAccessBindings(ctx context.Context, f AccessBindingFilter) ([]AccessBinding, error) {
	query := `SELECT id, subject_type, subject_id, resource_type, resource_id, role, COALESCE(effect,''), COALESCE(conditions_json,'{}'), created_at, updated_at
		FROM access_bindings WHERE 1=1`
	args := []any{}
	addEq := func(col, value string) {
		if value != "" {
			query += ` AND ` + col + ` = ?`
			args = append(args, value)
		}
	}
	addEq("subject_type", f.SubjectType)
	addEq("subject_id", f.SubjectID)
	addEq("resource_type", f.ResourceType)
	addEq("resource_id", f.ResourceID)
	addEq("role", f.Role)
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 200, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccessBinding{}
	for rows.Next() {
		var b AccessBinding
		var rawConditions string
		if err := rows.Scan(&b.ID, &b.SubjectType, &b.SubjectID, &b.ResourceType, &b.ResourceID, &b.Role, &b.Effect, &rawConditions, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(rawConditions), &b.Conditions); err != nil {
			b.Conditions = map[string]any{}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLStore) EvaluateAccessBinding(ctx context.Context, in AccessBindingEvaluateInput) (AccessBindingDecision, error) {
	in.SubjectType = strings.ToLower(strings.TrimSpace(in.SubjectType))
	in.SubjectID = strings.TrimSpace(in.SubjectID)
	in.ResourceType = strings.ToLower(strings.TrimSpace(in.ResourceType))
	in.ResourceID = strings.TrimSpace(in.ResourceID)
	in.Role = strings.ToLower(strings.TrimSpace(in.Role))
	if in.Context == nil {
		in.Context = map[string]any{}
	}
	out := AccessBindingDecision{
		Allowed:            false,
		Decision:           "no_match",
		Reason:             "no access binding matched",
		MatchedBindings:    []AccessBinding{},
		MissingConditions:  []string{},
		EvaluatedSubject:   in.SubjectType + ":" + in.SubjectID,
		EvaluatedResource:  in.ResourceType + ":" + in.ResourceID,
		EvaluatedRole:      in.Role,
		EvaluatedCondition: in.Context,
	}
	bindings, err := s.ListAccessBindings(ctx, AccessBindingFilter{Limit: 1000})
	if err != nil {
		return out, err
	}
	conditionMisses := []string{}
	for _, b := range bindings {
		if !bindingFieldMatch(b.SubjectType, in.SubjectType) || !bindingFieldMatch(b.SubjectID, in.SubjectID) {
			continue
		}
		if !bindingFieldMatch(b.ResourceType, in.ResourceType) || !bindingFieldMatch(b.ResourceID, in.ResourceID) {
			continue
		}
		if !bindingFieldMatch(b.Role, in.Role) {
			continue
		}
		ok, misses := bindingConditionsMatch(b.Conditions, in.Context)
		if !ok {
			conditionMisses = append(conditionMisses, misses...)
			continue
		}
		out.MatchedBindings = append(out.MatchedBindings, b)
	}
	if len(out.MatchedBindings) == 0 {
		out.MissingConditions = uniqueStrings(conditionMisses)
		if len(out.MissingConditions) > 0 {
			out.Reason = "matched binding scope but context conditions did not pass"
		}
		return out, nil
	}
	for _, b := range out.MatchedBindings {
		if strings.EqualFold(strings.TrimSpace(b.Effect), "deny") {
			out.Allowed = false
			out.Decision = "deny"
			out.Reason = "deny binding matched"
			out.MatchedBindingID = b.ID
			return out, nil
		}
	}
	for _, b := range out.MatchedBindings {
		if b.Effect == "" || strings.EqualFold(strings.TrimSpace(b.Effect), "allow") {
			out.Allowed = true
			out.Decision = "allow"
			out.Reason = "allow binding matched"
			out.MatchedBindingID = b.ID
			return out, nil
		}
	}
	out.Reason = "matched bindings had no allow effect"
	return out, nil
}

func bindingFieldMatch(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	return pattern == "*" || strings.EqualFold(pattern, value)
}

func bindingConditionsMatch(conditions, context map[string]any) (bool, []string) {
	if len(conditions) == 0 {
		return true, nil
	}
	missing := []string{}
	for key, expected := range conditions {
		actual, ok := lookupConditionValue(context, key)
		if !ok {
			missing = append(missing, key)
			continue
		}
		if !bindingValueMatches(expected, actual) {
			missing = append(missing, key)
		}
	}
	return len(missing) == 0, missing
}

func lookupConditionValue(context map[string]any, key string) (any, bool) {
	if context == nil {
		return nil, false
	}
	if v, ok := context[key]; ok {
		return v, true
	}
	for k, v := range context {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func bindingValueMatches(expected, actual any) bool {
	switch v := expected.(type) {
	case []any:
		for _, item := range v {
			if bindingValueMatches(item, actual) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range v {
			if bindingValueMatches(item, actual) {
				return true
			}
		}
		return false
	case string:
		expectedText := strings.TrimSpace(v)
		actualText := strings.TrimSpace(bindingValueString(actual))
		if expectedText == "*" {
			return actualText != ""
		}
		return strings.EqualFold(expectedText, actualText)
	default:
		return strings.EqualFold(strings.TrimSpace(bindingValueString(v)), strings.TrimSpace(bindingValueString(actual)))
	}
}

func bindingValueString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case json.Number:
		return value.String()
	case fmt.Stringer:
		return value.String()
	default:
		return fmt.Sprint(value)
	}
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
