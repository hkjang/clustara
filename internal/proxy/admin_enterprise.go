package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"clustara/internal/audit"
	"clustara/internal/store"
)

func (s *Server) handleEnterpriseOrganizations(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		orgs, err := s.db.ListEnterpriseOrganizations(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_orgs_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
	case http.MethodPost:
		var org store.EnterpriseOrganization
		if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		org.Name = strings.TrimSpace(org.Name)
		if org.Name == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name is required", "invalid_request_error", "missing_name")
			return
		}
		if strings.TrimSpace(org.ID) == "" {
			org.ID = "org_" + audit.HashText(strings.ToLower(org.Name))[:16]
		}
		if strings.TrimSpace(org.SyncStatus) == "" {
			org.SyncStatus = "manual"
		}
		if err := s.db.UpsertEnterpriseOrganization(r.Context(), org); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_org_save_failed")
			return
		}
		s.auditAdmin(r, "enterprise.org.upsert", "", auditJSON(org))
		writeJSON(w, http.StatusCreated, map[string]any{"organization": org})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleEnterpriseWorkspaces(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		workspaces, err := s.db.ListEnterpriseWorkspaces(r.Context(), store.EnterpriseWorkspaceFilter{OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id"))})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_workspaces_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"workspaces": workspaces})
	case http.MethodPost:
		var ws store.EnterpriseWorkspace
		if err := json.NewDecoder(r.Body).Decode(&ws); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		ws.OrganizationID = strings.TrimSpace(ws.OrganizationID)
		ws.Name = strings.TrimSpace(ws.Name)
		if ws.OrganizationID == "" || ws.Name == "" {
			writeOpenAIError(w, http.StatusBadRequest, "organization_id and name are required", "invalid_request_error", "missing_fields")
			return
		}
		if !s.enterpriseOrganizationExists(r, ws.OrganizationID) {
			writeOpenAIError(w, http.StatusBadRequest, "unknown organization_id", "invalid_request_error", "unknown_organization")
			return
		}
		if strings.TrimSpace(ws.ID) == "" {
			ws.ID = "ws_" + audit.HashText(ws.OrganizationID + "|" + strings.ToLower(ws.Name))[:16]
		}
		if err := s.db.UpsertEnterpriseWorkspace(r.Context(), ws); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_workspace_save_failed")
			return
		}
		s.auditAdmin(r, "enterprise.workspace.upsert", "", auditJSON(ws))
		writeJSON(w, http.StatusCreated, map[string]any{"workspace": ws})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleEnterpriseProjects(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		projects, err := s.db.ListEnterpriseProjects(r.Context(), store.EnterpriseProjectFilter{
			WorkspaceID: strings.TrimSpace(q.Get("workspace_id")),
			OwnerTeamID: strings.TrimSpace(q.Get("owner_team_id")),
			Environment: strings.TrimSpace(q.Get("environment")),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_projects_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
	case http.MethodPost:
		var p store.EnterpriseProject
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		p.WorkspaceID = strings.TrimSpace(p.WorkspaceID)
		p.Name = strings.TrimSpace(p.Name)
		p.OwnerTeamID = strings.TrimSpace(p.OwnerTeamID)
		if p.WorkspaceID == "" || p.Name == "" {
			writeOpenAIError(w, http.StatusBadRequest, "workspace_id and name are required", "invalid_request_error", "missing_fields")
			return
		}
		if !s.enterpriseWorkspaceExists(r, p.WorkspaceID) {
			writeOpenAIError(w, http.StatusBadRequest, "unknown workspace_id", "invalid_request_error", "unknown_workspace")
			return
		}
		if p.OwnerTeamID != "" {
			if _, found, err := s.db.AuthTeamByIDOrName(r.Context(), p.OwnerTeamID); err != nil || !found {
				writeOpenAIError(w, http.StatusBadRequest, "unknown owner_team_id", "invalid_request_error", "unknown_team")
				return
			}
		}
		if strings.TrimSpace(p.ID) == "" {
			p.ID = "prj_" + audit.HashText(p.WorkspaceID + "|" + strings.ToLower(p.Name))[:16]
		}
		if err := s.db.UpsertEnterpriseProject(r.Context(), p); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_project_save_failed")
			return
		}
		s.auditAdmin(r, "enterprise.project.upsert", "", auditJSON(p))
		writeJSON(w, http.StatusCreated, map[string]any{"project": p})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleCatalogEntities(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		entities, err := s.db.ListCatalogEntities(r.Context(), store.CatalogEntityFilter{
			Kind:        strings.TrimSpace(q.Get("kind")),
			ProjectID:   strings.TrimSpace(q.Get("project_id")),
			OwnerTeamID: strings.TrimSpace(q.Get("owner_team_id")),
			Limit:       intParam(q.Get("limit"), 200),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_entities_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entities": entities})
	case http.MethodPost:
		var e store.CatalogEntity
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		e.Kind = strings.TrimSpace(e.Kind)
		e.Name = strings.TrimSpace(e.Name)
		e.OwnerTeamID = strings.TrimSpace(e.OwnerTeamID)
		if e.Kind == "" || e.Name == "" {
			writeOpenAIError(w, http.StatusBadRequest, "kind and name are required", "invalid_request_error", "missing_fields")
			return
		}
		if e.ProjectID != "" && !s.enterpriseProjectExists(r, e.ProjectID) {
			writeOpenAIError(w, http.StatusBadRequest, "unknown project_id", "invalid_request_error", "unknown_project")
			return
		}
		if e.OwnerTeamID != "" {
			if _, found, err := s.db.AuthTeamByIDOrName(r.Context(), e.OwnerTeamID); err != nil || !found {
				writeOpenAIError(w, http.StatusBadRequest, "unknown owner_team_id", "invalid_request_error", "unknown_team")
				return
			}
		}
		if strings.TrimSpace(e.ID) == "" {
			e.ID = "cat_" + audit.HashText(strings.ToLower(e.Kind) + "|" + strings.ToLower(e.Name) + "|" + e.ProjectID)[:16]
		}
		if err := s.db.UpsertCatalogEntity(r.Context(), e); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_entity_save_failed")
			return
		}
		s.auditAdmin(r, "catalog.entity.upsert", "", auditJSON(e))
		writeJSON(w, http.StatusCreated, map[string]any{"entity": e})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleAccessBindingEvaluate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in store.AccessBindingEvaluateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	in.SubjectType = strings.ToLower(strings.TrimSpace(in.SubjectType))
	in.SubjectID = strings.TrimSpace(in.SubjectID)
	in.ResourceType = strings.ToLower(strings.TrimSpace(in.ResourceType))
	in.ResourceID = strings.TrimSpace(in.ResourceID)
	in.Role = strings.ToLower(strings.TrimSpace(in.Role))
	if in.SubjectType == "" || in.SubjectID == "" || in.ResourceType == "" || in.ResourceID == "" || in.Role == "" {
		writeOpenAIError(w, http.StatusBadRequest, "subject, resource and role are required", "invalid_request_error", "missing_fields")
		return
	}
	if in.Context == nil {
		in.Context = map[string]any{}
	}
	decision, err := s.db.EvaluateAccessBinding(r.Context(), in)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "access_binding_evaluate_failed")
		return
	}
	s.auditAdmin(r, "access.binding.evaluate", "", auditJSON(map[string]any{
		"subject":  decision.EvaluatedSubject,
		"resource": decision.EvaluatedResource,
		"role":     decision.EvaluatedRole,
		"decision": decision.Decision,
		"allowed":  decision.Allowed,
		"binding":  decision.MatchedBindingID,
	}))
	writeJSON(w, http.StatusOK, map[string]any{"decision": decision})
}

func (s *Server) handleAccessBindings(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		bindings, err := s.db.ListAccessBindings(r.Context(), store.AccessBindingFilter{
			SubjectType:  strings.TrimSpace(q.Get("subject_type")),
			SubjectID:    strings.TrimSpace(q.Get("subject_id")),
			ResourceType: strings.TrimSpace(q.Get("resource_type")),
			ResourceID:   strings.TrimSpace(q.Get("resource_id")),
			Role:         strings.TrimSpace(q.Get("role")),
			Limit:        intParam(q.Get("limit"), 200),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "access_bindings_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_bindings": bindings})
	case http.MethodPost:
		var b store.AccessBinding
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		b.SubjectType = strings.ToLower(strings.TrimSpace(b.SubjectType))
		b.SubjectID = strings.TrimSpace(b.SubjectID)
		b.ResourceType = strings.ToLower(strings.TrimSpace(b.ResourceType))
		b.ResourceID = strings.TrimSpace(b.ResourceID)
		b.Role = strings.ToLower(strings.TrimSpace(b.Role))
		b.Effect = strings.ToLower(strings.TrimSpace(b.Effect))
		if b.SubjectType == "" || b.SubjectID == "" || b.ResourceType == "" || b.ResourceID == "" || b.Role == "" {
			writeOpenAIError(w, http.StatusBadRequest, "subject, resource and role are required", "invalid_request_error", "missing_fields")
			return
		}
		if b.Effect == "" {
			b.Effect = "allow"
		}
		if b.Effect != "allow" && b.Effect != "deny" {
			writeOpenAIError(w, http.StatusBadRequest, "effect must be allow or deny", "invalid_request_error", "invalid_effect")
			return
		}
		if b.SubjectType == "team" {
			if _, found, err := s.db.AuthTeamByIDOrName(r.Context(), b.SubjectID); err != nil || !found {
				writeOpenAIError(w, http.StatusBadRequest, "unknown subject team", "invalid_request_error", "unknown_team")
				return
			}
		}
		if strings.TrimSpace(b.ID) == "" {
			b.ID = "bind_" + audit.HashText(strings.Join([]string{b.SubjectType, b.SubjectID, b.ResourceType, b.ResourceID, b.Role, b.Effect}, "|"))[:16]
		}
		if b.Conditions == nil {
			b.Conditions = map[string]any{}
		}
		if err := s.db.UpsertAccessBinding(r.Context(), b); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "access_binding_save_failed")
			return
		}
		s.auditAdmin(r, "access.binding.upsert", "", auditJSON(b))
		writeJSON(w, http.StatusCreated, map[string]any{"access_binding": b})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) enterpriseOrganizationExists(r *http.Request, id string) bool {
	orgs, err := s.db.ListEnterpriseOrganizations(r.Context())
	if err != nil {
		return false
	}
	for _, org := range orgs {
		if org.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) enterpriseWorkspaceExists(r *http.Request, id string) bool {
	workspaces, err := s.db.ListEnterpriseWorkspaces(r.Context(), store.EnterpriseWorkspaceFilter{})
	if err != nil {
		return false
	}
	for _, ws := range workspaces {
		if ws.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) enterpriseProjectExists(r *http.Request, id string) bool {
	projects, err := s.db.ListEnterpriseProjects(r.Context(), store.EnterpriseProjectFilter{})
	if err != nil {
		return false
	}
	for _, project := range projects {
		if project.ID == id {
			return true
		}
	}
	return false
}
