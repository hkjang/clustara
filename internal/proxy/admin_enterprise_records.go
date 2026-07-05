package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/store"
)

func (s *Server) listEnterpriseRecords(w http.ResponseWriter, r *http.Request, kind string) ([]store.EnterpriseRecord, bool) {
	rows, err := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{
		Kind:        kind,
		ScopeType:   strings.TrimSpace(r.URL.Query().Get("scope_type")),
		ScopeID:     strings.TrimSpace(r.URL.Query().Get("scope_id")),
		Status:      strings.TrimSpace(r.URL.Query().Get("status")),
		OwnerTeamID: strings.TrimSpace(r.URL.Query().Get("owner_team_id")),
		SourceRef:   strings.TrimSpace(r.URL.Query().Get("source_ref")),
		Limit:       intParam(r.URL.Query().Get("limit"), 200),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_records_failed")
		return nil, false
	}
	return rows, true
}

func (s *Server) upsertEnterpriseRecordFromRequest(w http.ResponseWriter, r *http.Request, kind, defaultStatus, auditAction string) (store.EnterpriseRecord, bool) {
	var rec store.EnterpriseRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return store.EnterpriseRecord{}, false
	}
	rec.Kind = kind
	rec.Name = strings.TrimSpace(rec.Name)
	if rec.ID == "" {
		rec.ID = newID(recordIDPrefix(kind))
	}
	if rec.Status == "" {
		rec.Status = defaultStatus
	}
	if rec.EvidenceID == "" {
		rec.EvidenceID = "ev_" + audit.HashText(strings.Join([]string{kind, rec.ScopeType, rec.ScopeID, rec.Name, time.Now().UTC().Format(time.RFC3339Nano)}, "|"))[:16]
	}
	if rec.CreatedBy == "" {
		rec.CreatedBy = adminID(r)
	}
	if rec.Payload == nil {
		rec.Payload = map[string]any{}
	}
	rec.Payload["evidence_id"] = rec.EvidenceID
	if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_record_save_failed")
		return store.EnterpriseRecord{}, false
	}
	s.auditAdmin(r, auditAction, "", auditJSON(rec))
	return rec, true
}

func recordIDPrefix(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch {
	case strings.Contains(kind, "evidence"):
		return "evid"
	case strings.Contains(kind, "ticket"):
		return "ticket"
	case strings.Contains(kind, "risk"):
		return "risk"
	case strings.Contains(kind, "billing"):
		return "bill"
	case strings.Contains(kind, "git"):
		return "git"
	case strings.Contains(kind, "calendar"):
		return "cal"
	default:
		return "erec"
	}
}

func enterpriseEnvelope(r *http.Request, scopeType, scopeID string, payload map[string]any) map[string]any {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["generated_at"] = time.Now().UTC().Format(time.RFC3339)
	payload["scope"] = map[string]any{"type": scopeType, "id": scopeID}
	payload["warnings"] = []string{}
	return payload
}

func (s *Server) handleEnterpriseEnforcementStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	bindings, _ := s.db.ListAccessBindings(r.Context(), store.AccessBindingFilter{Limit: 1})
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_enabled":       s.cfg.Auth.Enabled,
		"enforced_when_auth": true,
		"admin_bypass_roles": []string{"super_admin", "admin"},
		"bindings_present":   len(bindings) > 0,
		"guarded_prefixes":   []string{"/admin/k8s", "/admin/fleet", "/admin/security", "/admin/problems", "/admin/finops", "/admin/gitops", "/admin/governance", "/admin/orgs", "/admin/workspaces", "/admin/projects", "/admin/catalog", "/admin/access-bindings"},
		"excluded_prefixes":  []string{"/admin/ai"},
	})
}

func (s *Server) handleCatalogOwnershipMap(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	ownership, _ := s.db.ListK8sNamespaceOwnership(r.Context(), clusterID, "")
	entities, _ := s.db.ListCatalogEntities(r.Context(), store.CatalogEntityFilter{Limit: 1000})
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	ownedNS := map[string]bool{}
	for _, o := range ownership {
		ownedNS[o.ClusterID+"/"+o.Namespace] = true
	}
	coveredRuntime := map[string]bool{}
	for _, e := range entities {
		if e.RuntimeRef != "" {
			coveredRuntime[e.RuntimeRef] = true
		}
	}
	ownerlessNamespaces := []string{}
	ownerlessWorkloads := []string{}
	for _, it := range items {
		if it.Namespace != "" && !ownedNS[it.ClusterID+"/"+it.Namespace] {
			key := it.ClusterID + "/" + it.Namespace
			if !containsString(ownerlessNamespaces, key) {
				ownerlessNamespaces = append(ownerlessNamespaces, key)
			}
		}
		if it.Kind == "Deployment" || it.Kind == "StatefulSet" || it.Kind == "DaemonSet" {
			ref := it.ClusterID + "/" + it.Namespace + "/" + it.Kind + "/" + it.Name
			if !coveredRuntime[ref] {
				ownerlessWorkloads = append(ownerlessWorkloads, ref)
			}
		}
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "cluster", clusterID, map[string]any{
		"namespace_ownership": ownership,
		"catalog_entities":    entities,
		"governance_findings": map[string]any{
			"ownerless_namespaces": ownerlessNamespaces,
			"ownerless_workloads":  ownerlessWorkloads,
		},
	}))
}
