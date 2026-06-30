package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"clustara/internal/store"
)

var validMaskingLevels = map[string]bool{"none": true, "partial": true, "strict": true}
var validApprovalRules = map[string]bool{"inherit": true, "always": true, "never": true}

// handleMCPToolScopes lists or upserts MCP tool scope policies (CLU-REQ-11).
// GET/POST /admin/mcp/tool-scopes
func (s *Server) handleMCPToolScopes(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		scopes, err := s.db.ListMCPToolScopes(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "mcp_scopes_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool_scopes": scopes,
			"note": "도구별 최소권한 정책입니다(opt-in). 미설정 도구는 기존 동작을 유지합니다. role/namespace/cluster 허용 목록은 비우면 전체 허용입니다."})
	case http.MethodPost:
		var p struct {
			ServerLabel       string `json:"server_label"`
			ToolName          string `json:"tool_name"`
			AllowedRoles      string `json:"allowed_roles"`
			AllowedNamespaces string `json:"allowed_namespaces"`
			AllowedClusters   string `json:"allowed_clusters"`
			MaskingLevel      string `json:"masking_level"`
			ApprovalRule      string `json:"approval_rule"`
			Enabled           *bool  `json:"enabled"`
			Note              string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		p.ServerLabel = coalesceStr(strings.TrimSpace(p.ServerLabel), "*")
		p.ToolName = coalesceStr(strings.TrimSpace(p.ToolName), "*")
		p.MaskingLevel = coalesceStr(strings.ToLower(strings.TrimSpace(p.MaskingLevel)), "none")
		p.ApprovalRule = coalesceStr(strings.ToLower(strings.TrimSpace(p.ApprovalRule)), "inherit")
		if !validMaskingLevels[p.MaskingLevel] {
			writeOpenAIError(w, http.StatusBadRequest, "masking_level must be none/partial/strict", "invalid_request_error", "invalid_masking")
			return
		}
		if !validApprovalRules[p.ApprovalRule] {
			writeOpenAIError(w, http.StatusBadRequest, "approval_rule must be inherit/always/never", "invalid_request_error", "invalid_approval_rule")
			return
		}
		enabled := true
		if p.Enabled != nil {
			enabled = *p.Enabled
		}
		scope := store.MCPToolScope{
			ServerLabel: p.ServerLabel, ToolName: p.ToolName,
			AllowedRoles: strings.TrimSpace(p.AllowedRoles), AllowedNamespaces: strings.TrimSpace(p.AllowedNamespaces),
			AllowedClusters: strings.TrimSpace(p.AllowedClusters), MaskingLevel: p.MaskingLevel,
			ApprovalRule: p.ApprovalRule, Enabled: enabled, Note: strings.TrimSpace(p.Note),
		}
		if err := s.db.UpsertMCPToolScope(r.Context(), scope); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "mcp_scope_save_failed")
			return
		}
		s.auditAdmin(r, "mcp.tool_scope.upsert", "", auditJSON(map[string]any{"server": scope.ServerLabel, "tool": scope.ToolName, "roles": scope.AllowedRoles}))
		writeJSON(w, http.StatusCreated, map[string]any{"tool_scope": scope})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleMCPToolScopeByID deletes a tool scope. DELETE /admin/mcp/tool-scopes/{server}/{tool}
func (s *Server) handleMCPToolScopeByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodDelete {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/mcp/tool-scopes/"), "/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "path must be /admin/mcp/tool-scopes/{server}/{tool}", "invalid_request_error", "invalid_path")
		return
	}
	if err := s.db.DeleteMCPToolScope(r.Context(), parts[0], parts[1]); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "mcp_scope_delete_failed")
		return
	}
	s.auditAdmin(r, "mcp.tool_scope.delete", auditJSON(map[string]string{"server": parts[0], "tool": parts[1]}), "")
	writeJSON(w, http.StatusOK, map[string]string{"server_label": parts[0], "tool_name": parts[1], "status": "deleted"})
}
