package proxy

import (
	"net/http"
	"strings"
	"time"
)

const securityArtifactImportScope = "security:scan"

// authorizeSecurityArtifactImport accepts administrator credentials or a narrowly-scoped
// API/service-account key suitable for Trivy/Syft CI jobs. The key gains no other admin access.
func (s *Server) authorizeSecurityArtifactImport(w http.ResponseWriter, r *http.Request) bool {
	decision := s.evaluateAdminAccess(r)
	if decision.Allowed {
		return true
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		writeOpenAIError(w, http.StatusUnauthorized, "Bearer token is required; use an admin token or an API key with security:scan", "invalid_request_error", "authentication_required")
		return false
	}
	key, found, err := s.db.FindActiveAPIKeyByHash(r.Context(), hashProxyKey(token))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "failed to validate security import key", "server_error", "security_import_auth_failed")
		return false
	}
	if !found {
		if decision.Authenticated {
			writeOpenAIError(w, http.StatusForbidden, firstNonEmpty(decision.Reason, "security artifact import is not permitted"), "permission_error", "insufficient_scope")
		} else {
			writeOpenAIError(w, http.StatusUnauthorized, "invalid or expired admin/API key", "invalid_request_error", "invalid_api_key")
		}
		return false
	}
	if key.Status != "active" || !key.RevokedAt.IsZero() || (!key.ExpiresAt.IsZero() && !key.ExpiresAt.After(time.Now().UTC())) {
		s.auditAuthEvent(r.Context(), "api_key_denied", "", key.ID, key.Team, "security_artifact_import inactive_or_expired")
		writeOpenAIError(w, http.StatusUnauthorized, "API key is inactive, revoked, or expired", "invalid_request_error", "invalid_api_key")
		return false
	}
	if !ipAllowed(clientIP(r), key.AllowedIPs) {
		s.auditAuthEvent(r.Context(), "ip_denied", "", key.ID, key.Team, strings.Join(key.AllowedIPs, ","))
		writeOpenAIError(w, http.StatusForbidden, "API key is not allowed from this source IP", "permission_error", "ip_not_allowed")
		return false
	}
	if !hasScope(key.Scopes, securityArtifactImportScope) {
		s.auditAuthEvent(r.Context(), "scope_denied", "", key.ID, key.Team, securityArtifactImportScope+" path="+r.URL.Path)
		writeOpenAIError(w, http.StatusForbidden, "API key requires security:scan scope", "permission_error", "insufficient_scope")
		return false
	}
	return true
}
