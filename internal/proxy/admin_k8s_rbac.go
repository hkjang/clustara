package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
)

// handleK8sRBAC serves the operational RBAC reference: the capability catalog, the role→capability
// matrix, and a preflight check (role+capability → allowed). Read-only reference (does not change
// auth enforcement). GET /admin/k8s/rbac  ·  GET /admin/k8s/rbac/check?role=&capability=
func (s *Server) handleK8sRBAC(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/check") {
		q := r.URL.Query()
		role := strings.TrimSpace(q.Get("role"))
		capability := strings.TrimSpace(q.Get("capability"))
		if role == "" || capability == "" {
			writeOpenAIError(w, http.StatusBadRequest, "role and capability are required", "invalid_request_error", "missing_params")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"role": role, "capability": capability, "allowed": analyzer.RoleHasCapability(role, capability),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"capabilities": analyzer.K8sCapabilityCatalog(),
		"roles":        analyzer.K8sRoles(),
		"matrix":       analyzer.RoleMatrix(),
		"note":         "운영 RBAC 참조 모델입니다 — 역할별 허용 작업(capability)을 정의·점검합니다. 실제 인증 강제는 기존 admin 토큰/스코프를 따릅니다.",
	})
}
