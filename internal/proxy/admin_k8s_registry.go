package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"clustara/internal/analyzer"
)

// handleK8sPullSecret generates a ready-to-apply imagePullSecret manifest for a private registry.
// The credential is used only to assemble the returned manifest and is NEVER persisted or audited.
// POST /admin/k8s/registries/pull-secret {name, namespace, registry, username, password, email}
func (s *Server) handleK8sPullSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var p struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Registry  string `json:"registry"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		Email     string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	name := strings.TrimSpace(p.Name)
	if name == "" || strings.TrimSpace(p.Username) == "" || p.Password == "" {
		writeOpenAIError(w, http.StatusBadRequest, "name, username and password are required", "invalid_request_error", "missing_fields")
		return
	}
	manifest := analyzer.BuildPullSecretManifest(name, strings.TrimSpace(p.Namespace), strings.TrimSpace(p.Registry), p.Username, p.Password, strings.TrimSpace(p.Email))
	// Audit WITHOUT the credential — only the non-sensitive metadata.
	s.auditAdmin(r, "k8s.registry.pull_secret", "", auditJSON(map[string]string{
		"name": name, "namespace": strings.TrimSpace(p.Namespace), "registry": strings.TrimSpace(p.Registry), "username": p.Username,
	}))
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest": manifest,
		"note":     "이 매니페스트는 자격증명을 포함하므로 서버에 저장되지 않습니다. 안전한 경로로 클러스터에 적용하세요. `imagePullSecrets`에 이 Secret 이름을 참조하세요.",
	})
}
