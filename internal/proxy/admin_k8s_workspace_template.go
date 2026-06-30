package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
)

// Workspace Template (CLU-NEXT-10): generates the governed-namespace manifest set; the operator
// applies it via Stack Apply (validation + policy + approval). Pure generator — no cluster mutation.

// handleK8sWorkspaceTemplate generates a new-workspace manifest bundle.
// GET /admin/k8s/workspace-template?namespace=&team=&environment=&cpu=&mem=&pods=&default_deny=
func (s *Server) handleK8sWorkspaceTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	tpl := analyzer.GenerateWorkspaceTemplate(analyzer.WorkspaceTemplateRequest{
		Namespace:   strings.TrimSpace(q.Get("namespace")),
		OwnerTeam:   strings.TrimSpace(q.Get("team")),
		Environment: strings.TrimSpace(q.Get("environment")),
		CostCenter:  strings.TrimSpace(q.Get("cost_center")),
		CPUQuota:    strings.TrimSpace(q.Get("cpu")),
		MemQuota:    strings.TrimSpace(q.Get("mem")),
		PodQuota:    strings.TrimSpace(q.Get("pods")),
		DefaultDeny: q.Get("default_deny") == "true" || q.Get("default_deny") == "1",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"template":     tpl,
		"apply_bridge": map[string]any{"submit_to": "/admin/k8s/stacks", "method": "save-then-apply", "note": "앱 배포(Stack)로 저장→검증(dry-run)→승인→적용하세요."},
		"note":         "신규 Workspace 표준 매니페스트(Namespace·Quota·LimitRange·NetworkPolicy)입니다. Clustara가 직접 생성하지 않습니다.",
	})
}
