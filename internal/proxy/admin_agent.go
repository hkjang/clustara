package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
)

// handleAgentSuggestions returns context-aware suggested prompts + the resolved intent for the
// floating Ops Agent, derived from the current screen context (route + focused resource).
// GET /admin/agent/suggestions?route=&cluster_id=&namespace=&pod=&incident_id=&stack_id=&config_name=
func (s *Server) handleAgentSuggestions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	ctx := analyzer.AgentPageContext{
		Route:      strings.TrimSpace(q.Get("route")),
		ClusterID:  strings.TrimSpace(q.Get("cluster_id")),
		Namespace:  strings.TrimSpace(q.Get("namespace")),
		Pod:        strings.TrimSpace(q.Get("pod")),
		Kind:       strings.TrimSpace(q.Get("kind")),
		Name:       strings.TrimSpace(q.Get("name")),
		IncidentID: strings.TrimSpace(q.Get("incident_id")),
		StackID:    strings.TrimSpace(q.Get("stack_id")),
		ConfigName: strings.TrimSpace(q.Get("config_name")),
		Risk:       strings.TrimSpace(q.Get("risk")),
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"intent":      analyzer.RouteIntent(ctx.Route),
		"suggestions": analyzer.SuggestAgentPrompts(ctx),
		"note":        "현재 화면 맥락 기반 추천 질문입니다. 에이전트는 조회·분석·제안만 즉시 수행하고 변경은 승인 흐름으로 연결됩니다.",
	})
}
