package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleAgentSessions creates a floating-agent conversation session with the current page context.
// POST /admin/agent/sessions {route, context{...}}
func (s *Server) handleAgentSessions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		Route   string         `json:"route"`
		Context map[string]any `json:"context"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	ctxJSON, _ := json.Marshal(in.Context)
	sess := store.K8sAgentSession{ID: newID("k8sagent"), UserID: adminID(r), Route: strings.TrimSpace(in.Route), Context: string(ctxJSON)}
	if err := s.db.CreateK8sAgentSession(r.Context(), sess); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "agent_session_failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"session": sess})
}

// handleAgentSessionByID returns a session with its message history. GET /admin/agent/sessions/{id}
func (s *Server) handleAgentSessionByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/agent/sessions/"), "/")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "session id required", "invalid_request_error", "missing_session")
		return
	}
	sess, err := s.db.GetK8sAgentSession(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "session not found", "invalid_request_error", "session_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "agent_session_failed")
		return
	}
	msgs, _ := s.db.ListK8sAgentMessages(r.Context(), id, 200)
	writeJSON(w, http.StatusOK, map[string]any{"session": sess, "messages": msgs})
}

// handleAgentMessages processes a user question in a session: it resolves intent, grounds the answer
// in the cluster's RCA/events evidence (reusing the AI-ask path, read-only), persists both turns,
// and returns the answer + evidence + follow-up suggestions. Changes are never executed here.
// POST /admin/agent/messages {session_id, question}
func (s *Server) handleAgentMessages(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		SessionID string `json:"session_id"`
		Question  string `json:"question"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if strings.TrimSpace(in.SessionID) == "" || strings.TrimSpace(in.Question) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "session_id and question are required", "invalid_request_error", "missing_fields")
		return
	}
	sess, err := s.db.GetK8sAgentSession(r.Context(), in.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "session not found", "invalid_request_error", "session_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "agent_session_failed")
		return
	}

	var pctx analyzer.AgentPageContext
	_ = json.Unmarshal([]byte(sess.Context), &pctx)
	pctx.Route = firstNonEmpty(pctx.Route, sess.Route)
	intent := analyzer.ClassifyAgentIntent(in.Question, pctx.Route)

	// Ground the answer in current evidence (reuse the deterministic AI-ask gathering).
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: pctx.ClusterID, Limit: 2000})
	events, _ := s.db.ListK8sEvents(r.Context(), pctx.ClusterID, 500)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: pctx.ClusterID, Limit: 1000})
	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, time.Now().UTC(), 24*time.Hour)
	evidence := gatherK8sEvidence(pctx.Namespace, firstNonEmpty(pctx.Pod, pctx.Name), rca, events, nil)
	prompt := composeK8sAIPrompt(in.Question, evidence)

	toolPlan := analyzer.PlanAgentTools(intent, pctx)
	answer, llmErr := s.workflowChatStep(r, "clustara/auto", prompt, 1024, nil)
	llmOK := llmErr == nil && strings.TrimSpace(answer) != ""
	note := ""
	if !llmOK {
		answer = composeAgentFallbackAnswer(in.Question, evidence, toolPlan)
		if llmErr != nil {
			note = "LLM 호출 실패 — 근거 기반 요약으로 대체했습니다: " + llmErr.Error()
		} else {
			note = "LLM이 빈 답변을 반환하여 근거 기반 요약으로 대체했습니다."
		}
	}

	evJSON, _ := json.Marshal(evidence)
	_ = s.db.AppendK8sAgentMessage(r.Context(), store.K8sAgentMessage{ID: newID("k8samsg"), SessionID: sess.ID, Role: "user", Content: in.Question, Intent: intent, CreatedAt: nowK8sAgentTime()})
	_ = s.db.AppendK8sAgentMessage(r.Context(), store.K8sAgentMessage{ID: newID("k8samsg"), SessionID: sess.ID, Role: "agent", Content: answer, Intent: intent, Evidence: string(evJSON), LLMAvailable: llmOK, CreatedAt: nowK8sAgentTime()})

	s.auditAdmin(r, "k8s.agent.message", sess.ID, auditJSON(map[string]any{"intent": intent, "llm": llmOK, "tools": len(toolPlan)}))
	writeJSON(w, http.StatusOK, map[string]any{
		"intent": intent, "answer": answer, "evidence": evidence, "llm_available": llmOK,
		"tool_plan": toolPlan, "suggestions": analyzer.SuggestAgentPrompts(pctx), "note": note,
		"safety": "이 에이전트는 조회·분석만 수행합니다. 변경은 Action Center 승인 흐름으로 진행하세요.",
	})
}

func nowK8sAgentTime() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func composeAgentFallbackAnswer(question string, evidence []string, toolPlan []analyzer.AgentToolCall) string {
	var b strings.Builder
	b.WriteString("LLM 호출은 실패했지만, 현재 수집된 근거 기준으로 요약합니다.\n\n")
	b.WriteString("핵심 요약\n")
	if len(evidence) == 0 {
		b.WriteString("- 저장된 RCA/Warning 이벤트 근거에서 직접적인 이상 신호가 확인되지 않았습니다.\n")
		b.WriteString("- 실시간성이 의심되면 수집 상태에서 agent live/stale 여부와 마지막 수집 시각을 먼저 확인하세요.\n")
	} else {
		limit := min(len(evidence), 5)
		for i := 0; i < limit; i++ {
			b.WriteString("- ")
			b.WriteString(strings.TrimSpace(evidence[i]))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n권고 조치\n")
	b.WriteString("- 운영 홈과 장애 워룸에서 같은 대상의 최신 이벤트와 인시던트 상태를 확인하세요.\n")
	b.WriteString("- 수집 상태에서 realtime agent가 stale이면 클러스터 수집을 실행해 inventory/event를 보정하세요.\n")
	if strings.TrimSpace(question) != "" {
		b.WriteString("- 질문: ")
		b.WriteString(strings.TrimSpace(question))
		b.WriteString("\n")
	}
	if len(toolPlan) > 0 {
		tools := make([]string, 0, len(toolPlan))
		for _, tool := range toolPlan {
			if strings.TrimSpace(tool.Tool) != "" {
				tools = append(tools, tool.Tool)
			}
		}
		if len(tools) > 0 {
			b.WriteString("\n참고 도구: ")
			b.WriteString(strings.Join(tools, ", "))
			b.WriteString("\n")
		}
	}
	return strings.TrimSpace(b.String())
}

// handleAgentActionCard builds a proposed action card (the agent proposes, never executes). The
// returned card carries the exact action-request payload the operator submits to the Action Center
// approval flow. POST /admin/agent/action-cards {action, kind, namespace, name}
func (s *Server) handleAgentActionCard(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		Action    string `json:"action"`
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if strings.TrimSpace(in.Action) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "action is required", "invalid_request_error", "missing_action")
		return
	}
	card := analyzer.BuildAgentActionCard(in.Action, strings.TrimSpace(in.Kind), strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Name))
	// Approval Bridge: the payload the operator submits to the Action Center (POST
	// /admin/k8s/actions). The agent does NOT create it automatically.
	bridge := map[string]any{
		"approval_endpoint": "/admin/k8s/actions",
		"request_payload": map[string]any{
			"action": card.Action, "resource_kind": card.Kind, "namespace": card.Namespace, "resource_name": card.Name,
		},
	}
	s.auditAdmin(r, "k8s.agent.action_card", "", auditJSON(map[string]any{"action": card.Action, "target": card.Namespace + "/" + card.Kind + "/" + card.Name}))
	writeJSON(w, http.StatusOK, map[string]any{
		"card": card, "approval_bridge": bridge,
		"safety": "에이전트는 조치를 실행하지 않습니다. 이 카드를 Action Center 승인 흐름으로 제출하세요.",
	})
}

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
	intent := analyzer.RouteIntent(ctx.Route)
	writeJSON(w, http.StatusOK, map[string]any{
		"intent":      intent,
		"suggestions": analyzer.SuggestAgentPrompts(ctx),
		"tool_plan":   analyzer.PlanAgentTools(intent, ctx),
		"note":        "현재 화면 맥락 기반 추천 질문입니다. 에이전트는 조회·분석·제안만 즉시 수행하고 변경은 승인 흐름으로 연결됩니다.",
	})
}
