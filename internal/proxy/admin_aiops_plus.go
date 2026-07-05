package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

func (s *Server) handleAIOpsProblemDetail(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/problems/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "problem id is required", "invalid_request_error", "missing_problem")
		return
	}
	problemID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	problem, incidents, ok := s.findAIOpsProblem(r, problemID)
	if !ok {
		writeOpenAIError(w, http.StatusNotFound, "problem not found", "invalid_request_error", "problem_not_found")
		return
	}
	switch action {
	case "", "detail":
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "problem", problemID, map[string]any{
			"problem": problem, "incidents": incidents,
			"timeline":       buildProblemTimeline(incidents, nil, nil),
			"confidence":     aiopsConfidenceBreakdown(problem),
			"runbook_draft":  aiopsRunbookDraft(problem, incidents),
			"affected_graph": aiopsAffectedGraph(problem, incidents),
		}))
	case "timeline":
		events, _ := s.db.ListK8sEvents(r.Context(), problem.ClusterID, 500)
		if problem.Namespace != "" {
			filtered := events[:0]
			for _, ev := range events {
				if ev.Namespace == problem.Namespace {
					filtered = append(filtered, ev)
				}
			}
			events = filtered
		}
		actions, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: problem.ClusterID, Limit: 200})
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "problem_timeline", problemID, map[string]any{"timeline": buildProblemTimeline(incidents, events, actions)}))
	case "runbook-draft":
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "runbook_draft", problemID, map[string]any{"runbook": aiopsRunbookDraft(problem, incidents)}))
	case "postmortem":
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "postmortem_draft", problemID, map[string]any{"postmortem": aiopsPostmortemDraft(problem, incidents)}))
	default:
		writeOpenAIError(w, http.StatusNotFound, "unknown problem subresource", "invalid_request_error", "unknown_problem_subresource")
	}
}

func (s *Server) findAIOpsProblem(r *http.Request, id string) (aiopsProblem, []store.K8sIncident, bool) {
	incidents, err := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{Status: firstNonEmptyStr(r.URL.Query().Get("status"), "open"), Limit: 500})
	if err != nil {
		return aiopsProblem{}, nil, false
	}
	problems := buildAIOpsProblems(incidents)
	for _, p := range problems {
		if p.ID == id || p.Key == id {
			matched := []store.K8sIncident{}
			for _, inc := range incidents {
				if strings.Join([]string{inc.ClusterID, inc.Namespace, firstNonEmptyStr(inc.Condition, inc.Kind+"/"+inc.Name)}, "|") == p.Key {
					matched = append(matched, inc)
				}
			}
			return p, matched, true
		}
	}
	return aiopsProblem{}, nil, false
}

func buildProblemTimeline(incidents []store.K8sIncident, events []store.K8sEvent, actions []store.K8sActionRequest) []map[string]any {
	rows := []map[string]any{}
	for _, inc := range incidents {
		rows = append(rows, map[string]any{
			"ts": inc.UpdatedAt, "type": "incident", "severity": inc.Severity,
			"title": inc.Title, "target": strings.Trim(strings.Join([]string{inc.Namespace, inc.Kind, inc.Name}, "/"), "/"),
			"evidence": inc.Evidence,
		})
	}
	for _, ev := range events {
		rows = append(rows, map[string]any{
			"ts": ev.LastSeen, "type": "event", "severity": strings.ToLower(ev.Type),
			"title": ev.Reason, "target": strings.Trim(strings.Join([]string{ev.Namespace, ev.InvolvedKind, ev.InvolvedName}, "/"), "/"),
			"message": ev.Message,
		})
	}
	for _, act := range actions {
		rows = append(rows, map[string]any{
			"ts": act.UpdatedAt, "type": "action", "severity": act.RiskLevel,
			"title": act.Action + " · " + act.Status, "target": strings.Trim(strings.Join([]string{act.Namespace, act.ResourceKind, act.ResourceName}, "/"), "/"),
			"result": act.Result,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return toString(rows[i]["ts"]) > toString(rows[j]["ts"])
	})
	if len(rows) > 200 {
		return rows[:200]
	}
	return rows
}

func aiopsConfidenceBreakdown(p aiopsProblem) map[string]any {
	missing := []string{}
	if p.EvidenceCount == 0 {
		missing = append(missing, "no_structured_evidence")
	}
	if p.Namespace == "" {
		missing = append(missing, "namespace_unknown")
	}
	return map[string]any{
		"score":          p.Confidence,
		"formula":        "35 + incident_count*15(max30) + evidence_count*5(max25) + severity_bonus",
		"incident_count": p.IncidentCount,
		"evidence_count": p.EvidenceCount,
		"severity":       p.Severity,
		"missing_data":   missing,
	}
}

func aiopsRunbookDraft(p aiopsProblem, incidents []store.K8sIncident) map[string]any {
	cond := strings.ToLower(p.Condition + " " + p.Title)
	steps := []string{"영향 서비스와 owner 확인", "최근 배포·설정 변경 확인", "관련 이벤트와 로그 evidence 확인"}
	actions := []map[string]any{}
	rollback := "최근 변경 revision이 있으면 Manifest Change Studio 또는 Stack rollback 후보를 검토"
	switch {
	case strings.Contains(cond, "crash") || strings.Contains(cond, "oom"):
		steps = append(steps, "previous log 마지막 200줄 확인", "resource limit과 최근 memory peak 확인")
		actions = append(actions, map[string]any{"action": "restart_owner", "approval_required": true, "risk": "medium"})
	case strings.Contains(cond, "image"):
		steps = append(steps, "image tag/digest와 imagePullSecret 확인", "registry 접근성과 인증서 확인")
		actions = append(actions, map[string]any{"action": "rollback_image", "approval_required": true, "risk": "high"})
	case strings.Contains(cond, "node") || strings.Contains(cond, "pressure"):
		steps = append(steps, "노드 condition과 allocatable 확인", "PDB 영향 분석 후 cordon/drain 여부 판단")
		actions = append(actions, map[string]any{"action": "cordon_node", "approval_required": true, "risk": "high"})
	default:
		actions = append(actions, map[string]any{"action": "collect_evidence_bundle", "approval_required": false, "risk": "low"})
	}
	return map[string]any{
		"problem_id":        p.ID,
		"steps":             steps,
		"candidate_actions": actions,
		"rollback_hint":     rollback,
		"approval_note":     "prod/high-risk 조치는 Action Center 승인 후 실행",
		"incident_ids":      incidentIDs(incidents),
	}
}

func aiopsPostmortemDraft(p aiopsProblem, incidents []store.K8sIncident) map[string]any {
	started, latest := "", ""
	for _, inc := range incidents {
		if started == "" || incidentTimeAfter(started, inc.OpenedAt) {
			started = inc.OpenedAt
		}
		if latest == "" || incidentTimeAfter(inc.UpdatedAt, latest) {
			latest = inc.UpdatedAt
		}
	}
	if latest == "" {
		latest = time.Now().UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"title":                p.Title,
		"summary":              "자동 초안: " + p.Condition + " problem이 " + p.Namespace + " 범위에서 감지되었습니다.",
		"impact":               map[string]any{"affected_resources": p.AffectedResources, "severity": p.Severity},
		"timeline_window":      map[string]string{"started_at": started, "latest_at": latest},
		"root_cause_candidate": p.Condition,
		"confidence":           aiopsConfidenceBreakdown(p),
		"followups":            []string{"owner runbook 보강", "반복 발생 조건 확인", "정책/알림 라우팅 조정"},
	}
}

func aiopsAffectedGraph(p aiopsProblem, incidents []store.K8sIncident) map[string]any {
	nodes := []map[string]any{{"id": "problem:" + p.ID, "kind": "Problem", "label": p.Title}}
	edges := []map[string]any{}
	seen := map[string]bool{}
	for _, inc := range incidents {
		id := strings.Trim(strings.Join([]string{inc.ClusterID, inc.Namespace, inc.Kind, inc.Name}, "/"), "/")
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		nodes = append(nodes, map[string]any{"id": id, "kind": inc.Kind, "namespace": inc.Namespace, "name": inc.Name, "severity": inc.Severity})
		edges = append(edges, map[string]any{"from": "problem:" + p.ID, "to": id, "type": "affects"})
	}
	return map[string]any{"nodes": nodes, "edges": edges}
}

func incidentIDs(incidents []store.K8sIncident) []string {
	out := make([]string, 0, len(incidents))
	for _, inc := range incidents {
		out = append(out, inc.ID)
	}
	sort.Strings(out)
	return out
}
