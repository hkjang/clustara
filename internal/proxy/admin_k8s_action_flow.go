package proxy

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"clustara/internal/store"
)

type k8sActionFlowItem struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Lane         string `json:"lane"`
	ClusterID    string `json:"cluster_id"`
	Namespace    string `json:"namespace"`
	Target       string `json:"target"`
	Status       string `json:"status"`
	RiskLevel    string `json:"risk_level"`
	Title        string `json:"title"`
	Detail       string `json:"detail"`
	RequestedBy  string `json:"requested_by"`
	NextAction   string `json:"next_action"`
	PrimaryLabel string `json:"primary_label"`
	Href         string `json:"href"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type k8sActionFlowLane struct {
	ID          string              `json:"id"`
	Label       string              `json:"label"`
	Description string              `json:"description"`
	Count       int                 `json:"count"`
	Items       []k8sActionFlowItem `json:"items"`
}

// handleK8sActionFlow gives operators one "what should I do next?" view across
// action requests, config changes, YAML changes, exec sessions, and debug requests.
// GET /admin/k8s/action-flow?cluster_id=&limit=
func (s *Server) handleK8sActionFlow(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	clusterID := strings.TrimSpace(q.Get("cluster_id"))
	limit := intParam(q.Get("limit"), 100)

	actions, err := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: clusterID, Limit: limit})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_flow_actions_failed")
		return
	}
	configChanges, err := s.db.ListK8sConfigChangeRequests(r.Context(), store.K8sConfigChangeFilter{ClusterID: clusterID, Limit: limit})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_flow_config_changes_failed")
		return
	}
	manifestChanges, err := s.db.ListK8sManifestChangeRequests(r.Context(), store.K8sManifestChangeFilter{ClusterID: clusterID, Limit: limit})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_flow_manifest_changes_failed")
		return
	}
	execSessions, err := s.db.ListK8sPodExecSessions(r.Context(), store.K8sPodExecSessionFilter{ClusterID: clusterID, Limit: limit})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_flow_exec_failed")
		return
	}
	debugSessions, err := s.db.ListK8sDebugSessions(r.Context(), store.K8sDebugSessionFilter{ClusterID: clusterID, Limit: limit})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_flow_debug_failed")
		return
	}

	items := make([]k8sActionFlowItem, 0, len(actions)+len(configChanges)+len(manifestChanges)+len(execSessions)+len(debugSessions))
	for _, a := range actions {
		items = append(items, flowItemFromAction(a))
	}
	for _, c := range configChanges {
		items = append(items, flowItemFromConfigChange(c))
	}
	for _, m := range manifestChanges {
		items = append(items, flowItemFromManifestChange(m))
	}
	for _, e := range execSessions {
		items = append(items, flowItemFromExecSession(e))
	}
	for _, d := range debugSessions {
		items = append(items, flowItemFromDebugSession(d))
	}
	sort.SliceStable(items, func(i, j int) bool {
		li, lj := lanePriority(items[i].Lane), lanePriority(items[j].Lane)
		if li != lj {
			return li < lj
		}
		return flowItemTime(items[i]) > flowItemTime(items[j])
	})

	lanes := buildActionFlowLanes(items)
	summary := map[string]int{"total": len(items)}
	for _, lane := range lanes {
		summary[lane.ID] = lane.Count
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":   items,
		"lanes":   lanes,
		"summary": summary,
		"note":    "요청 종류가 아니라 사용자의 다음 행동 기준으로 운영 작업을 묶은 흐름판입니다.",
	})
}

func flowItemFromAction(a store.K8sActionRequest) k8sActionFlowItem {
	lane, next, label := classifyActionFlow("action", a.Status, false)
	return k8sActionFlowItem{
		ID: a.ID, Kind: "action", Lane: lane, ClusterID: a.ClusterID, Namespace: a.Namespace,
		Target:       flowTarget(a.ResourceKind, a.Namespace, a.ResourceName),
		Status:       a.Status,
		RiskLevel:    a.RiskLevel,
		Title:        "K8s 액션 · " + a.Action,
		Detail:       firstNonEmpty(a.DryRunDiff, a.Result),
		RequestedBy:  a.RequestedBy,
		NextAction:   next,
		PrimaryLabel: label,
		Href:         flowHref("k8s-actions", a.ClusterID),
		CreatedAt:    a.CreatedAt,
		UpdatedAt:    a.UpdatedAt,
	}
}

func flowItemFromConfigChange(c store.K8sConfigChangeRequest) k8sActionFlowItem {
	lane, next, label := classifyActionFlow("config_change", c.Status, c.RequiresApproval)
	return k8sActionFlowItem{
		ID: c.ID, Kind: "config_change", Lane: lane, ClusterID: c.ClusterID, Namespace: c.Namespace,
		Target:       flowTarget(c.SourceKind, c.Namespace, c.SourceName),
		Status:       c.Status,
		RiskLevel:    c.RiskLevel,
		Title:        "Config 변경 · " + c.ChangeType,
		Detail:       firstNonEmpty(c.Reason, c.ProposedSummary, c.Result),
		RequestedBy:  c.RequestedBy,
		NextAction:   next,
		PrimaryLabel: label,
		Href:         flowHref("k8s-security", c.ClusterID),
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}

func flowItemFromManifestChange(m store.K8sManifestChangeRequest) k8sActionFlowItem {
	lane, next, label := classifyActionFlow("manifest_change", m.Status, m.RequiresApproval)
	return k8sActionFlowItem{
		ID: m.ID, Kind: "manifest_change", Lane: lane, ClusterID: m.ClusterID, Namespace: m.Namespace,
		Target:       flowTarget(m.Kind, m.Namespace, m.Name),
		Status:       m.Status,
		RiskLevel:    m.RiskLevel,
		Title:        "YAML 변경 · " + m.Kind,
		Detail:       firstNonEmpty(m.Reason, m.Result),
		RequestedBy:  m.CreatedBy,
		NextAction:   next,
		PrimaryLabel: label,
		Href:         flowHref("k8s-manifest-changes", m.ClusterID),
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

func flowItemFromExecSession(e store.K8sPodExecSession) k8sActionFlowItem {
	lane, next, label := classifyActionFlow("exec_session", e.Status, e.RequireApproval)
	return k8sActionFlowItem{
		ID: e.ID, Kind: "exec_session", Lane: lane, ClusterID: e.ClusterID, Namespace: e.Namespace,
		Target:       flowTarget("Pod", e.Namespace, e.Pod),
		Status:       e.Status,
		RiskLevel:    e.RiskLevel,
		Title:        "Pod Exec · " + firstNonEmpty(e.Container, "container"),
		Detail:       firstNonEmpty(e.Reason, e.Command, e.ErrorMessage),
		RequestedBy:  e.RequestedBy,
		NextAction:   next,
		PrimaryLabel: label,
		Href:         flowHref("k8s-settings", e.ClusterID),
		CreatedAt:    e.CreatedAt,
		UpdatedAt:    e.UpdatedAt,
	}
}

func flowItemFromDebugSession(d store.K8sDebugSession) k8sActionFlowItem {
	lane, next, label := classifyActionFlow("debug_session", d.Status, d.RequireApproval)
	return k8sActionFlowItem{
		ID: d.ID, Kind: "debug_session", Lane: lane, ClusterID: d.ClusterID, Namespace: d.Namespace,
		Target:       flowTarget("Pod", d.Namespace, d.Pod),
		Status:       d.Status,
		RiskLevel:    d.RiskLevel,
		Title:        "Debug Container · " + firstNonEmpty(d.Template, d.DebugImage),
		Detail:       firstNonEmpty(d.Reason, d.ManifestPreview),
		RequestedBy:  d.RequestedBy,
		NextAction:   next,
		PrimaryLabel: label,
		Href:         flowHref("k8s-settings", d.ClusterID),
		CreatedAt:    d.CreatedAt,
		UpdatedAt:    d.UpdatedAt,
	}
}

func classifyActionFlow(kind, status string, requiresApproval bool) (lane, nextAction, label string) {
	st := strings.ToLower(strings.TrimSpace(status))
	switch kind {
	case "manifest_change":
		switch st {
		case "draft":
			return "prepare", "validate", "검증"
		case "validated":
			if requiresApproval {
				return "approval", "approve", "승인"
			}
			return "ready", "apply", "적용"
		case "approval_required":
			return "approval", "approve", "승인"
		case "approved":
			return "ready", "apply", "적용"
		case "applied":
			return "verify", "verify", "검증확인"
		case "verified", "rolled_back":
			return "done", "closed", "완료"
		case "rejected", "failed", "verify_failed", "rollback_requested", "running":
			return "attention", "review", "확인"
		}
	case "config_change":
		switch st {
		case "pending":
			if requiresApproval {
				return "approval", "approve", "승인"
			}
			return "ready", "apply", "적용 기록"
		case "approval_required":
			return "approval", "approve", "승인"
		case "approved":
			return "ready", "apply", "적용 기록"
		case "applied":
			return "verify", "verify", "검증"
		case "verified":
			return "done", "closed", "완료"
		case "rejected", "failed", "verification_failed":
			return "attention", "review", "확인"
		}
	case "exec_session":
		switch st {
		case "pending_approval":
			return "approval", "approve", "승인"
		case "ready":
			return "ready", "execute", "실행"
		case "completed":
			return "done", "closed", "완료"
		case "running", "failed", "rejected", "denied", "expired":
			return "attention", "review", "확인"
		}
	case "debug_session":
		switch st {
		case "pending_approval":
			return "approval", "approve", "승인"
		case "ready":
			return "ready", "manual_apply", "주입 준비"
		case "completed", "applied":
			return "done", "closed", "완료"
		case "rejected", "failed", "blocked":
			return "attention", "review", "확인"
		}
	default:
		switch st {
		case "pending", "approval_required", "pending_approval":
			return "approval", "approve", "승인"
		case "approved":
			return "ready", "execute", "실행"
		case "executed":
			return "done", "closed", "완료"
		case "running", "failed", "rejected":
			return "attention", "review", "확인"
		}
	}
	return "prepare", "review", "검토"
}

func buildActionFlowLanes(items []k8sActionFlowItem) []k8sActionFlowLane {
	lanes := []k8sActionFlowLane{
		{ID: "attention", Label: "확인 필요", Description: "실패, 반려, 차단, 실행 중처럼 먼저 눈으로 확인할 작업"},
		{ID: "approval", Label: "승인 대기", Description: "운영자 또는 승인자가 결정해야 하는 요청"},
		{ID: "ready", Label: "실행 가능", Description: "승인되었거나 승인 없이 다음 단계로 진행 가능한 작업"},
		{ID: "verify", Label: "검증 필요", Description: "적용 이후 사후 확인이 필요한 변경"},
		{ID: "prepare", Label: "준비/검증", Description: "초안, 검증 전 상태의 요청"},
		{ID: "done", Label: "완료", Description: "이미 닫힌 최근 작업"},
	}
	index := make(map[string]int, len(lanes))
	for i := range lanes {
		index[lanes[i].ID] = i
	}
	for _, it := range items {
		i, ok := index[it.Lane]
		if !ok {
			i = index["prepare"]
		}
		lanes[i].Items = append(lanes[i].Items, it)
		lanes[i].Count++
	}
	return lanes
}

func lanePriority(lane string) int {
	switch lane {
	case "attention":
		return 0
	case "approval":
		return 1
	case "ready":
		return 2
	case "verify":
		return 3
	case "prepare":
		return 4
	case "done":
		return 5
	default:
		return 9
	}
}

func flowItemTime(it k8sActionFlowItem) string {
	return firstNonEmpty(it.UpdatedAt, it.CreatedAt)
}

func flowTarget(kind, namespace, name string) string {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "-"
	}
	return ns + "/" + strings.TrimSpace(kind) + "/" + strings.TrimSpace(name)
}

func flowHref(tab, clusterID string) string {
	if strings.TrimSpace(clusterID) == "" {
		return "#/" + tab
	}
	return "#/" + tab + "?cluster_id=" + url.QueryEscape(clusterID)
}
