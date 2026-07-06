package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

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
	AgeSeconds   int64  `json:"age_seconds"`
	AgeLabel     string `json:"age_label"`
	SLAStatus    string `json:"sla_status"`
	SLAReason    string `json:"sla_reason"`
	ActorHint    string `json:"actor_hint"`
	ActorReason  string `json:"actor_reason"`
	HandoffText  string `json:"handoff_text"`
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
	now := time.Now().UTC()
	for i := range items {
		items[i] = annotateActionFlowSLA(items[i], now)
		items[i] = annotateActionFlowActor(items[i])
		items[i].HandoffText = actionFlowHandoffText(items[i])
	}
	sort.SliceStable(items, func(i, j int) bool {
		li, lj := lanePriority(items[i].Lane), lanePriority(items[j].Lane)
		if li != lj {
			return li < lj
		}
		si, sj := flowSLAPriority(items[i].SLAStatus), flowSLAPriority(items[j].SLAStatus)
		if si != sj {
			return si < sj
		}
		return flowItemTime(items[i]) > flowItemTime(items[j])
	})

	lanes := buildActionFlowLanes(items)
	summary := map[string]int{"total": len(items), "sla_warning": 0, "sla_breached": 0}
	for _, lane := range lanes {
		summary[lane.ID] = lane.Count
	}
	for _, it := range items {
		switch it.SLAStatus {
		case "warning":
			summary["sla_warning"]++
		case "breached":
			summary["sla_breached"]++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           items,
		"lanes":           lanes,
		"summary":         summary,
		"handoff_summary": actionFlowHandoffSummary(items, summary, 8),
		"generated_at":    now.Format(time.RFC3339Nano),
		"note":            "요청 종류가 아니라 사용자의 다음 행동 기준으로 운영 작업을 묶은 흐름판입니다.",
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

func annotateActionFlowSLA(it k8sActionFlowItem, now time.Time) k8sActionFlowItem {
	ageBase := actionFlowAgeBase(it)
	if ts, ok := parseActionFlowTime(ageBase); ok {
		age := now.Sub(ts)
		if age < 0 {
			age = 0
		}
		it.AgeSeconds = int64(age.Seconds())
		it.AgeLabel = actionFlowAgeLabel(age)
	} else {
		it.AgeLabel = "-"
	}
	warn, breach := actionFlowSLAThresholds(it.Lane)
	switch {
	case breach > 0 && time.Duration(it.AgeSeconds)*time.Second >= breach:
		it.SLAStatus = "breached"
	case warn > 0 && time.Duration(it.AgeSeconds)*time.Second >= warn:
		it.SLAStatus = "warning"
	default:
		it.SLAStatus = "ok"
	}
	it.SLAReason = actionFlowSLAReason(it.Lane, it.SLAStatus, it.AgeLabel)
	return it
}

func actionFlowAgeBase(it k8sActionFlowItem) string {
	switch it.Lane {
	case "approval", "prepare":
		return firstNonEmpty(it.CreatedAt, it.UpdatedAt)
	case "ready", "verify", "attention", "done":
		return firstNonEmpty(it.UpdatedAt, it.CreatedAt)
	default:
		return firstNonEmpty(it.UpdatedAt, it.CreatedAt)
	}
}

func annotateActionFlowActor(it k8sActionFlowItem) k8sActionFlowItem {
	risk := strings.ToLower(strings.TrimSpace(it.RiskLevel))
	switch it.Lane {
	case "approval":
		if risk == "critical" || risk == "high" || it.Kind == "debug_session" {
			it.ActorHint = "security/admin"
			it.ActorReason = "고위험·보안성 요청은 보안 담당자 또는 관리자가 승인해야 합니다."
		} else {
			it.ActorHint = "approver/operator"
			it.ActorReason = "승인 권한이 있는 운영자 또는 승인자가 결정해야 합니다."
		}
	case "ready":
		switch it.Kind {
		case "exec_session":
			it.ActorHint = "requester/operator"
			it.ActorReason = "승인된 단일 명령 세션은 요청자 또는 운영자가 실행합니다."
		case "debug_session":
			it.ActorHint = "operator"
			it.ActorReason = "Debug Container 주입은 운영 절차에 따라 운영자가 진행합니다."
		default:
			it.ActorHint = "operator/admin"
			it.ActorReason = "승인된 변경은 운영자 또는 관리자가 실행합니다."
		}
	case "verify":
		it.ActorHint = "requester/operator"
		it.ActorReason = "적용 이후 상태는 요청자와 운영자가 함께 검증합니다."
	case "prepare":
		it.ActorHint = "requester"
		it.ActorReason = "초안·검증 전 요청은 요청자가 보완해야 합니다."
	case "attention":
		it.ActorHint = "operator"
		it.ActorReason = "실패·반려·차단 상태는 운영자가 원인을 확인해야 합니다."
	case "done":
		it.ActorHint = "closed"
		it.ActorReason = "닫힌 작업입니다."
	default:
		it.ActorHint = "operator"
		it.ActorReason = "운영자 확인이 필요합니다."
	}
	if it.SLAStatus == "breached" && it.Lane != "done" {
		it.ActorReason += " SLA가 초과되어 우선 처리 대상입니다."
	}
	return it
}

func actionFlowHandoffText(it k8sActionFlowItem) string {
	parts := []string{
		"[Clustara 운영 작업 인계]",
		"작업: " + firstNonEmpty(it.Title, it.Kind, "-"),
		"ID: " + firstNonEmpty(it.ID, "-"),
		"대상: " + firstNonEmpty(it.Target, "-"),
		"상태: " + firstNonEmpty(it.Status, "-") + " / 위험도: " + firstNonEmpty(it.RiskLevel, "-"),
		"다음 단계: " + firstNonEmpty(it.PrimaryLabel, it.NextAction, "-"),
		"다음 담당: " + firstNonEmpty(it.ActorHint, "-"),
		"SLA: " + firstNonEmpty(it.SLAStatus, "-") + " (" + firstNonEmpty(it.AgeLabel, "-") + ")",
		"우선 사유: " + actionFlowPriorityReason(it),
	}
	if it.RequestedBy != "" {
		parts = append(parts, "요청자: "+it.RequestedBy)
	}
	if it.ActorReason != "" {
		parts = append(parts, "담당 사유: "+it.ActorReason)
	}
	if it.Href != "" {
		parts = append(parts, "처리 화면: "+it.Href)
	}
	return strings.Join(parts, "\n")
}

func actionFlowHandoffSummary(items []k8sActionFlowItem, summary map[string]int, limit int) string {
	if limit <= 0 {
		limit = 8
	}
	active := make([]k8sActionFlowItem, 0, limit)
	activeTotal := 0
	for _, it := range items {
		if it.Lane == "done" {
			continue
		}
		if it.Lane == "prepare" && it.SLAStatus == "ok" {
			continue
		}
		activeTotal++
		if len(active) < limit {
			active = append(active, it)
		}
	}
	if len(active) == 0 {
		return "[Clustara 운영 작업 요약]\n처리 대기 작업이 없습니다."
	}
	lines := []string{
		"[Clustara 운영 작업 요약]",
		fmt.Sprintf(
			"총 %d건 · 확인 %d · 승인 %d · 실행 %d · 검증 %d · SLA 초과 %d · 임박 %d",
			summary["total"],
			summary["attention"],
			summary["approval"],
			summary["ready"],
			summary["verify"],
			summary["sla_breached"],
			summary["sla_warning"],
		),
	}
	for _, it := range active {
		sla := firstNonEmpty(it.SLAStatus, "-")
		if it.AgeLabel != "" && it.AgeLabel != "-" {
			sla += " " + it.AgeLabel
		}
		lines = append(lines, "- ["+
			firstNonEmpty(it.Lane, "-")+"/"+firstNonEmpty(it.Status, "-")+"/"+firstNonEmpty(it.RiskLevel, "-")+"] "+
			firstNonEmpty(it.Title, it.Kind, "-")+
			" ("+firstNonEmpty(it.ID, "-")+")"+
			" | "+firstNonEmpty(it.Target, "-")+
			" | 다음: "+firstNonEmpty(it.PrimaryLabel, it.NextAction, "-")+
			" | 담당: "+firstNonEmpty(it.ActorHint, "-")+
			" | SLA: "+sla+
			" | 사유: "+actionFlowPriorityReason(it)+
			" | "+firstNonEmpty(it.Href, "-"))
	}
	if activeTotal > len(active) {
		lines = append(lines, fmt.Sprintf("외 %d건은 액션 승인함에서 확인", activeTotal-len(active)))
	}
	return strings.Join(lines, "\n")
}

func actionFlowPriorityReason(it k8sActionFlowItem) string {
	reasons := make([]string, 0, 3)
	switch it.SLAStatus {
	case "breached":
		reasons = append(reasons, "SLA 초과")
	case "warning":
		reasons = append(reasons, "SLA 임박")
	}
	switch it.Lane {
	case "attention":
		reasons = append(reasons, "확인 필요")
	case "approval":
		if len(reasons) == 0 {
			reasons = append(reasons, "승인 대기")
		}
	case "ready":
		if len(reasons) == 0 {
			reasons = append(reasons, "실행 가능")
		}
	case "verify":
		if len(reasons) == 0 {
			reasons = append(reasons, "검증 필요")
		}
	case "prepare":
		if len(reasons) == 0 {
			reasons = append(reasons, "준비/검증")
		}
	}
	if len(reasons) == 0 {
		return "처리 대기"
	}
	return strings.Join(reasons, " · ")
}

func actionFlowSLAThresholds(lane string) (warn, breach time.Duration) {
	switch lane {
	case "attention":
		return 0, 0
	case "approval":
		return 30 * time.Minute, 2 * time.Hour
	case "ready":
		return 15 * time.Minute, time.Hour
	case "verify":
		return 30 * time.Minute, 4 * time.Hour
	case "prepare":
		return 4 * time.Hour, 24 * time.Hour
	default:
		return 0, 0
	}
}

func actionFlowSLAReason(lane, status, age string) string {
	if status == "ok" {
		if lane == "done" {
			return "닫힌 작업"
		}
		return "SLA 정상"
	}
	switch lane {
	case "approval":
		return "승인 대기 " + age
	case "ready":
		return "실행 대기 " + age
	case "verify":
		return "사후 검증 대기 " + age
	case "prepare":
		return "검증 전 초안 " + age
	case "attention":
		return "확인 필요 " + age
	default:
		return "대기 " + age
	}
}

func actionFlowAgeLabel(age time.Duration) string {
	if age < time.Minute {
		return "방금"
	}
	if age < time.Hour {
		return strconv.Itoa(int(age/time.Minute)) + "분"
	}
	if age < 48*time.Hour {
		return strconv.Itoa(int(age/time.Hour)) + "시간"
	}
	return strconv.Itoa(int(age/(24*time.Hour))) + "일"
}

func parseActionFlowTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	return time.Time{}, false
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

func flowSLAPriority(status string) int {
	switch status {
	case "breached":
		return 0
	case "warning":
		return 1
	case "ok":
		return 2
	default:
		return 3
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
