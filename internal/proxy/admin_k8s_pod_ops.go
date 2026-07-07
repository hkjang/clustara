package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

type podLogMergedLine struct {
	Pod    string `json:"pod"`
	Number int    `json:"number"`
	Level  string `json:"level"`
	Text   string `json:"text"`
}

type logSensitivityRule struct {
	Type    string
	Pattern *regexp.Regexp
}

var logSensitivityRules = []logSensitivityRule{
	{"authorization", regexp.MustCompile(`(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]+`)},
	{"password", regexp.MustCompile(`(?i)\b(password|passwd|pwd)\s*[:=]\s*[^,\s]+`)},
	{"token", regexp.MustCompile(`(?i)\b(token|api[_-]?key|secret)\s*[:=]\s*[^,\s]+`)},
	{"korean_rrn", regexp.MustCompile(`\b\d{6}-\d{7}\b`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

func (s *Server) handleK8sPodBookmarks(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		rows, err := s.db.ListK8sPodBookmarks(r.Context(), store.K8sPodBookmarkFilter{
			UserID: firstNonEmpty(strings.TrimSpace(q.Get("user_id")), adminID(r)), ClusterID: strings.TrimSpace(q.Get("cluster_id")),
			Namespace: strings.TrimSpace(q.Get("namespace")), Auto: strings.TrimSpace(q.Get("auto")), Limit: recentLimit(r),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_bookmarks_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"bookmarks": rows})
	case http.MethodPost:
		var in struct {
			ClusterID string `json:"cluster_id"`
			Namespace string `json:"namespace"`
			Pod       string `json:"pod"`
			Note      string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		ns, pod := strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Pod)
		if ns == "" || pod == "" {
			writeOpenAIError(w, http.StatusBadRequest, "namespace and pod are required", "invalid_request_error", "missing_pod")
			return
		}
		clusterID := strings.TrimSpace(in.ClusterID)
		var item store.K8sInventoryItem
		if clusterID == "" {
			var ok bool
			clusterID, item, ok = s.resolvePodInventory(nil, r, ns, pod)
			if !ok {
				writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required when pod identity is ambiguous", "invalid_request_error", "cluster_id_required")
				return
			}
		} else {
			var err error
			item, err = s.db.GetK8sInventoryItem(r.Context(), clusterID, "Pod", ns, pod)
			if err != nil {
				writeOpenAIError(w, http.StatusNotFound, "pod not found", "invalid_request_error", "pod_not_found")
				return
			}
		}
		s.upsertPodBookmark(r, clusterID, podView(item, nil, false), false, strings.TrimSpace(in.Note), "manual")
		rows, _ := s.db.ListK8sPodBookmarks(r.Context(), store.K8sPodBookmarkFilter{UserID: adminID(r), ClusterID: clusterID, Namespace: ns, Limit: 20})
		writeJSON(w, http.StatusCreated, map[string]any{"bookmarks": rows})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sPodBookmarkByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodDelete {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/pod-bookmarks/"), "/")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "bookmark id is required", "invalid_request_error", "missing_bookmark")
		return
	}
	if err := s.db.DeleteK8sPodBookmark(r.Context(), id, adminID(r)); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "bookmark not found", "invalid_request_error", "bookmark_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_bookmark_delete_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleK8sPodAccesses(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	rows, err := s.db.ListK8sPodAccesses(r.Context(), store.K8sPodAccessFilter{
		UserID: firstNonEmpty(strings.TrimSpace(q.Get("user_id")), adminID(r)), ClusterID: strings.TrimSpace(q.Get("cluster_id")),
		Namespace: strings.TrimSpace(q.Get("namespace")), Pod: strings.TrimSpace(q.Get("pod")), Action: strings.TrimSpace(q.Get("action")), Limit: recentLimit(r),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_accesses_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accesses": rows})
}

func (s *Server) handleK8sPodBookmark(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	var in struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	view := podView(item, nil, false)
	if err := s.upsertPodBookmark(r, clusterID, view, false, strings.TrimSpace(in.Note), "manual"); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_bookmark_failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"bookmark": map[string]any{"cluster_id": clusterID, "namespace": namespace, "pod": pod}})
}

func (s *Server) upsertPodBookmark(r *http.Request, clusterID string, pod k8sPodView, auto bool, note, reason string) error {
	if pod.Name == "" {
		return nil
	}
	userID := adminID(r)
	if auto {
		userID = "system:auto"
	}
	return s.db.UpsertK8sPodBookmark(r.Context(), &store.K8sPodBookmark{
		ID: newID("k8sbm"), UserID: userID, ClusterID: clusterID, Namespace: pod.Namespace, Pod: pod.Name,
		OwnerKind: pod.OwnerKind, OwnerName: pod.OwnerName, Note: note, Auto: auto, Reason: reason,
	})
}

func (s *Server) recordPodAccess(r *http.Request, clusterID, namespace, pod, action, context string) {
	if clusterID == "" || namespace == "" || pod == "" || action == "" {
		return
	}
	_ = s.db.RecordK8sPodAccess(r.Context(), store.K8sPodAccess{
		ID: newID("k8spacc"), UserID: adminID(r), ClusterID: clusterID, Namespace: namespace, Pod: pod, Action: action, Context: context,
	})
}

func (s *Server) handleK8sPodLogPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"presets": podLogFilterPresets()})
}

func podLogFilterPresets() []map[string]any {
	return []map[string]any{
		{"name": "ERROR", "query": "ERROR", "error_only": true, "description": "error level 로그만 빠르게 확인"},
		{"name": "Exception", "query": "Exception", "error_only": false, "description": "Java/Python/Node 예외와 stacktrace 탐색"},
		{"name": "Timeout", "query": "timeout", "error_only": false, "description": "timeout/deadline/retry 계열 탐색"},
		{"name": "Connection refused", "query": "connection refused", "error_only": false, "description": "서비스 endpoint 또는 네트워크 단절 탐색"},
		{"name": "Spring Boot", "query": "org.springframework", "error_only": false, "description": "Spring Boot 예외와 actuator/probe 로그"},
		{"name": "Nginx 5xx", "query": " 5", "error_only": false, "description": "Nginx access/error 로그의 5xx 탐색"},
		{"name": "PostgreSQL", "query": "postgres", "error_only": false, "description": "DB 연결/인증/timeout 탐색"},
		{"name": "Redis", "query": "redis", "error_only": false, "description": "Redis 연결과 timeout 탐색"},
	}
}

func (s *Server) handleK8sPodLogMaskingReport(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	var in struct {
		Text string `json:"text"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	text := in.Text
	if strings.TrimSpace(text) == "" {
		resp, err := s.readPodLogs(r.Context(), r, namespace, pod)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_pod_masking_report_failed")
			return
		}
		text = resp.Text
	}
	findings := detectLogSensitivity(text)
	masked := analyzer.MaskSensitive(text)
	writeJSON(w, http.StatusOK, map[string]any{
		"namespace": namespace, "pod": pod, "masked": true, "findings": findings,
		"summary": map[string]any{"finding_types": len(findings), "raw_changed": masked != text},
		"preview": map[string]string{"before": truncateRunes(text, 2000), "after": truncateRunes(masked, 2000)},
	})
}

func detectLogSensitivity(text string) []map[string]any {
	out := []map[string]any{}
	for _, rule := range logSensitivityRules {
		matches := rule.Pattern.FindAllString(text, 20)
		if len(matches) == 0 {
			continue
		}
		samples := []string{}
		for _, sample := range matches {
			samples = append(samples, analyzer.MaskSensitive(sample))
			if len(samples) >= 3 {
				break
			}
		}
		out = append(out, map[string]any{"type": rule.Type, "count": len(matches), "samples": samples})
	}
	return out
}

func (s *Server) handleK8sPodLogSnapshot(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	var in struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	resp, err := s.readPodLogs(r.Context(), r, namespace, pod)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_pod_log_snapshot_failed")
		return
	}
	summary := map[string]any{}
	b, _ := json.Marshal(resp.Summary)
	_ = json.Unmarshal(b, &summary)
	snap := store.K8sPodLogSnapshot{
		ID: newID("k8slogsnap"), ClusterID: resp.ClusterID, Namespace: namespace, Pod: pod, Container: resp.Container,
		Previous: resp.Previous, TailLines: resp.TailLines, Reason: firstNonEmpty(strings.TrimSpace(in.Reason), "manual snapshot"),
		Summary: summary, Text: resp.Text, CreatedBy: adminID(r),
	}
	if err := s.db.InsertK8sPodLogSnapshot(r.Context(), snap); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_log_snapshot_failed")
		return
	}
	s.recordPodAccess(r, resp.ClusterID, namespace, pod, "log_snapshot", snap.Reason)
	writeJSON(w, http.StatusCreated, map[string]any{"snapshot": snap})
}

func (s *Server) handleK8sPodLogSnapshots(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, _, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	rows, err := s.db.ListK8sPodLogSnapshots(r.Context(), store.K8sPodLogSnapshotFilter{ClusterID: clusterID, Namespace: namespace, Pod: pod, Limit: recentLimit(r)})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_log_snapshots_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": rows})
}

func (s *Server) handleK8sPodLogMerge(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, target, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), clusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	reader, ok := client.(podLogReader)
	if !ok {
		writeOpenAIError(w, http.StatusBadRequest, "cluster client does not support Pod logs", "invalid_request_error", "k8s_pod_logs_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Pod", Namespace: namespace, Limit: 1000})
	siblings := []store.K8sInventoryItem{target}
	for _, item := range items {
		if item.Name != target.Name && samePodWorkload(target, item) {
			siblings = append(siblings, item)
		}
		if len(siblings) >= boundedInt(r.URL.Query().Get("pods"), 5, 1, 20) {
			break
		}
	}
	opts := kube.PodLogOptions{
		Container: strings.TrimSpace(r.URL.Query().Get("container")), TailLines: boundedInt(r.URL.Query().Get("tail_lines"), 100, 1, 1000),
		SinceSeconds: parseSinceSeconds(r.URL.Query().Get("since")), SinceTime: strings.TrimSpace(r.URL.Query().Get("since_time")),
		Timestamps: parseBool(r.URL.Query().Get("timestamps")), LimitBytes: boundedInt(r.URL.Query().Get("limit_bytes"), 1024*1024, 4096, 5*1024*1024),
	}
	lines := []podLogMergedLine{}
	streams := []map[string]any{}
	for _, item := range siblings {
		localOpts := opts
		if localOpts.Container == "" {
			localOpts.Container = defaultContainerName(item)
		}
		raw, err := reader.PodLogs(r.Context(), namespace, item.Name, localOpts)
		if err != nil {
			streams = append(streams, map[string]any{"pod": item.Name, "error": err.Error()})
			continue
		}
		processed := processPodLogs(raw, strings.TrimSpace(r.URL.Query().Get("q")), parseBool(r.URL.Query().Get("error_only")))
		streams = append(streams, map[string]any{"pod": item.Name, "container": localOpts.Container, "summary": processed.Summary, "risk": podView(item, events, false).RiskLevel})
		for _, line := range processed.Lines {
			lines = append(lines, podLogMergedLine{Pod: item.Name, Number: line.Number, Level: line.Level, Text: line.Text})
		}
	}
	if len(lines) > 1000 {
		lines = lines[len(lines)-1000:]
	}
	s.recordPodAccess(r, clusterID, namespace, pod, "log_merge", "siblings="+strconv.Itoa(len(siblings)))
	writeJSON(w, http.StatusOK, map[string]any{"cluster_id": clusterID, "namespace": namespace, "pod": pod, "streams": streams, "merged_lines": lines})
}

func (s *Server) handleK8sTerminalTemplates(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": terminalCommandTemplates()})
}

func terminalCommandTemplates() []map[string]any {
	return []map[string]any{
		{"name": "프로세스 확인", "command": "ps aux", "risk": "low"},
		{"name": "환경변수 확인", "command": "env", "risk": "low"},
		{"name": "디스크 사용량", "command": "df -h", "risk": "low"},
		{"name": "메모리 확인", "command": "free -m", "risk": "low"},
		{"name": "DNS 확인", "command": "nslookup kubernetes.default", "risk": "medium"},
		{"name": "HTTP 확인", "command": "curl -I http://localhost:9090/health", "risk": "medium"},
	}
}

func (s *Server) handleK8sPodExecBriefing(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	command := strings.TrimSpace(r.URL.Query().Get("command"))
	role := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("role")), "viewer")
	risk, reason := classifyTerminalCommandRisk(command)
	policies, _ := s.db.ListK8sTerminalPolicies(r.Context(), store.K8sTerminalPolicyFilter{Role: role, ClusterID: clusterID, Enabled: "true", Limit: 500})
	eval := evaluateTerminalPolicy(terminalPolicyEvalRequest{Role: role, ClusterID: clusterID, Namespace: namespace, Pod: pod, PodLabels: item.Labels, Command: command}, policies)
	view := podView(item, nil, true)
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod, "command": command, "role": role,
		"risk": map[string]string{"level": risk, "reason": reason}, "policy_result": eval,
		"context": map[string]any{
			"phase": view.Phase, "ready": view.Ready, "restarts": view.RestartCount,
			"recent_restarts": view.RecentRestartCount, "restart_signal": view.RestartSignal,
			"node": view.NodeName, "owner": podOwnerLabel(view),
		},
		"templates": terminalCommandTemplates(),
		"warnings":  execRiskWarnings(risk, eval.RequireApproval, eval.Allowed),
	})
}

func execRiskWarnings(risk string, requireApproval, allowed bool) []string {
	out := []string{}
	if !allowed {
		out = append(out, "현재 정책으로는 실행할 수 없습니다.")
	}
	if requireApproval {
		out = append(out, "승인 후 실행됩니다.")
	}
	if risk == "high" || risk == "critical" {
		out = append(out, "위험 명령입니다. 실행 전 변경 가능성과 롤백 경로를 확인하세요.")
	}
	return out
}

func (s *Server) handleK8sDebugCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	writeJSON(w, http.StatusOK, debugCatalogResponse())
}

func debugCatalogResponse() map[string]any {
	images := []map[string]any{
		{"name": "busybox", "image": "busybox:1.36", "use_case": "기본 shell, 파일/프로세스 확인", "risk": "low", "digest_pinned": false},
		{"name": "curl", "image": "curlimages/curl:8.8.0", "use_case": "HTTP endpoint 확인", "risk": "low", "digest_pinned": false},
		{"name": "netshoot", "image": "nicolaka/netshoot:latest", "use_case": "DNS/route/tcpdump 등 네트워크 진단", "risk": "medium", "digest_pinned": false},
		{"name": "postgres-client", "image": "postgres:16-alpine", "use_case": "PostgreSQL 연결 확인", "risk": "medium", "digest_pinned": false},
		{"name": "redis-cli", "image": "redis:7-alpine", "use_case": "Redis 연결 확인", "risk": "medium", "digest_pinned": false},
	}
	templates := []map[string]any{
		{"name": "DNS 점검", "recommended_image": "nicolaka/netshoot:latest", "commands": []string{"nslookup kubernetes.default", "dig +short service.namespace.svc.cluster.local"}},
		{"name": "HTTP 점검", "recommended_image": "curlimages/curl:8.8.0", "commands": []string{"curl -v http://service:port/health"}},
		{"name": "DB 포트 점검", "recommended_image": "nicolaka/netshoot:latest", "commands": []string{"nc -vz host 5432"}},
		{"name": "기본 파일/프로세스", "recommended_image": "busybox:1.36", "commands": []string{"ps", "ls -la /proc/1/root"}},
	}
	return map[string]any{"images": images, "templates": templates, "policy": map[string]any{"privileged_allowed": false, "host_pid_allowed": false, "host_network_allowed": false, "require_approval": true}}
}

func (s *Server) handleK8sDebugSessions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	rows, err := s.db.ListK8sDebugSessions(r.Context(), store.K8sDebugSessionFilter{ClusterID: strings.TrimSpace(q.Get("cluster_id")), Namespace: strings.TrimSpace(q.Get("namespace")), Pod: strings.TrimSpace(q.Get("pod")), Status: strings.TrimSpace(q.Get("status")), Limit: recentLimit(r)})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_debug_sessions_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": rows})
}

func (s *Server) handleK8sDebugSessionByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/debug/sessions/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "debug session id required", "invalid_request_error", "missing_debug_session")
		return
	}
	id, _ := url.PathUnescape(parts[0])
	if len(parts) == 1 && r.Method == http.MethodGet {
		sess, err := s.db.GetK8sDebugSession(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "debug session not found", "invalid_request_error", "debug_session_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_debug_session_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"session": sess})
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	command := strings.ToLower(strings.TrimSpace(parts[1]))
	status := map[string]string{"approve": "ready", "reject": "rejected"}[command]
	if status == "" {
		writeOpenAIError(w, http.StatusBadRequest, "unsupported debug session command", "invalid_request_error", "unsupported_debug_session_command")
		return
	}
	var in struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	updated, err := s.db.UpdateK8sDebugSessionDecision(r.Context(), id, status, adminID(r), strings.TrimSpace(in.Note))
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "debug session not found", "invalid_request_error", "debug_session_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_debug_session_decide_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": updated, "next_action": map[string]string{"ready": "manual_ephemeral_container_apply", "rejected": "closed"}[status]})
}

func (s *Server) handleK8sPodDebugSessions(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	switch r.Method {
	case http.MethodGet:
		clusterID, _, ok := s.resolvePodInventory(w, r, namespace, pod)
		if !ok {
			return
		}
		rows, err := s.db.ListK8sDebugSessions(r.Context(), store.K8sDebugSessionFilter{ClusterID: clusterID, Namespace: namespace, Pod: pod, Limit: recentLimit(r)})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_debug_sessions_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": rows, "catalog": debugCatalogResponse()})
	case http.MethodPost:
		s.requestK8sPodDebugSession(w, r, namespace, pod)
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) requestK8sPodDebugSession(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	var in struct {
		TargetContainer string `json:"target_container"`
		DebugImage      string `json:"debug_image"`
		Template        string `json:"template"`
		Reason          string `json:"reason"`
		Privileged      bool   `json:"privileged"`
		HostPID         bool   `json:"host_pid"`
		HostNetwork     bool   `json:"host_network"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	image := firstNonEmpty(strings.TrimSpace(in.DebugImage), recommendDebugImage(item))
	target := firstNonEmpty(strings.TrimSpace(in.TargetContainer), defaultContainerName(item))
	status, risk, reason := "pending_approval", debugImageRisk(image), "approval required before ephemeral container injection"
	if !debugImageAllowed(image) {
		status, risk, reason = "blocked", "critical", "debug image is not in the allowed catalog"
	}
	if in.Privileged || in.HostPID || in.HostNetwork {
		status, risk, reason = "blocked", "critical", "privileged, hostPID, and hostNetwork debug options are blocked by policy"
	}
	preview := buildDebugManifestPreview(namespace, pod, target, image)
	sess := store.K8sDebugSession{
		ID: newID("k8sdbg"), ClusterID: clusterID, Namespace: namespace, Pod: pod, TargetContainer: target, DebugImage: image,
		Template: strings.TrimSpace(in.Template), Reason: firstNonEmpty(strings.TrimSpace(in.Reason), reason), Status: status, RiskLevel: risk,
		RequireApproval: true, RequestedBy: adminID(r), ManifestPreview: compactJSON(preview),
	}
	if err := s.db.InsertK8sDebugSession(r.Context(), &sess); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_debug_session_create_failed")
		return
	}
	s.recordPodAccess(r, clusterID, namespace, pod, "debug_request", image)
	writeJSON(w, http.StatusCreated, map[string]any{"session": sess, "catalog": debugCatalogResponse(), "next_action": map[string]string{"pending_approval": "approval_required", "blocked": "closed"}[status]})
}

func debugImageAllowed(image string) bool {
	for _, allowed := range []string{"busybox:1.36", "curlimages/curl:8.8.0", "nicolaka/netshoot:latest", "postgres:16-alpine", "redis:7-alpine"} {
		if image == allowed {
			return true
		}
	}
	return false
}

func debugImageRisk(image string) string {
	if strings.Contains(image, "netshoot") || strings.Contains(image, "postgres") || strings.Contains(image, "redis") {
		return "medium"
	}
	return "low"
}

func recommendDebugImage(item store.K8sInventoryItem) string {
	hay := strings.ToLower(item.Name + " " + strings.Join(mapValues(item.Labels), " ") + " " + compactMaskedJSON(item.Spec))
	switch {
	case strings.Contains(hay, "redis"):
		return "redis:7-alpine"
	case strings.Contains(hay, "postgres") || strings.Contains(hay, "pgsql"):
		return "postgres:16-alpine"
	case strings.Contains(hay, "dns") || strings.Contains(hay, "network"):
		return "nicolaka/netshoot:latest"
	default:
		return "busybox:1.36"
	}
}

func buildDebugManifestPreview(namespace, pod, target, image string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"namespace": namespace, "name": pod},
		"ephemeralContainers": []map[string]any{{
			"name":            "clustara-debug-" + strconv.FormatInt(time.Now().Unix(), 10),
			"image":           image,
			"targetContainer": target,
			"stdin":           true,
			"tty":             true,
			"securityContext": map[string]any{"privileged": false, "allowPrivilegeEscalation": false, "runAsNonRoot": false},
		}},
	}
}

func (s *Server) handleK8sPodActionSafety(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	view := podView(item, events, true)
	siblings := 0
	for _, other := range items {
		if other.Kind == "Pod" && other.Namespace == namespace && other.Name != pod && samePodWorkload(item, other) {
			ov := podView(other, events, false)
			if ov.ReadyCount == ov.ContainerCount && ov.ContainerCount > 0 {
				siblings++
			}
		}
	}
	blockers := []string{}
	warnings := []string{}
	if view.OwnerKind == "" || view.OwnerName == "" {
		blockers = append(blockers, "standalone Pod라 delete 후 자동 복구가 보장되지 않습니다.")
	}
	if siblings == 0 {
		warnings = append(warnings, "같은 workload의 Ready sibling Pod가 없어 endpoint 감소 영향이 클 수 있습니다.")
	}
	if view.RecentWarningEvents > 0 || view.RecentRestartCount > 0 {
		warnings = append(warnings, "최근 Warning 이벤트 또는 restart가 있어 조치 전 증적 번들을 권장합니다.")
	}
	actions := []map[string]any{
		{"action": "evict_pod", "preferred": true, "risk": riskFromBlockers(blockers, warnings), "approval_required": true, "reason": "PDB 고려 조치가 가능하면 delete보다 evict를 우선 권장"},
		{"action": "delete_pod", "preferred": false, "risk": riskFromBlockers(blockers, warnings), "approval_required": true, "reason": "ReplicaSet/owner가 있을 때 재생성을 유도"},
		{"action": "rollout_restart_owner", "preferred": false, "risk": "medium", "approval_required": true, "reason": "owner 전체 restart로 config/image 문제를 일괄 재시도"},
		{"action": "evidence_bundle", "preferred": siblings == 0 || view.RecentRestartCount > 0 || view.RecentWarningEvents > 0, "risk": "low", "approval_required": false, "reason": "조치 전 로그/이벤트/manifest 증적 고정"},
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod, "owner": map[string]string{"kind": view.OwnerKind, "name": view.OwnerName},
		"ready_siblings": siblings, "blockers": blockers, "warnings": warnings, "actions": actions,
	})
}

func riskFromBlockers(blockers, warnings []string) string {
	if len(blockers) > 0 {
		return "high"
	}
	if len(warnings) > 0 {
		return "medium"
	}
	return "low"
}

func (s *Server) handleK8sPodRunbook(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	view := podView(item, nil, true)
	steps := []map[string]any{
		{"step": 1, "title": "증적 고정", "action": "evidence_bundle", "approval_required": false},
		{"step": 2, "title": "previous 로그와 이벤트 확인", "action": "logs_previous_and_events", "approval_required": false},
		{"step": 3, "title": "Golden Pod Diff 비교", "action": "golden_diff", "approval_required": false},
		{"step": 4, "title": "조치 안전성 확인", "action": "action_safety", "approval_required": false},
		{"step": 5, "title": "권장 조치 승인 요청", "action": recommendedRunbookAction(view), "approval_required": true},
		{"step": 6, "title": "조치 후 Health Replay로 확인", "action": "post_check_health_replay", "approval_required": false},
	}
	// Symptom-driven staged orchestration plan (pre-check → diagnose → remediate → post-check → rollback).
	recentChange := s.podHasRecentChange(r.Context(), clusterID, item)
	plan := analyzer.BuildRunbookPlan(view.PrimarySymptom, analyzer.RunbookContext{
		HasOwner: view.OwnerName != "", RecentChange: recentChange,
	})
	writeJSON(w, http.StatusOK, map[string]any{"cluster_id": clusterID, "namespace": namespace, "pod": pod, "condition": firstNonEmpty(view.RiskLevel, podStatusRisk(view.Status), "normal"), "steps": steps, "plan": plan})
}

// podHasRecentChange reports whether the pod had an "updated" revision within the last 30 minutes
// (a recent deploy/config change → rollback becomes a candidate in the runbook plan).
func (s *Server) podHasRecentChange(ctx context.Context, clusterID string, item store.K8sInventoryItem) bool {
	revs, _ := s.db.ListK8sRevisions(ctx, store.K8sRevisionFilter{ClusterID: clusterID, Kind: "Pod", Namespace: item.Namespace, Name: item.Name, Limit: 4})
	now := time.Now().UTC()
	for _, rev := range revs {
		if !strings.EqualFold(rev.ChangeKind, "updated") {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, rev.ObservedAt); err == nil && now.Sub(t) <= 30*time.Minute {
			return true
		}
	}
	return false
}

func recommendedRunbookAction(view k8sPodView) string {
	status := strings.ToLower(view.Status + " " + view.Phase)
	switch {
	case strings.Contains(status, "crashloop") || view.RecentRestartCount > 0:
		return "delete_pod_or_rollout_restart_owner"
	case strings.Contains(status, "imagepull"):
		return "fix_image_or_imagepullsecret_then_rollout"
	case strings.Contains(status, "pending"):
		return "check_quota_taint_affinity_pvc"
	default:
		return "observe_or_request_debug_session"
	}
}

func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
