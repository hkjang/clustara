package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

func (s *Server) handleK8sExecSessions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	s.writeK8sPodExecSessions(w, r, "", "")
}

func (s *Server) handleK8sExecSessionByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/exec/sessions/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "session id required", "invalid_request_error", "bad_exec_session_path")
		return
	}
	id, _ := url.PathUnescape(parts[0])
	sess, err := s.db.GetK8sPodExecSession(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "exec session not found: "+id, "invalid_request_error", "exec_session_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_exec_session_failed")
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		writeK8sExecSessionDetail(w, sess)
		return
	}
	if len(parts) != 2 || parts[1] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "session id and command required", "invalid_request_error", "bad_exec_session_path")
		return
	}
	command, _ := url.PathUnescape(parts[1])
	command = strings.ToLower(strings.TrimSpace(command))
	if command == "export" {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.writeK8sExecSessionExport(w, r, sess)
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var payload struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	if command == "execute" {
		s.executeK8sPodExecSession(w, r, sess)
		return
	}
	if sess.Status != "pending_approval" {
		writeOpenAIError(w, http.StatusConflict, "exec session must be pending_approval before decision (current: "+sess.Status+")", "invalid_request_error", "exec_session_bad_state")
		return
	}
	status := ""
	nextAction := ""
	switch command {
	case "approve":
		status = "ready"
		nextAction = "connect_exec_transport"
	case "reject":
		status = "rejected"
		nextAction = "closed"
	default:
		writeOpenAIError(w, http.StatusBadRequest, "unsupported exec session command", "invalid_request_error", "unsupported_exec_session_command")
		return
	}
	updated, err := s.db.UpdateK8sPodExecSessionDecision(r.Context(), id, status, adminID(r), strings.TrimSpace(payload.Note))
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "exec session not found: "+id, "invalid_request_error", "exec_session_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_exec_session_decide_failed")
		return
	}
	s.auditAdmin(r, "k8s.pod.exec_session."+command, id, auditJSON(map[string]any{
		"cluster_id": updated.ClusterID, "namespace": updated.Namespace, "pod": updated.Pod,
		"container": updated.Container, "role": updated.Role, "status": updated.Status,
	}))
	writeJSON(w, http.StatusOK, map[string]any{"session": updated, "next_action": nextAction})
}

func writeK8sExecSessionDetail(w http.ResponseWriter, sess store.K8sPodExecSession) {
	policy := k8sExecSessionPolicy(sess)
	replay := k8sExecSessionReplay(sess)
	writeJSON(w, http.StatusOK, map[string]any{
		"session":       sess,
		"policy_result": policy,
		"replay":        replay,
	})
}

func (s *Server) writeK8sExecSessionExport(w http.ResponseWriter, r *http.Request, sess store.K8sPodExecSession) {
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	body := buildK8sExecSessionReport(generatedAt, sess)
	s.auditAdmin(r, "k8s.pod.exec_session.export", sess.ID, auditJSON(map[string]any{
		"cluster_id": sess.ClusterID, "namespace": sess.Namespace, "pod": sess.Pod, "status": sess.Status,
	}))
	name := sanitizeDownloadName(sess.ID + "_exec_replay.md")
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(body))
}

func k8sExecSessionPolicy(sess store.K8sPodExecSession) map[string]any {
	policy := map[string]any{}
	if strings.TrimSpace(sess.PolicyResult) == "" {
		return policy
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(sess.PolicyResult), &decoded); err == nil {
		return decoded
	}
	policy["raw"] = sess.PolicyResult
	return policy
}

func k8sExecSessionReplay(sess store.K8sPodExecSession) []map[string]any {
	replay := []map[string]any{{
		"at":       sess.CreatedAt,
		"category": "request",
		"status":   "requested",
		"title":    "exec 세션 요청",
		"detail":   sess.Role + " · " + sess.Namespace + "/" + sess.Pod + " · " + sess.Command,
		"actor":    sess.RequestedBy,
	}}
	if sess.DecidedAt != "" {
		replay = append(replay, map[string]any{
			"at":       sess.DecidedAt,
			"category": "decision",
			"status":   decisionStatusLabel(sess.Status),
			"title":    "승인 결정",
			"detail":   sess.DecisionNote,
			"actor":    sess.DecidedBy,
		})
	}
	if sess.ExecutedAt != "" {
		replay = append(replay, map[string]any{
			"at":       sess.ExecutedAt,
			"category": "execution",
			"status":   sess.Status,
			"title":    "단일 명령 실행",
			"detail":   fmt.Sprintf("exit %d", sess.ExitCode),
			"actor":    sess.ExecutedBy,
		})
	}
	return replay
}

func buildK8sExecSessionReport(generatedAt string, sess store.K8sPodExecSession) string {
	policy := k8sExecSessionPolicy(sess)
	policyJSON, _ := json.MarshalIndent(policy, "", "  ")
	var b strings.Builder
	b.WriteString("# Clustara Pod Exec Session Report\n\n")
	b.WriteString("- Generated: " + markdownTableCell(generatedAt) + "\n")
	b.WriteString("- Session ID: `" + markdownInlineCode(sess.ID) + "`\n")
	b.WriteString("- Status: `" + markdownInlineCode(sess.Status) + "`\n\n")

	b.WriteString("## Target\n\n")
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	for _, row := range [][2]string{
		{"Cluster", sess.ClusterID},
		{"Namespace", sess.Namespace},
		{"Pod", sess.Pod},
		{"Container", sess.Container},
		{"Role", sess.Role},
		{"Command", sess.Command},
		{"Reason", sess.Reason},
		{"Risk", sess.RiskLevel},
		{"Approval Required", fmt.Sprintf("%t", sess.RequireApproval)},
		{"Audit Enabled", fmt.Sprintf("%t", sess.AuditEnabled)},
		{"Max Session Minutes", fmt.Sprintf("%d", sess.MaxSessionMinutes)},
	} {
		b.WriteString("| " + markdownTableCell(row[0]) + " | " + markdownTableCell(row[1]) + " |\n")
	}

	b.WriteString("\n## Replay\n\n")
	b.WriteString("| Time | Type | Status | Actor | Detail |\n| --- | --- | --- | --- | --- |\n")
	for _, e := range k8sExecSessionReplay(sess) {
		detail := strings.TrimSpace(fmt.Sprint(e["title"]) + " · " + fmt.Sprint(e["detail"]))
		b.WriteString("| " + markdownTableCell(e["at"]) + " | " + markdownTableCell(e["category"]) + " | " + markdownTableCell(e["status"]) + " | " + markdownTableCell(e["actor"]) + " | " + markdownTableCell(detail) + " |\n")
	}

	b.WriteString("\n## Policy Result\n\n")
	b.WriteString("```json\n" + string(policyJSON) + "\n```\n")

	b.WriteString("\n## Execution Output Sample\n\n")
	if strings.TrimSpace(sess.OutputSample) == "" && strings.TrimSpace(sess.ErrorMessage) == "" {
		b.WriteString("_No execution output was stored._\n")
	} else {
		output := sess.OutputSample
		if strings.TrimSpace(sess.ErrorMessage) != "" {
			output += "\n[error]\n" + sess.ErrorMessage
		}
		b.WriteString("```\n" + strings.ReplaceAll(output, "```", "'''") + "\n```\n")
	}
	return b.String()
}

func markdownTableCell(v any) string {
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" || s == "<nil>" {
		return "-"
	}
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}

func markdownInlineCode(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, "`", "'")
}

func (s *Server) executeK8sPodExecSession(w http.ResponseWriter, r *http.Request, sess store.K8sPodExecSession) {
	if sess.Status != "ready" {
		writeOpenAIError(w, http.StatusConflict, "exec session must be ready before execute (current: "+sess.Status+")", "invalid_request_error", "exec_session_not_ready")
		return
	}
	if risk, reason := classifyTerminalCommandRisk(sess.Command); risk == "critical" {
		writeOpenAIError(w, http.StatusConflict, "critical command cannot be executed: "+reason, "invalid_request_error", "exec_command_blocked")
		return
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), sess.ClusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	execClient, ok := client.(kube.PodCommandExecutor)
	if !ok {
		updated, _ := s.db.UpdateK8sPodExecSessionExecution(r.Context(), sess.ID, "failed", adminID(r), "", "cluster client does not support Pod exec", 1)
		writeJSON(w, http.StatusOK, map[string]any{"session": updated, "executed": false, "error": "cluster client does not support Pod exec"})
		return
	}
	timeout := execSessionTimeout(sess.MaxSessionMinutes)
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	start := time.Now()
	result, execErr := execClient.PodExec(ctx, sess.Namespace, sess.Pod, kube.PodExecOptions{
		Container:  sess.Container,
		Command:    sess.Command,
		LimitBytes: 256 * 1024,
	})
	durationMS := time.Since(start).Milliseconds()
	stdout := analyzer.MaskSensitive(result.Stdout)
	stderr := analyzer.MaskSensitive(result.Stderr)
	exitCode := result.ExitCode
	status := "completed"
	errMsg := ""
	if execErr != nil {
		status = "failed"
		errMsg = analyzer.MaskSensitive(execErr.Error())
		if exitCode == 0 {
			exitCode = 1
		}
	} else if exitCode != 0 {
		status = "failed"
		errMsg = firstNonEmpty(stderr, fmt.Sprintf("command exited with code %d", exitCode))
	}
	outputSample := truncateRunes(strings.TrimSpace(stdout+"\n"+stderr), 8000)
	updated, err := s.db.UpdateK8sPodExecSessionExecution(r.Context(), sess.ID, status, adminID(r), outputSample, truncateRunes(errMsg, 2000), exitCode)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "exec session not found: "+sess.ID, "invalid_request_error", "exec_session_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_exec_session_update_failed")
		return
	}
	s.auditAdmin(r, "k8s.pod.exec_session.execute", sess.ID, auditJSON(map[string]any{
		"cluster_id": sess.ClusterID, "namespace": sess.Namespace, "pod": sess.Pod, "container": sess.Container,
		"role": sess.Role, "status": status, "exit_code": exitCode, "duration_ms": durationMS,
	}))
	writeJSON(w, http.StatusOK, map[string]any{
		"session":  updated,
		"executed": status == "completed",
		"result": map[string]any{
			"stdout": stdout, "stderr": stderr, "exit_code": exitCode, "masked": true, "duration_ms": durationMS,
		},
		"error": errMsg,
	})
}

func (s *Server) handleK8sPodExecSessions(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	switch r.Method {
	case http.MethodGet:
		s.writeK8sPodExecSessions(w, r, namespace, pod)
	case http.MethodPost:
		s.requestK8sPodExecSession(w, r, namespace, pod)
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) writeK8sPodExecSessions(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	q := r.URL.Query()
	filter := store.K8sPodExecSessionFilter{
		ClusterID: strings.TrimSpace(q.Get("cluster_id")),
		Namespace: firstNonEmpty(namespace, strings.TrimSpace(q.Get("namespace"))),
		Pod:       firstNonEmpty(pod, strings.TrimSpace(q.Get("pod"))),
		Status:    strings.TrimSpace(q.Get("status")),
		Limit:     recentLimit(r),
	}
	sessions, err := s.db.ListK8sPodExecSessions(r.Context(), filter)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_exec_sessions_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) requestK8sPodExecSession(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	var in struct {
		ClusterID   string            `json:"cluster_id"`
		Container   string            `json:"container"`
		Command     string            `json:"command"`
		Role        string            `json:"role"`
		Reason      string            `json:"reason"`
		PodLabels   map[string]string `json:"pod_labels"`
		RequestedBy string            `json:"requested_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	command := strings.TrimSpace(in.Command)
	if command == "" {
		writeOpenAIError(w, http.StatusBadRequest, "command is required", "invalid_request_error", "missing_command")
		return
	}
	clusterID := strings.TrimSpace(firstNonEmpty(in.ClusterID, r.URL.Query().Get("cluster_id")))
	var item store.K8sInventoryItem
	if clusterID != "" {
		found, err := s.db.GetK8sInventoryItem(r.Context(), clusterID, "Pod", namespace, pod)
		if err != nil {
			writeOpenAIError(w, http.StatusNotFound, "pod not found", "invalid_request_error", "pod_not_found")
			return
		}
		item = found
	} else {
		resolvedClusterID, found, ok := s.resolvePodInventory(w, r, namespace, pod)
		if !ok {
			return
		}
		clusterID, item = resolvedClusterID, found
	}
	role := strings.ToLower(strings.TrimSpace(firstNonEmpty(in.Role, "viewer")))
	container := strings.TrimSpace(firstNonEmpty(in.Container, defaultContainerName(item)))
	labels := mergePodLabels(item.Labels, in.PodLabels)
	policies, err := s.db.ListK8sTerminalPolicies(r.Context(), store.K8sTerminalPolicyFilter{Role: role, ClusterID: clusterID, Enabled: "true", Limit: 500})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_terminal_policy_eval_failed")
		return
	}
	result := evaluateTerminalPolicy(terminalPolicyEvalRequest{
		Role:      role,
		ClusterID: clusterID,
		Namespace: namespace,
		Pod:       pod,
		PodLabels: labels,
		Command:   command,
	}, policies)
	status := "denied"
	nextAction := "blocked"
	if result.Allowed && result.RequireApproval {
		status = "pending_approval"
		nextAction = "approval_required"
	} else if result.Allowed {
		status = "ready"
		nextAction = "connect_exec_transport"
	}
	policyResult, _ := json.Marshal(result)
	requestedBy := strings.TrimSpace(firstNonEmpty(in.RequestedBy, adminID(r)))
	session := store.K8sPodExecSession{
		ID:                newID("k8sexec"),
		ClusterID:         clusterID,
		Namespace:         namespace,
		Pod:               pod,
		Container:         container,
		Command:           command,
		Role:              role,
		RequestedBy:       requestedBy,
		Status:            status,
		RiskLevel:         result.RiskLevel,
		RequireApproval:   result.RequireApproval,
		AuditEnabled:      result.AuditEnabled,
		MaxSessionMinutes: result.MaxSessionMinutes,
		PolicyResult:      string(policyResult),
		Reason:            strings.TrimSpace(firstNonEmpty(in.Reason, result.Reason)),
	}
	if err := s.db.CreateK8sPodExecSession(r.Context(), &session); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_exec_session_create_failed")
		return
	}
	s.auditAdmin(r, "k8s.pod.exec_session.request", session.ID, auditJSON(map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod, "container": container,
		"role": role, "status": status, "risk": result.RiskLevel, "matched_policies": result.MatchedPolicies,
	}))
	writeJSON(w, http.StatusCreated, map[string]any{
		"session":       session,
		"policy_result": result,
		"next_action":   nextAction,
		"executed":      false,
		"note":          "exec transport is not opened by this endpoint; the policy-gated session request is recorded for approval/audit",
	})
}

func mergePodLabels(base, override map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func execSessionTimeout(maxSessionMinutes int) time.Duration {
	if maxSessionMinutes <= 0 {
		maxSessionMinutes = 1
	}
	if maxSessionMinutes > 10 {
		maxSessionMinutes = 10
	}
	return time.Duration(maxSessionMinutes) * time.Minute
}

func decisionStatusLabel(status string) string {
	switch status {
	case "ready", "completed", "failed":
		return "approved"
	case "rejected":
		return "rejected"
	default:
		return status
	}
}
