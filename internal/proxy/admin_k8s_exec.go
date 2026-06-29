package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

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
