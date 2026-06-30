package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Developer Self-Service Request Center (CLU-NEXT-01/02).
//
// A developer raises an operational request; it is mapped onto an EXISTING approval flow — action
// requests are created in the Action Center (operator approves → live executor runs), config edits
// are bridged to Config Change Control, and read-only requests (log access) return a direct link.
// Clustara never executes the change here; the developer view stays a safe self-service portal.

// handleK8sDevRequest creates a developer request and bridges it to the right approval flow.
// GET  /admin/k8s/dev-requests → supported types
// POST /admin/k8s/dev-requests {type, cluster_id, namespace, resource_kind, resource_name, replicas, reason}
func (s *Server) handleK8sDevRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"types": analyzer.SupportedDevRequestTypes(),
			"note":  "개발자 셀프서비스 요청 — 모든 변경은 기존 승인 흐름(Action Center·Config Change Control)으로 연결되며 Clustara가 직접 실행하지 않습니다.",
		})
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		Type         string `json:"type"`
		ClusterID    string `json:"cluster_id"`
		Namespace    string `json:"namespace"`
		ResourceKind string `json:"resource_kind"`
		ResourceName string `json:"resource_name"`
		Replicas     int    `json:"replicas"`
		Reason       string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if in.Type == "" || strings.TrimSpace(in.ClusterID) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "type and cluster_id are required", "invalid_request_error", "missing_fields")
		return
	}
	if in.Type != analyzer.DevReqScale {
		in.Replicas = -1 // only scale uses replicas; default to "unset" so the planner validates others correctly
	}
	plan := analyzer.PlanDevRequest(analyzer.DevRequestInput{
		Type: in.Type, ClusterID: in.ClusterID, Namespace: in.Namespace,
		ResourceKind: in.ResourceKind, ResourceName: in.ResourceName, Replicas: in.Replicas, Reason: in.Reason,
	})
	if !plan.Valid {
		writeOpenAIError(w, http.StatusBadRequest, firstNonEmpty(plan.Error, "invalid request"), "invalid_request_error", "invalid_dev_request")
		return
	}

	switch plan.Flow {
	case analyzer.FlowAction:
		// Create a pending action request in the Action Center (operator approves → executor).
		params := map[string]any{}
		if in.Type == analyzer.DevReqScale {
			params["replicas"] = in.Replicas
		}
		req := store.K8sActionRequest{
			ID: newID("k8sact"), ClusterID: strings.TrimSpace(in.ClusterID), Namespace: strings.TrimSpace(in.Namespace),
			ResourceKind: strings.TrimSpace(in.ResourceKind), ResourceName: strings.TrimSpace(in.ResourceName),
			Action: plan.Action, Parameters: params, RiskLevel: plan.RiskLevel, Status: "pending_approval",
			RequestedBy: adminID(r), Result: firstNonEmpty(in.Reason, plan.Summary),
			IdempotencyKey: newID("idem"),
			CommandHash:    k8sActionCommandHash(strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.Namespace), strings.TrimSpace(in.ResourceKind), strings.TrimSpace(in.ResourceName), plan.Action, params),
		}
		if err := s.db.InsertK8sActionRequest(r.Context(), req); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "dev_request_failed")
			return
		}
		s.auditAdmin(r, "k8s.dev_request", req.ID, auditJSON(map[string]any{"type": in.Type, "action": plan.Action, "target": req.Namespace + "/" + req.ResourceName}))
		writeJSON(w, http.StatusCreated, map[string]any{
			"plan": plan, "created": "action_request", "action_id": req.ID, "status": "pending_approval",
			"track_at": "/admin/k8s/actions", "approval_ui": "#/k8s-actions" + clusterQuery(in.ClusterID),
			"note": "Action Center 승인 대기로 등록되었습니다. 운영자 승인 후 실행됩니다." + executableNote(plan.Executable),
		})
	case analyzer.FlowConfigChange:
		// Config edits carry payload Clustara won't hold; bridge the developer to the Config Change flow.
		writeJSON(w, http.StatusOK, map[string]any{
			"plan": plan, "created": "bridge", "submit_to": "/admin/k8s/config-changes", "approval_ui": "#/k8s-security",
			"payload_template": map[string]any{
				"cluster_id": in.ClusterID, "namespace": in.Namespace, "source_kind": in.ResourceKind, "source_name": in.ResourceName,
				"change_type": "update", "reason": in.Reason,
			},
			"note": "Config 변경은 Config Change Control Center로 제출하세요(영향도 자동 첨부·승인·검증). Secret/Config 원문은 Clustara에 저장하지 않습니다.",
		})
	default: // readonly (log access)
		logURL := "/admin/k8s/pods/" + url.PathEscape(in.Namespace) + "/" + url.PathEscape(in.ResourceName) + "/logs?cluster_id=" + url.QueryEscape(in.ClusterID)
		writeJSON(w, http.StatusOK, map[string]any{
			"plan": plan, "created": "readonly", "logs_endpoint": logURL,
			"logs_ui": "#/k8s-pods?" + strings.TrimPrefix(clusterQuery(in.ClusterID), "?") + "&namespace=" + url.QueryEscape(in.Namespace) + "&pod=" + url.QueryEscape(in.ResourceName),
			"note":    "로그는 읽기 전용이라 승인이 필요 없습니다. 마스킹된 로그가 제공됩니다.",
		})
	}
}

func clusterQuery(clusterID string) string {
	if strings.TrimSpace(clusterID) == "" {
		return ""
	}
	return "?cluster_id=" + url.QueryEscape(clusterID)
}

// executableNote appends a caveat when the live executor cannot run the action (manual handling).
func executableNote(executable bool) string {
	if executable {
		return ""
	}
	return " (자동 실행기가 지원하지 않는 작업이라 운영자가 수동 처리합니다.)"
}
