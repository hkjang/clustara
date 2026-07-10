package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	k8saction "clustara/internal/action"
	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Developer Self-Service Request Center (CLU-NEXT-01/02).
//
// A developer raises an operational request; it is mapped onto an EXISTING approval flow. Role-aware
// operators can choose "request only", "approve", or "approve and execute"; developer/viewer roles
// stay on the safe request-only path. Config edits are bridged to Config Change Control, and read-only
// requests (log access) return a direct link.

// handleK8sDevRequest creates a developer request and bridges it to the right approval flow.
// GET  /admin/k8s/dev-requests → supported types
// POST /admin/k8s/dev-requests {type, cluster_id, namespace, resource_kind, resource_name, replicas, reason, mode}
func (s *Server) handleK8sDevRequest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"types": analyzer.SupportedDevRequestTypes(),
			"modes": []string{"request", "approve", "execute"},
			"note":  "개발자 셀프서비스 요청 — 변경은 액션 승인함 또는 Config Change Control로 연결됩니다. super_admin/admin은 실행 가능 작업을 즉시 승인·실행할 수 있습니다.",
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
		Mode         string `json:"mode"` // request | approve | execute
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
		role := s.effectiveAdminRole(r)
		mode := normalizeDevRequestMode(in.Mode)
		if mode == "" {
			mode = "request" // Backward-compatible API default; the SPA sends the role-aware default.
		}
		if _, err := s.db.GetK8sCluster(r.Context(), in.ClusterID); errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+in.ClusterID, "invalid_request_error", "cluster_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
			return
		}

		params := map[string]any{}
		if in.Type == analyzer.DevReqScale {
			params["replicas"] = in.Replicas
		}
		decision := k8saction.Classify(plan.Action)
		all, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: in.ClusterID, Limit: 2000})
		var target store.K8sInventoryItem
		if t, err := s.db.GetK8sInventoryItem(r.Context(), in.ClusterID, in.ResourceKind, in.Namespace, in.ResourceName); err == nil {
			target = t
		}
		impact := k8saction.AssessImpact(plan.Action, params, target, all)
		status := "pending"
		if decision.RequiresApproval || len(impact.Blockers) > 0 || plan.RequiresApproval {
			status = "approval_required"
		}
		diff := "요청 요약: " + plan.Summary + "\n영향도: " + impact.Summary
		if len(impact.Blockers) > 0 {
			diff += "\n승인 필요 사유: " + strings.Join(impact.Blockers, " · ")
		}
		req := store.K8sActionRequest{
			ID: newID("k8sact"), ClusterID: strings.TrimSpace(in.ClusterID), Namespace: strings.TrimSpace(in.Namespace),
			ResourceKind: strings.TrimSpace(in.ResourceKind), ResourceName: strings.TrimSpace(in.ResourceName),
			Action: plan.Action, Parameters: params, RiskLevel: firstNonEmpty(decision.RiskLevel, plan.RiskLevel), Status: status,
			RequestedBy: adminID(r), DryRunDiff: diff, Result: firstNonEmpty(in.Reason, plan.Summary),
			IdempotencyKey: newID("idem"),
			CommandHash:    k8sActionCommandHash(strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.Namespace), strings.TrimSpace(in.ResourceKind), strings.TrimSpace(in.ResourceName), plan.Action, params),
		}
		if err := s.db.InsertK8sActionRequest(r.Context(), req); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "dev_request_failed")
			return
		}
		note := "액션 승인함에 등록되었습니다."
		modeNote := ""
		execution := map[string]any(nil)
		if mode == "approve" || mode == "execute" {
			if devRequestRoleCanApprove(role, req.RiskLevel) {
				if err := s.db.UpdateK8sActionStatus(r.Context(), req.ID, "approved", adminID(r), "role-aware approval via Developer View: "+role); err != nil {
					writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "dev_request_approval_failed")
					return
				}
				req.Status = "approved"
				note = "역할 권한으로 액션이 승인되었습니다."
			} else {
				modeNote = "현재 역할(" + role + ")과 위험도(" + req.RiskLevel + ") 기준으로 즉시 승인/실행 대신 승인 요청으로 등록했습니다."
				mode = "request"
			}
		}
		if mode == "execute" && req.Status == "approved" {
			if !plan.Executable || !k8sActionExecutable(req.Action) {
				mode = "approve"
				modeNote = "자동 실행기가 지원하지 않는 작업이라 승인 상태로 남기고 운영자가 수동 처리합니다."
			} else if !devRequestRoleCanExecute(role, req.RiskLevel) {
				mode = "approve"
				modeNote = "현재 역할(" + role + ")은 이 위험도(" + req.RiskLevel + ") 작업을 즉시 실행할 수 없어 승인 상태로 남겼습니다."
			} else {
				result := s.runApprovedK8sAction(r.Context(), adminID(r), req)
				execution = map[string]any{"http_status": result.HTTPStatus}
				if result.Err != nil {
					execution["status"] = firstNonEmpty(result.Status, "blocked")
					execution["error"] = result.Message
					modeNote = "즉시 실행이 완료되지 않았습니다. 액션 승인함에서 상태와 오류를 확인하세요."
					if result.ExecutionFailed {
						req.Status = result.Status
						req.Result = result.Message
						s.auditAdmin(r, "k8s.action.execute", "", auditJSON(map[string]any{"id": req.ID, "action": req.Action, "status": result.Status, "via": "developer_view"}))
					}
				} else {
					execution["status"] = result.Status
					execution["result"] = result.Message
					req.Status = result.Status
					req.Result = result.Message
					note = "역할 권한으로 액션이 승인되고 즉시 실행되었습니다."
					s.auditAdmin(r, "k8s.action.execute", "", auditJSON(map[string]any{"id": req.ID, "action": req.Action, "status": result.Status, "via": "developer_view"}))
				}
			}
		}
		s.auditAdmin(r, "k8s.dev_request", req.ID, auditJSON(map[string]any{"type": in.Type, "action": plan.Action, "target": req.Namespace + "/" + req.ResourceName, "mode": mode, "role": role, "status": req.Status}))
		actionUI := "#/k8s-actions" + clusterQuery(in.ClusterID)
		if modeNote != "" {
			note += " " + modeNote
		} else if req.Status == "approval_required" || req.Status == "pending" {
			note += " 운영자 승인 후 실행됩니다."
		}
		if updated, err := s.db.GetK8sActionRequest(r.Context(), req.ID); err == nil {
			req = updated
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"plan": plan, "created": "action_request", "action": req, "action_id": req.ID, "status": req.Status,
			"role": role, "mode": mode, "track_at": "/admin/k8s/actions", "approval_ui": actionUI, "action_ui": actionUI,
			"execution": execution, "note": note + executableNote(plan.Executable),
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

func (s *Server) effectiveAdminRole(r *http.Request) string {
	if claims, ok := s.currentAccessClaims(r); ok && strings.TrimSpace(claims.Role) != "" {
		return strings.ToLower(strings.TrimSpace(claims.Role))
	}
	if !s.cfg.Auth.Enabled {
		if role, _, ok := s.legacyTokenIdentity(r); ok {
			return role
		}
		return ""
	}
	return "admin"
}

func normalizeDevRequestMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "request", "approve", "execute":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return ""
	}
}

func devRequestRoleCanApprove(role, risk string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	risk = strings.ToLower(strings.TrimSpace(risk))
	switch role {
	case "super_admin", "admin":
		return true
	case "ops_admin", "operator", "approver":
		return risk == "" || risk == "low" || risk == "medium"
	default:
		return false
	}
}

func devRequestRoleCanExecute(role, risk string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	risk = strings.ToLower(strings.TrimSpace(risk))
	switch role {
	case "super_admin", "admin":
		return true
	case "operator":
		return risk == "" || risk == "low" || risk == "medium"
	default:
		return false
	}
}
