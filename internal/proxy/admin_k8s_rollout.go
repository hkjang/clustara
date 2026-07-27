package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/kube"
	"clustara/internal/store"
)

type rolloutRequestInput struct {
	ClusterID      string `json:"clusterId"`
	Namespace      string `json:"namespace"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Reason         string `json:"reason"`
	TicketNo       string `json:"ticketNo"`
	ExecutionMode  string `json:"executionMode"`
	AutoRollback   bool   `json:"autoRollback"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type rolloutCheck struct {
	Code    string `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type rolloutPrecheck struct {
	Allowed          bool           `json:"allowed"`
	RiskLevel        string         `json:"risk_level"`
	RequiresApproval bool           `json:"requires_approval"`
	Healthy          bool           `json:"healthy"`
	Desired          int            `json:"desired"`
	Ready            int            `json:"ready"`
	Available        int            `json:"available"`
	Updated          int            `json:"updated"`
	Strategy         string         `json:"strategy"`
	Images           []string       `json:"images"`
	Checks           []rolloutCheck `json:"checks"`
	Blockers         []string       `json:"blockers"`
	Warnings         []string       `json:"warnings"`
	SuperAdminDirect bool           `json:"super_admin_direct"`
}

type namespaceRolloutTarget struct {
	Target   store.K8sInventoryItem `json:"target"`
	Precheck rolloutPrecheck        `json:"precheck"`
}

func (s *Server) handleWorkloadRolloutPrecheck(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.requireRolloutScope(w, r, "rollout:view") {
		return
	}
	var in rolloutRequestInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	check, target, err := s.rolloutPrecheck(r, in)
	if err != nil {
		s.writeRolloutLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": target, "precheck": check, "requested_target": in})
}

func (s *Server) handleNamespaceRolloutPrecheck(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.requireRolloutScope(w, r, "rollout:view") {
		return
	}
	var in rolloutRequestInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	in.ClusterID, in.Namespace = strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.Namespace)
	if in.ClusterID == "" || in.Namespace == "" {
		writeOpenAIError(w, http.StatusBadRequest, "clusterId and namespace are required", "invalid_request_error", "namespace_rollout_scope_required")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: in.ClusterID, Namespace: in.Namespace, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "namespace_rollout_lookup_failed")
		return
	}
	targets := make([]store.K8sInventoryItem, 0)
	for _, item := range items {
		if canonicalRolloutKind(item.Kind) != "" {
			targets = append(targets, item)
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Kind == targets[j].Kind {
			return targets[i].Name < targets[j].Name
		}
		return targets[i].Kind < targets[j].Kind
	})
	if len(targets) == 0 {
		writeOpenAIError(w, http.StatusNotFound, "no rollout-capable workloads in namespace", "not_found_error", "namespace_rollout_targets_not_found")
		return
	}
	if len(targets) > 100 {
		writeOpenAIError(w, http.StatusConflict, "namespace rollout is limited to 100 workloads", "invalid_request_error", "namespace_rollout_target_limit")
		return
	}
	results := make([]namespaceRolloutTarget, 0, len(targets))
	allowed := true
	for _, target := range targets {
		check, resolved, checkErr := s.rolloutPrecheck(r, rolloutRequestInput{ClusterID: in.ClusterID, Namespace: in.Namespace, Kind: target.Kind, Name: target.Name})
		if checkErr != nil {
			writeOpenAIError(w, http.StatusInternalServerError, checkErr.Error(), "server_error", "namespace_rollout_precheck_failed")
			return
		}
		allowed = allowed && check.Allowed
		results = append(results, namespaceRolloutTarget{Target: resolved, Precheck: check})
	}
	writeJSON(w, http.StatusOK, map[string]any{"cluster_id": in.ClusterID, "namespace": in.Namespace, "allowed": allowed, "target_count": len(results), "targets": results})
}

func (s *Server) handleWorkloadRollout(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.requireRolloutScope(w, r, "rollout:request") {
		return
	}
	var in rolloutRequestInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" {
		writeOpenAIError(w, http.StatusBadRequest, "reason is required", "invalid_request_error", "rollout_reason_required")
		return
	}
	if in.TimeoutSeconds <= 0 {
		in.TimeoutSeconds = 600
	}
	if in.ExecutionMode == "" {
		in.ExecutionMode = "IMMEDIATE"
	}
	check, target, err := s.rolloutPrecheck(r, in)
	if err != nil {
		s.writeRolloutLookupError(w, err)
		return
	}
	if !check.Allowed {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "rollout precheck blocked", "precheck": check})
		return
	}
	// A Pod request is deliberately executed against its owning rollout-capable
	// controller. Persist the resolved identity so audit, locking and rollback all
	// refer to the resource that Kubernetes actually restarts.
	in.Namespace, in.Kind, in.Name = target.Namespace, target.Kind, target.Name
	existing, _ := s.db.ListK8sRolloutActions(r.Context(), in.ClusterID, target.UID, 20)
	for _, x := range existing {
		if rolloutActive(x.Status) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "rollout already in progress", "rollout": x})
			return
		}
	}
	actionID := newID("k8sact")
	rolloutID := newID("rollout")
	status := "approval_required"
	directBySuperAdmin := check.SuperAdminDirect && strings.EqualFold(in.ExecutionMode, "IMMEDIATE")
	canExecute := s.rolloutScopeAllowed(r, "rollout:execute")
	if (!check.RequiresApproval || directBySuperAdmin) && canExecute && strings.EqualFold(in.ExecutionMode, "IMMEDIATE") {
		status = "approved"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	params := map[string]any{"reason": in.Reason, "ticket_no": in.TicketNo, "rollout_id": rolloutID, "auto_rollback": in.AutoRollback, "timeout_seconds": in.TimeoutSeconds}
	act := store.K8sActionRequest{ID: actionID, ClusterID: in.ClusterID, Namespace: in.Namespace, ResourceKind: in.Kind, ResourceName: in.Name,
		Action: "rollout_restart", Parameters: params, RiskLevel: check.RiskLevel, Status: status, RequestedBy: adminID(r), TargetUID: target.UID,
		TargetResourceVersion: k8sActionTargetResourceVersion(target), IdempotencyKey: firstNonEmpty(strings.TrimSpace(r.Header.Get("Idempotency-Key")), newID("idem")),
		CommandHash: k8sActionCommandHash(in.ClusterID, in.Namespace, in.Kind, in.Name, "rollout_restart", params),
		DryRunDiff:  fmt.Sprintf("롤아웃 사전검사 통과: Ready %d/%d · Available %d · 전략 %s", check.Ready, check.Desired, check.Available, check.Strategy)}
	if directBySuperAdmin {
		act.ApprovedBy, act.ApprovedAt = adminID(r), now
		act.DryRunDiff += "\n최고 관리자 즉시 실행: 경고·일반 승인 단계를 우회했으며 차단 항목은 없습니다."
	}
	if err := s.db.InsertK8sActionRequest(r.Context(), act); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "rollout_action_save_failed")
		return
	}
	roll := store.K8sRolloutAction{ID: rolloutID, ActionRequestID: actionID, ClusterID: in.ClusterID, Namespace: in.Namespace, ResourceKind: in.Kind,
		ResourceName: in.Name, ResourceUID: target.UID, RequestedBy: adminID(r), Reason: in.Reason, TicketNo: in.TicketNo,
		ExecutionMode: strings.ToUpper(in.ExecutionMode), Status: status, RiskLevel: check.RiskLevel, PreviousRevision: rolloutRevision(target),
		PreviousSpecHash: hashJSON(target.Spec), AutoRollback: in.AutoRollback, TimeoutSeconds: in.TimeoutSeconds,
		DesiredReplicas: check.Desired, UpdatedReplicas: check.Updated, ReadyReplicas: check.Ready, AvailableReplicas: check.Available,
		UnavailableReplicas: maxInt(0, check.Desired-check.Available), Precheck: map[string]any{"checks": check.Checks, "warnings": check.Warnings}}
	if template, ok := target.Spec["template"].(map[string]any); ok {
		roll.PreviousTemplate = template
	}
	if directBySuperAdmin {
		roll.ApprovedBy, roll.ApprovedAt = adminID(r), now
	}
	if err := s.db.InsertK8sRolloutAction(r.Context(), roll); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeOpenAIError(w, http.StatusConflict, "rollout already in progress", "invalid_request_error", "rollout_in_progress")
		} else {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "rollout_save_failed")
		}
		return
	}
	_ = s.db.AppendK8sRolloutEvent(r.Context(), store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: roll.ID,
		Status: status, Stage: "requested", Message: "롤아웃 요청 접수", Evidence: map[string]any{"precheck": check, "requested_by": adminID(r)}})
	if status == "approval_required" {
		s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("롤아웃 승인 대기: %s/%s %s/%s · 요청자 %s · 사유 %s",
			roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, roll.RequestedBy, roll.Reason))
	}
	s.auditAdmin(r, "k8s.rollout.request", roll.ID, auditJSON(roll))
	if status == "approved" {
		result := s.runApprovedK8sAction(r.Context(), adminID(r), act)
		roll, _ = s.db.GetK8sRolloutAction(r.Context(), roll.ID)
		if result.Err != nil {
			s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("롤아웃 실행 실패: %s/%s %s/%s · %s",
				roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, result.Message))
			writeJSON(w, result.HTTPStatus, map[string]any{"rollout": roll, "action": act, "precheck": check, "error": result.Message})
			return
		}
		s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("롤아웃 실행 시작: %s/%s %s/%s · action %s",
			roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, roll.ID))
		roll, _ = s.reconcileRollout(r, roll)
		writeJSON(w, http.StatusAccepted, map[string]any{"rollout": roll, "action": act, "precheck": check})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"rollout": roll, "action": act, "precheck": check})
}

func (s *Server) handleRolloutByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/rollouts/"), "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "rollout id required", "invalid_request_error", "rollout_id_required")
		return
	}
	roll, err := s.db.GetK8sRolloutAction(r.Context(), parts[0])
	if err != nil {
		s.writeRolloutLookupError(w, err)
		return
	}
	if len(parts) > 1 && parts[1] == "stream" {
		if !s.requireRolloutScope(w, r, "rollout:view") {
			return
		}
		s.streamRollout(w, r, roll)
		return
	}
	if len(parts) > 1 && parts[1] == "evidence" {
		if r.Method != http.MethodGet || !s.requireRolloutScope(w, r, "rollout:view") {
			return
		}
		s.writeRolloutEvidence(w, r, roll)
		return
	}
	if len(parts) > 1 {
		if r.Method != http.MethodPost {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		switch parts[1] {
		case "approve":
			if !s.requireRolloutScope(w, r, "rollout:approve") || !s.requireRolloutScope(w, r, "rollout:execute") {
				return
			}
			if err := s.db.UpdateK8sActionStatus(r.Context(), roll.ActionRequestID, "approved", adminID(r), "rollout approved"); err != nil {
				writeOpenAIError(w, http.StatusConflict, err.Error(), "invalid_request_error", "rollout_approve_failed")
				return
			}
			act, _ := s.db.GetK8sActionRequest(r.Context(), roll.ActionRequestID)
			result := s.runApprovedK8sAction(r.Context(), adminID(r), act)
			if result.Err != nil {
				s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("승인된 롤아웃 실행 실패: %s/%s %s/%s · %s",
					roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, result.Message))
				writeJSON(w, result.HTTPStatus, map[string]any{"error": result.Message})
				return
			}
			s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("승인된 롤아웃 실행 시작: %s/%s %s/%s · action %s",
				roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, roll.ID))
		case "reject":
			if !s.requireRolloutScope(w, r, "rollout:approve") {
				return
			}
			if err := s.db.UpdateK8sActionStatus(r.Context(), roll.ActionRequestID, "rejected", adminID(r), "rollout rejected"); err != nil {
				writeOpenAIError(w, http.StatusConflict, err.Error(), "invalid_request_error", "rollout_reject_failed")
				return
			}
			roll.Status = "rejected"
			roll.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
			_ = s.db.UpdateK8sRolloutProgress(r.Context(), roll)
		default:
			writeOpenAIError(w, http.StatusNotImplemented, "pause/resume/rollback is not supported in this release", "invalid_request_error", "rollout_command_unsupported")
			return
		}
	} else if !s.requireRolloutScope(w, r, "rollout:view") {
		return
	}
	roll, err = s.reconcileRollout(r, roll)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "rollout_reconcile_failed")
		return
	}
	pods, _ := s.db.ListK8sRolloutPodTransitions(r.Context(), roll.ID)
	events, _ := s.db.ListK8sRolloutEvents(r.Context(), roll.ID)
	writeJSON(w, http.StatusOK, map[string]any{"rollout": roll, "pods": pods, "events": events, "progress_percent": rolloutProgress(roll)})
}

func (s *Server) handleResourceRollouts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.requireRolloutScope(w, r, "rollout:view") {
		return
	}
	trim := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/resources/"), "/")
	parts := strings.Split(trim, "/")
	if len(parts) != 2 || parts[1] != "rollouts" {
		writeOpenAIError(w, http.StatusBadRequest, "resource uid and rollouts path required", "invalid_request_error", "bad_resource_rollout_path")
		return
	}
	items, err := s.db.ListK8sRolloutActions(r.Context(), r.URL.Query().Get("cluster_id"), parts[0], intParam(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "rollout_history_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rollouts": items})
}

func (s *Server) rolloutPrecheck(r *http.Request, in rolloutRequestInput) (rolloutPrecheck, store.K8sInventoryItem, error) {
	var out rolloutPrecheck
	if strings.EqualFold(strings.TrimSpace(in.Kind), "pod") || strings.EqualFold(strings.TrimSpace(in.Kind), "pods") {
		resolved, err := s.resolvePodRolloutTarget(r, in)
		if err != nil {
			return out, store.K8sInventoryItem{}, err
		}
		in.Namespace, in.Kind, in.Name = resolved.Namespace, resolved.Kind, resolved.Name
	}
	kind := canonicalRolloutKind(in.Kind)
	if kind == "" {
		return out, store.K8sInventoryItem{}, fmt.Errorf("unsupported rollout kind")
	}
	target, err := s.db.GetK8sInventoryItem(r.Context(), in.ClusterID, kind, in.Namespace, in.Name)
	if err != nil {
		return out, target, err
	}
	out.Desired = rolloutDesired(target)
	if kind == "DaemonSet" {
		out.Ready = intAny(target.StatusObject["numberReady"])
	} else {
		out.Ready = intAny(target.StatusObject["readyReplicas"])
	}
	out.Available = rolloutAvailable(target)
	out.Updated = rolloutUpdated(target)
	out.Strategy = rolloutStrategy(target)
	out.Images = rolloutImages(target)
	out.Healthy = out.Desired > 0 && out.Ready == out.Desired && out.Available == out.Desired && !rolloutConditionFailed(target) && target.DeletionTimestamp == ""
	add := func(code, status, msg string) {
		out.Checks = append(out.Checks, rolloutCheck{code, status, msg})
		if status == "blocked" {
			out.Blockers = append(out.Blockers, msg)
		}
		if status == "warning" {
			out.Warnings = append(out.Warnings, msg)
		}
	}
	if target.DeletionTimestamp != "" {
		add("deleting", "blocked", "리소스가 삭제 처리 중입니다.")
	} else {
		add("deleting", "passed", "삭제 처리 중이 아닙니다.")
	}
	if rolloutInProgress(target) {
		add("in_progress", "blocked", "기존 Kubernetes rollout이 진행 중입니다.")
	} else {
		add("in_progress", "passed", "진행 중인 rollout이 없습니다.")
	}
	if !out.Healthy {
		add("healthy", "blocked", fmt.Sprintf("정상 기준 미충족: Ready %d/%d, Available %d/%d", out.Ready, out.Desired, out.Available, out.Desired))
	} else {
		add("healthy", "passed", "Ready·Available replica가 목표값과 일치합니다.")
	}
	if out.Desired == 1 {
		add("single_replica", "warning", "Replica 1은 서비스 중단 위험이 있습니다.")
	}
	if out.Desired == 0 {
		add("zero_replica", "warning", "Replica 0 상태이며 교체할 Pod가 없습니다.")
	}
	if strings.EqualFold(kind, "Deployment") && boolAny(target.Spec["paused"]) {
		add("paused", "blocked", "일시정지된 Deployment입니다.")
	}
	if (kind == "StatefulSet" || kind == "DaemonSet") && strings.EqualFold(out.Strategy, "OnDelete") {
		status := "warning"
		if kind == "DaemonSet" {
			status = "blocked"
		}
		add("on_delete", status, kind+" OnDelete 전략은 자동 Pod 교체가 보장되지 않습니다.")
	}
	all, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: in.ClusterID, Limit: 5000})
	if hasBadOwnedPod(target, all) {
		add("pod_health", "blocked", "소유 Pod에 CrashLoopBackOff 또는 ImagePullBackOff가 있습니다.")
	} else {
		add("pod_health", "passed", "차단 대상 Pod 오류가 없습니다.")
	}
	if hasNotReadyNode(all) {
		add("node_health", "warning", "NotReady 노드가 있어 신규 Pod 배치가 지연될 수 있습니다.")
	}
	if kind == "StatefulSet" && hasBadPVC(in.Namespace, all) {
		add("pvc", "blocked", "Pending 또는 Lost PVC가 있어 StatefulSet rollout을 차단합니다.")
	}
	pdbFound, pdbBlocked := pdbSafety(target, all)
	if pdbBlocked {
		add("pdb", "blocked", "PodDisruptionBudget의 disruptionsAllowed가 0입니다.")
	} else if pdbFound {
		add("pdb", "passed", "PodDisruptionBudget이 중단을 허용합니다.")
	} else {
		add("pdb", "warning", "일치하는 PodDisruptionBudget을 확인할 수 없습니다.")
	}
	out.RiskLevel = "low"
	if out.Desired <= 1 || kind != "Deployment" || len(out.Warnings) > 1 {
		out.RiskLevel = "high"
	} else if strings.Contains(strings.ToLower(in.ClusterID), "prod") || strings.Contains(strings.ToLower(in.Namespace), "prod") {
		out.RiskLevel = "medium"
	}
	out.RequiresApproval = out.RiskLevel != "low"
	out.Allowed = len(out.Blockers) == 0
	out.SuperAdminDirect = s.rolloutSuperAdmin(r) && out.Allowed
	return out, target, nil
}

func (s *Server) resolvePodRolloutTarget(r *http.Request, in rolloutRequestInput) (store.K8sInventoryItem, error) {
	pod, err := s.db.GetK8sInventoryItem(r.Context(), in.ClusterID, "Pod", in.Namespace, in.Name)
	if err != nil {
		return store.K8sInventoryItem{}, err
	}
	kind, name := podOwner(pod.Spec)
	if strings.EqualFold(kind, "ReplicaSet") {
		rs, rsErr := s.db.GetK8sInventoryItem(r.Context(), in.ClusterID, "ReplicaSet", in.Namespace, name)
		if rsErr != nil {
			return store.K8sInventoryItem{}, fmt.Errorf("Pod owner ReplicaSet %q could not be resolved: %w", name, rsErr)
		}
		kind, name = podOwner(rs.Spec)
	}
	kind = canonicalRolloutKind(kind)
	if kind == "" || strings.TrimSpace(name) == "" {
		return store.K8sInventoryItem{}, fmt.Errorf("Pod %s/%s is not owned by a Deployment, StatefulSet, or DaemonSet", in.Namespace, in.Name)
	}
	return s.db.GetK8sInventoryItem(r.Context(), in.ClusterID, kind, in.Namespace, name)
}

func (s *Server) rolloutSuperAdmin(r *http.Request) bool {
	if claims, ok := s.currentAccessClaims(r); ok {
		return strings.EqualFold(claims.Role, "super_admin")
	}
	return !s.cfg.Auth.Enabled
}

func (s *Server) requireRolloutScope(w http.ResponseWriter, r *http.Request, scope string) bool {
	if s.rolloutScopeAllowed(r, scope) {
		return true
	}
	writeOpenAIError(w, http.StatusForbidden, "missing required scope: "+scope, "invalid_request_error", "insufficient_scope")
	return false
}

func (s *Server) rolloutScopeAllowed(r *http.Request, scope string) bool {
	if !s.cfg.Auth.Enabled {
		return true
	}
	claims, ok := s.currentAccessClaims(r)
	if ok && (strings.EqualFold(claims.Role, "super_admin") || hasScope(claims.Scopes, scope)) {
		return true
	}
	return false
}

func (s *Server) writeRolloutEvidence(w http.ResponseWriter, r *http.Request, roll store.K8sRolloutAction) {
	pods, _ := s.db.ListK8sRolloutPodTransitions(r.Context(), roll.ID)
	events, _ := s.db.ListK8sRolloutEvents(r.Context(), roll.ID)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="clustara-rollout-%s-evidence.json"`, roll.ID))
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": "1.0", "generated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"rollout": roll, "events": events, "pod_transitions": pods,
	})
}

func (s *Server) reconcileRollout(r *http.Request, roll store.K8sRolloutAction) (store.K8sRolloutAction, error) {
	previousStatus := roll.Status
	target, err := s.db.GetK8sInventoryItem(r.Context(), roll.ClusterID, roll.ResourceKind, roll.Namespace, roll.ResourceName)
	if err != nil {
		return roll, nil
	}
	roll.DesiredReplicas = rolloutDesired(target)
	roll.UpdatedReplicas = rolloutUpdated(target)
	if target.Kind == "DaemonSet" {
		roll.ReadyReplicas = intAny(target.StatusObject["numberReady"])
	} else {
		roll.ReadyReplicas = intAny(target.StatusObject["readyReplicas"])
	}
	roll.AvailableReplicas = rolloutAvailable(target)
	roll.UnavailableReplicas = maxInt(0, roll.DesiredReplicas-roll.AvailableReplicas)
	roll.TargetRevision = rolloutRevision(target)
	roll.TargetSpecHash = hashJSON(target.Spec)
	if roll.StartedAt != "" {
		start, _ := time.Parse(time.RFC3339Nano, roll.StartedAt)
		roll.DurationMS = time.Since(start).Milliseconds()
		if rolloutConditionFailed(target) {
			roll.Status = "failed"
			roll.FailureReason = "ProgressDeadlineExceeded 또는 ReplicaFailure"
			roll.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if roll.DesiredReplicas > 0 && roll.UpdatedReplicas >= roll.DesiredReplicas && roll.ReadyReplicas >= roll.DesiredReplicas && roll.AvailableReplicas >= roll.DesiredReplicas {
			roll.Status = "succeeded"
			roll.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if roll.TimeoutSeconds > 0 && roll.DurationMS > int64(roll.TimeoutSeconds)*1000 && roll.Status != "succeeded" {
			roll.Status = "timed_out"
			roll.FailureReason = "rollout timeout"
			roll.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
	all, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: roll.ClusterID, Kind: "Pod", Namespace: roll.Namespace, Limit: 2000})
	for _, pod := range all {
		if !podOwnedByWorkload(pod, target) {
			continue
		}
		life, _ := s.db.GetK8sPodLifecycleByName(r.Context(), roll.ClusterID, pod.Namespace, pod.Name, pod.UID)
		_ = s.db.UpsertK8sRolloutPodTransition(r.Context(), store.K8sRolloutPodTransition{ID: "rollpod_" + roll.ID + "_" + pod.UID, ActionID: roll.ID, PodUID: pod.UID, PodName: pod.Name,
			NodeName: textMap(pod.Spec, "nodeName"), Revision: firstNonEmpty(pod.Labels["pod-template-hash"], pod.Labels["controller-revision-hash"]),
			CreatedAt: life.CreatedAt, ScheduledAt: life.ScheduledAt, ContainerStartedAt: firstContainerStarted(pod.StatusObject), ReadyAt: life.ReadyAt,
			TerminatingAt: pod.DeletionTimestamp, Result: pod.Status, FailureReason: textMap(pod.StatusObject, "reason"), ObservedAt: pod.ObservedAt})
	}
	if err := s.db.UpdateK8sRolloutProgress(r.Context(), roll); err != nil {
		return roll, err
	}
	if roll.Status != previousStatus {
		_ = s.db.AppendK8sRolloutEvent(r.Context(), store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: roll.ID,
			Status: roll.Status, Stage: rolloutEventStage(roll.Status), Message: firstNonEmpty(roll.FailureReason, "롤아웃 상태 전환"),
			Evidence: map[string]any{"desired": roll.DesiredReplicas, "updated": roll.UpdatedReplicas, "ready": roll.ReadyReplicas, "available": roll.AvailableReplicas}})
		if roll.Status == "succeeded" {
			s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("롤아웃 성공: %s/%s %s/%s · Ready %d/%d · %s",
				roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, roll.ReadyReplicas, roll.DesiredReplicas,
				(time.Duration(roll.DurationMS)*time.Millisecond).Round(time.Second)))
		} else if roll.Status == "failed" || roll.Status == "timed_out" {
			s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("롤아웃 %s: %s/%s %s/%s · %s",
				roll.Status, roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, roll.FailureReason))
		}
	}
	if (roll.Status == "failed" || roll.Status == "timed_out") && roll.AutoRollback && roll.RollbackStatus == "" {
		roll = s.autoRollbackDeployment(r, roll)
		_ = s.db.UpdateK8sRolloutProgress(r.Context(), roll)
	}
	return s.db.GetK8sRolloutAction(r.Context(), roll.ID)
}

func (s *Server) autoRollbackDeployment(r *http.Request, roll store.K8sRolloutAction) store.K8sRolloutAction {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if !strings.EqualFold(roll.ResourceKind, "Deployment") {
		roll.RollbackStatus = "manual_required"
		roll.RollbackFailureReason = "StatefulSet·DaemonSet 자동 롤백은 안전 정책상 지원하지 않습니다."
		return roll
	}
	if len(roll.PreviousTemplate) == 0 {
		roll.RollbackStatus = "manual_required"
		roll.RollbackFailureReason = "저장된 이전 Pod Template이 없습니다."
		return roll
	}
	roll.RollbackStatus, roll.RollbackStartedAt = "running", now
	_ = s.db.UpdateK8sRolloutProgress(r.Context(), roll)
	cluster, err := s.db.GetK8sCluster(r.Context(), roll.ClusterID)
	if err == nil {
		var client kube.Client
		client, err = s.k8sClientForCluster(r.Context(), cluster)
		if err == nil {
			exec, ok := client.(kube.RolloutRollbackExecutor)
			if !ok {
				err = errors.New("cluster client does not support rollout rollback")
			} else {
				err = exec.RollbackDeploymentTemplate(r.Context(), roll.Namespace, roll.ResourceName, roll.PreviousTemplate,
					kube.RolloutRestartMetadata{RestartedBy: adminID(r), ActionID: roll.ID, Reason: "automatic rollback"})
			}
		}
	}
	if err != nil {
		roll.RollbackStatus, roll.RollbackFailureReason = "failed", err.Error()
	} else {
		roll.RollbackStatus, roll.RollbackCompletedAt = "requested", time.Now().UTC().Format(time.RFC3339Nano)
	}
	_ = s.db.AppendK8sRolloutEvent(r.Context(), store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: roll.ID,
		Status: roll.Status, Stage: "rollback", Message: firstNonEmpty(roll.RollbackFailureReason, "이전 Pod Template 자동 롤백 요청 완료"),
		Evidence: map[string]any{"rollback_status": roll.RollbackStatus}})
	s.notifyMattermost(r.Context(), "k8s_rollout", fmt.Sprintf("Deployment 자동 롤백 %s: %s/%s %s · %s",
		roll.RollbackStatus, roll.ClusterID, roll.Namespace, roll.ResourceName, firstNonEmpty(roll.RollbackFailureReason, "이전 Pod Template 복원 요청")))
	return roll
}

func rolloutEventStage(status string) string {
	switch status {
	case "succeeded":
		return "completed"
	case "failed", "timed_out":
		return "failed"
	case "monitoring":
		return "pod_replacement"
	default:
		return status
	}
}

func (s *Server) streamRollout(w http.ResponseWriter, r *http.Request, roll store.K8sRolloutAction) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeOpenAIError(w, http.StatusNotImplemented, "streaming unsupported", "server_error", "sse_unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		current, _ := s.reconcileRollout(r, roll)
		pods, _ := s.db.ListK8sRolloutPodTransitions(r.Context(), roll.ID)
		payload, _ := json.Marshal(map[string]any{"rollout": current, "pods": pods, "progress_percent": rolloutProgress(current)})
		_, _ = fmt.Fprintf(w, "event: progress\ndata: %s\n\n", payload)
		flusher.Flush()
		if !rolloutActive(current.Status) {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			roll = current
		}
	}
}

func (s *Server) writeRolloutLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "rollout target not found", "not_found_error", "rollout_target_not_found")
		return
	}
	writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "rollout_invalid")
}

func canonicalRolloutKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "deployment", "deployments":
		return "Deployment"
	case "statefulset", "statefulsets":
		return "StatefulSet"
	case "daemonset", "daemonsets":
		return "DaemonSet"
	}
	return ""
}
func rolloutDesired(it store.K8sInventoryItem) int {
	if it.Kind == "DaemonSet" {
		return intAny(it.StatusObject["desiredNumberScheduled"])
	}
	return intAny(firstAny(it.Spec["replicas"], it.StatusObject["replicas"]))
}
func rolloutAvailable(it store.K8sInventoryItem) int {
	if it.Kind == "DaemonSet" {
		return intAny(it.StatusObject["numberAvailable"])
	}
	return intAny(it.StatusObject["availableReplicas"])
}
func rolloutUpdated(it store.K8sInventoryItem) int {
	if it.Kind == "DaemonSet" {
		return intAny(it.StatusObject["updatedNumberScheduled"])
	}
	return intAny(it.StatusObject["updatedReplicas"])
}
func rolloutStrategy(it store.K8sInventoryItem) string {
	m, _ := it.Spec["updateStrategy"].(map[string]any)
	if it.Kind == "Deployment" {
		m, _ = it.Spec["strategy"].(map[string]any)
	}
	return firstNonEmpty(textMap(m, "type"), "RollingUpdate")
}
func rolloutRevision(it store.K8sInventoryItem) string {
	return firstNonEmpty(it.Annotations["deployment.kubernetes.io/revision"], textMap(it.StatusObject, "currentRevision"), textMap(it.StatusObject, "updateRevision"))
}
func rolloutImages(it store.K8sInventoryItem) []string {
	out := []string{}
	tpl, _ := it.Spec["template"].(map[string]any)
	spec, _ := tpl["spec"].(map[string]any)
	for _, raw := range asSliceAny(spec["containers"]) {
		m, _ := raw.(map[string]any)
		if v := textMap(m, "image"); v != "" {
			out = append(out, v)
		}
	}
	return out
}
func rolloutInProgress(it store.K8sInventoryItem) bool {
	return rolloutUpdated(it) < rolloutDesired(it) || rolloutAvailable(it) < rolloutDesired(it)
}
func rolloutConditionFailed(it store.K8sInventoryItem) bool {
	for _, raw := range asSliceAny(it.StatusObject["conditions"]) {
		m, _ := raw.(map[string]any)
		t := textMap(m, "type")
		r := textMap(m, "reason")
		if (t == "Progressing" && r == "ProgressDeadlineExceeded") || t == "ReplicaFailure" {
			return true
		}
	}
	return false
}
func rolloutActive(status string) bool {
	switch status {
	case "requested", "pending", "approval_required", "approved", "running", "monitoring":
		return true
	}
	return false
}
func rolloutProgress(a store.K8sRolloutAction) int {
	if a.DesiredReplicas <= 0 {
		return 0
	}
	v := a.UpdatedReplicas * 100 / a.DesiredReplicas
	if v > 100 {
		return 100
	}
	return v
}
func firstAny(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}
func textMap(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	v, _ := m[k].(string)
	return v
}
func hashJSON(v any) string { b, _ := json.Marshal(v); return auditHash(string(b)) }
func auditHash(v string) string {
	h := k8sActionCommandHash("", "", "", "", v, nil)
	if len(h) > 32 {
		return h[:32]
	}
	return h
}
func hasNotReadyNode(all []store.K8sInventoryItem) bool {
	for _, it := range all {
		if it.Kind == "Node" && it.Status != "Ready" && it.Status != "ready" {
			return true
		}
	}
	return false
}
func hasBadPVC(ns string, all []store.K8sInventoryItem) bool {
	for _, it := range all {
		if it.Kind == "PersistentVolumeClaim" && it.Namespace == ns && (it.Status == "Pending" || it.Status == "Lost") {
			return true
		}
	}
	return false
}
func hasBadOwnedPod(target store.K8sInventoryItem, all []store.K8sInventoryItem) bool {
	for _, p := range all {
		if p.Kind == "Pod" && podOwnedByWorkload(p, target) {
			for _, raw := range asSliceAny(p.StatusObject["containerStatuses"]) {
				m, _ := raw.(map[string]any)
				state, _ := m["state"].(map[string]any)
				waiting, _ := state["waiting"].(map[string]any)
				r := textMap(waiting, "reason")
				if r == "CrashLoopBackOff" || r == "ImagePullBackOff" || r == "ErrImagePull" {
					return true
				}
			}
		}
	}
	return false
}
func podOwnedByWorkload(pod, target store.K8sInventoryItem) bool {
	selector, _ := target.Spec["selector"].(map[string]any)
	match, _ := selector["matchLabels"].(map[string]any)
	if len(match) == 0 {
		return false
	}
	for k, v := range match {
		if pod.Labels[k] != fmt.Sprint(v) {
			return false
		}
	}
	return true
}
func pdbSafety(target store.K8sInventoryItem, all []store.K8sInventoryItem) (bool, bool) {
	for _, it := range all {
		if it.Kind != "PodDisruptionBudget" || it.Namespace != target.Namespace {
			continue
		}
		sel, _ := it.Spec["selector"].(map[string]any)
		match, _ := sel["matchLabels"].(map[string]any)
		targetSel, _ := target.Spec["selector"].(map[string]any)
		labels, _ := targetSel["matchLabels"].(map[string]any)
		same := len(match) > 0
		for k, v := range match {
			if fmt.Sprint(labels[k]) != fmt.Sprint(v) {
				same = false
			}
		}
		if same {
			return true, intAny(it.StatusObject["disruptionsAllowed"]) == 0
		}
	}
	return false, false
}
func firstContainerStarted(status map[string]any) string {
	for _, raw := range asSliceAny(status["containerStatuses"]) {
		m, _ := raw.(map[string]any)
		state, _ := m["state"].(map[string]any)
		running, _ := state["running"].(map[string]any)
		if v := textMap(running, "startedAt"); v != "" {
			return v
		}
	}
	return ""
}
