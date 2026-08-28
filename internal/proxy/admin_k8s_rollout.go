package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	stableParams := map[string]any{
		"reason": in.Reason, "ticket_no": in.TicketNo, "auto_rollback": in.AutoRollback,
		"timeout_seconds": in.TimeoutSeconds, "execution_mode": strings.ToUpper(in.ExecutionMode),
	}
	commandHash := k8sActionCommandHash(in.ClusterID, in.Namespace, in.Kind, in.Name, "rollout_restart", stableParams)
	if idempotencyKey != "" {
		existingAction, lookupErr := s.db.GetK8sActionRequestByIdempotencyKey(r.Context(), idempotencyKey)
		if lookupErr == nil {
			if existingAction.CommandHash != commandHash {
				writeOpenAIError(w, http.StatusConflict, "idempotency key was already used for a different rollout request", "invalid_request_error", "idempotency_conflict")
				return
			}
			existingRollout, rolloutErr := s.db.GetK8sRolloutByActionRequest(r.Context(), existingAction.ID)
			if rolloutErr != nil {
				writeOpenAIError(w, http.StatusInternalServerError, "idempotent rollout ledger is incomplete", "server_error", "rollout_ledger_incomplete")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"rollout": existingRollout, "action": existingAction, "precheck": check, "idempotent_replay": true})
			return
		}
		if !errors.Is(lookupErr, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusInternalServerError, lookupErr.Error(), "server_error", "rollout_idempotency_lookup_failed")
			return
		}
	} else {
		idempotencyKey = newID("idem")
	}
	existing, _ := s.db.ListK8sRolloutActions(r.Context(), in.ClusterID, target.UID, 20)
	for _, x := range existing {
		if rolloutNeedsReconcile(x) {
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
	params := map[string]any{
		"reason": in.Reason, "ticket_no": in.TicketNo, "rollout_id": rolloutID,
		"auto_rollback": in.AutoRollback, "timeout_seconds": in.TimeoutSeconds,
		"execution_mode": strings.ToUpper(in.ExecutionMode),
	}
	act := store.K8sActionRequest{ID: actionID, ClusterID: in.ClusterID, Namespace: in.Namespace, ResourceKind: in.Kind, ResourceName: in.Name,
		Action: "rollout_restart", Parameters: params, RiskLevel: check.RiskLevel, Status: status, RequestedBy: adminID(r), TargetUID: target.UID,
		TargetResourceVersion: k8sActionTargetResourceVersion(target), IdempotencyKey: idempotencyKey,
		CommandHash: commandHash,
		DryRunDiff:  fmt.Sprintf("롤아웃 사전검사 통과: Ready %d/%d · Available %d · 전략 %s", check.Ready, check.Desired, check.Available, check.Strategy)}
	if directBySuperAdmin {
		act.ApprovedBy, act.ApprovedAt = adminID(r), now
		act.DryRunDiff += "\n최고 관리자 즉시 실행: 경고·일반 승인 단계를 우회했으며 차단 항목은 없습니다."
	}
	roll := store.K8sRolloutAction{ID: rolloutID, ActionRequestID: actionID, ClusterID: in.ClusterID, Namespace: in.Namespace, ResourceKind: in.Kind,
		ResourceName: in.Name, ResourceUID: target.UID, RequestedBy: adminID(r), Reason: in.Reason, TicketNo: in.TicketNo,
		ExecutionMode: strings.ToUpper(in.ExecutionMode), Status: status, RiskLevel: check.RiskLevel, PreviousRevision: rolloutRevision(target),
		PreviousSpecHash: hashJSON(target.Spec), AutoRollback: in.AutoRollback, TimeoutSeconds: in.TimeoutSeconds,
		DesiredReplicas: check.Desired, UpdatedReplicas: check.Updated, ReadyReplicas: check.Ready, AvailableReplicas: check.Available,
		UnavailableReplicas: maxInt(0, check.Desired-check.Available), Precheck: map[string]any{
			"checks": check.Checks, "warnings": check.Warnings,
			"observed_generation": intAny(target.StatusObject["observedGeneration"]),
			"target_observed_at":  firstNonEmpty(target.ObservedAt, target.UpdatedAt),
		}}
	if template, ok := target.Spec["template"].(map[string]any); ok {
		roll.PreviousTemplate = template
	}
	if directBySuperAdmin {
		roll.ApprovedBy, roll.ApprovedAt = adminID(r), now
	}
	event := store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: roll.ID,
		Status: status, Stage: "requested", Message: "롤아웃 요청 접수", Evidence: map[string]any{"precheck": check, "requested_by": adminID(r)}}
	if err := s.db.InsertK8sRolloutRequest(r.Context(), act, roll, event); err != nil {
		if replayAction, replayErr := s.db.GetK8sActionRequestByIdempotencyKey(r.Context(), idempotencyKey); replayErr == nil {
			if replayAction.CommandHash == commandHash {
				if replayRollout, replayRolloutErr := s.db.GetK8sRolloutByActionRequest(r.Context(), replayAction.ID); replayRolloutErr == nil {
					writeJSON(w, http.StatusAccepted, map[string]any{"rollout": replayRollout, "action": replayAction, "precheck": check, "idempotent_replay": true})
					return
				}
			}
			writeOpenAIError(w, http.StatusConflict, "idempotency key was already used for a different rollout request", "invalid_request_error", "idempotency_conflict")
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeOpenAIError(w, http.StatusConflict, "rollout already in progress", "invalid_request_error", "rollout_in_progress")
		} else {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "rollout_save_failed")
		}
		return
	}
	roll, _ = s.db.GetK8sRolloutAction(r.Context(), roll.ID)
	act, _ = s.db.GetK8sActionRequest(r.Context(), act.ID)
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
			if roll.Status != "approval_required" {
				writeOpenAIError(w, http.StatusConflict, "rollout is not awaiting approval", "invalid_request_error", "rollout_bad_state")
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
			// Both ledgers move together. Updating them separately, with the
			// rollout write's error discarded, let the action land as rejected
			// while the rollout kept its old status — and the blind write could
			// also clobber a reconciler update that landed in between.
			if err := s.db.RejectK8sRolloutWithAction(r.Context(), roll.ID, roll.ActionRequestID, adminID(r), "rollout rejected",
				roll.Status, roll.RollbackStatus, roll.UpdatedAt); err != nil {
				status := http.StatusConflict
				if errors.Is(err, store.ErrNotFound) {
					status = http.StatusNotFound
				}
				writeOpenAIError(w, status, err.Error(), "invalid_request_error", "rollout_reject_failed")
				return
			}
			roll.Status = "rejected"
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
	// Inventory backs the pod / node / PVC / PDB checks below. A failed read yields an
	// empty slice, which every one of them reads as "nothing wrong" — pod_health would
	// even report "no blocking Pod errors" without having looked at a single Pod. Block
	// instead, matching rolloutExecutionHazard, which already refuses to let an
	// unverified disruption through.
	all, invErr := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: in.ClusterID, Limit: 5000})
	if invErr != nil {
		add("inventory", "blocked", "클러스터 인벤토리를 조회할 수 없어 Pod·노드·PVC·PodDisruptionBudget 안전 점검을 수행하지 못했습니다: "+invErr.Error())
	} else {
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
		pdb := pdbSafety(target, all)
		switch {
		case pdb.Blocked:
			add("pdb", "blocked", pdb.Reason)
		case pdb.Found:
			add("pdb", "passed", "PodDisruptionBudget이 중단을 허용합니다.")
		default:
			add("pdb", "warning", "일치하는 PodDisruptionBudget을 확인할 수 없습니다.")
		}
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
	if identity, ok := mcpAdminIdentityFromRequest(r); ok {
		return strings.EqualFold(identity.Role, "super_admin")
	}
	if claims, ok := s.currentAccessClaims(r); ok {
		return strings.EqualFold(claims.Role, "super_admin")
	}
	return !s.cfg.Auth.Enabled && !s.keycloakConfig().Enabled
}

func (s *Server) requireRolloutScope(w http.ResponseWriter, r *http.Request, scope string) bool {
	if s.rolloutScopeAllowed(r, scope) {
		return true
	}
	writeOpenAIError(w, http.StatusForbidden, "missing required scope: "+scope, "invalid_request_error", "insufficient_scope")
	return false
}

func (s *Server) rolloutScopeAllowed(r *http.Request, scope string) bool {
	if identity, ok := mcpAdminIdentityFromRequest(r); ok {
		return strings.EqualFold(identity.Role, "super_admin") || hasScope(identity.Scopes, scope)
	}
	claims, ok := s.currentAccessClaims(r)
	if ok && (strings.EqualFold(claims.Role, "super_admin") || hasScope(claims.Scopes, scope)) {
		return true
	}
	return !s.cfg.Auth.Enabled && !s.keycloakConfig().Enabled
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

// reconcileRollout refreshes a rollout for an HTTP endpoint. It records observed
// progress but never initiates the rollback patch — see reconcileRolloutContext.
func (s *Server) reconcileRollout(r *http.Request, roll store.K8sRolloutAction) (store.K8sRolloutAction, error) {
	return s.reconcileRolloutContext(r.Context(), adminID(r), roll, false)
}

type rolloutObservation struct {
	Fresh                      bool
	ActionAnnotation           bool
	SpecChanged                bool
	RevisionChanged            bool
	GenerationAdvanced         bool
	MutationObserved           bool
	ControllerObserved         bool
	ExecutionObserved          bool
	Healthy                    bool
	RollbackMutationObserved   bool
	RollbackControllerObserved bool
	RollbackObserved           bool
}

const (
	rolloutRollbackRequestTimeout = 90 * time.Second
	rolloutRollbackClaimGrace     = 2 * time.Minute
	rolloutRollbackMinimumTimeout = 3 * time.Minute
)

func (o rolloutObservation) evidence(roll store.K8sRolloutAction, target store.K8sInventoryItem) map[string]any {
	return map[string]any{
		"desired": roll.DesiredReplicas, "updated": roll.UpdatedReplicas, "ready": roll.ReadyReplicas,
		"available": roll.AvailableReplicas, "fresh_snapshot": o.Fresh, "action_annotation": o.ActionAnnotation,
		"spec_changed": o.SpecChanged, "revision_changed": o.RevisionChanged,
		"generation_advanced": o.GenerationAdvanced, "mutation_observed": o.MutationObserved,
		"controller_observed": o.ControllerObserved, "execution_observed": o.ExecutionObserved,
		"rollback_mutation_observed":   o.RollbackMutationObserved,
		"rollback_controller_observed": o.RollbackControllerObserved, "rollback_observed": o.RollbackObserved, "target_uid": target.UID,
		"target_revision": rolloutRevision(target), "target_spec_hash": hashJSON(target.Spec),
		"observed_at": firstNonEmpty(target.ObservedAt, target.UpdatedAt),
	}
}

// reconcileRolloutContext advances one rollout from observed cluster state.
//
// initiateRollback controls whether this call may issue the automatic rollback
// patch. Only the durable worker passes true. Read endpoints must not: patching
// a Deployment is a cluster mutation, `rollout:rollback` is a real issuable
// scope, and the rollout detail page requires only `rollout:view` — so a viewer
// could both trigger the mutation and be recorded as the actor who performed
// it. Deferring costs nothing: the worker picks it up on its next tick.
func (s *Server) reconcileRolloutContext(ctx context.Context, actor string, roll store.K8sRolloutAction, initiateRollback bool) (store.K8sRolloutAction, error) {
	now := time.Now().UTC()
	if !rolloutReconcileDue(roll) {
		return roll, nil
	}
	before := roll
	previousStatus, previousRollbackStatus := roll.Status, roll.RollbackStatus
	if actor == "" {
		actor = "system:rollout-reconciler"
	}

	// "running" is the CAS claim held around the external patch. Do not recycle
	// it while the original caller may still be in flight. A crashed owner can be
	// recovered after a grace period longer than the default database lease.
	if roll.RollbackStatus == "running" {
		claimedAt, ok := parseRolloutTime(roll.UpdatedAt)
		if !ok {
			claimedAt, ok = parseRolloutTime(roll.RollbackStartedAt)
		}
		if !ok || now.Sub(claimedAt) < rolloutRollbackClaimGrace {
			return roll, nil
		}
		roll.RollbackStatus = "requested"
	}
	// v0.9.156 recorded completed_at when Kubernetes only acknowledged the patch.
	if roll.RollbackStatus == "requested" {
		roll.RollbackCompletedAt = ""
	}

	var target store.K8sInventoryItem
	targetFound := false
	target, err := s.db.GetK8sInventoryItem(ctx, roll.ClusterID, roll.ResourceKind, roll.Namespace, roll.ResourceName)
	if err == nil {
		targetFound = true
	} else if !errors.Is(err, store.ErrNotFound) {
		return roll, err
	}

	observation := rolloutObservation{}
	if targetFound {
		roll.DesiredReplicas = rolloutDesired(target)
		roll.UpdatedReplicas = rolloutUpdated(target)
		if target.Kind == "DaemonSet" {
			roll.ReadyReplicas = intAny(target.StatusObject["numberReady"])
		} else {
			roll.ReadyReplicas = intAny(target.StatusObject["readyReplicas"])
		}
		roll.AvailableReplicas = rolloutAvailable(target)
		roll.UnavailableReplicas = maxInt(0, roll.DesiredReplicas-roll.AvailableReplicas)
		observation = observeRollout(roll, target)
		if roll.RollbackStatus == "" && (observation.MutationObserved || observation.ControllerObserved) {
			roll.TargetRevision = rolloutRevision(target)
			roll.TargetSpecHash = hashJSON(target.Spec)
		}
		s.recordRolloutPods(ctx, roll, target)
	}

	start, started := parseRolloutTime(roll.StartedAt)
	if started {
		roll.DurationMS = now.Sub(start).Milliseconds()
		if roll.DurationMS < 0 {
			roll.DurationMS = 0
		}
	}
	if !rolloutTerminal(roll.Status) && started {
		timedOut := roll.TimeoutSeconds > 0 && roll.DurationMS > int64(roll.TimeoutSeconds)*1000
		// Failure evidence has priority over timeout, and timeout has priority over
		// health. A single snapshot can therefore never overwrite a failure with success.
		switch {
		case targetFound && observation.Fresh && roll.ResourceUID != "" && target.UID != roll.ResourceUID:
			roll.Status = "failed"
			roll.FailureReason = "rollout target UID changed"
			roll.CompletedAt = now.Format(time.RFC3339Nano)
		case targetFound && observation.ExecutionObserved && rolloutConditionFailed(target):
			roll.Status = "failed"
			roll.FailureReason = "ProgressDeadlineExceeded 또는 ReplicaFailure"
			roll.CompletedAt = now.Format(time.RFC3339Nano)
		case timedOut:
			roll.Status = "timed_out"
			roll.FailureReason = "rollout timeout"
			roll.CompletedAt = now.Format(time.RFC3339Nano)
		case targetFound && observation.ExecutionObserved && observation.Healthy:
			roll.Status = "succeeded"
			roll.FailureReason = ""
			roll.CompletedAt = now.Format(time.RFC3339Nano)
		}
	}

	rollbackJustRequested := false
	if (roll.Status == "failed" || roll.Status == "timed_out") && roll.AutoRollback && roll.RollbackStatus == "" {
		if targetFound {
			// Freeze the failed generation as the rollback baseline. Monitoring
			// must later observe both the restore patch and a newer controller revision.
			roll.TargetRevision = rolloutRevision(target)
			roll.TargetSpecHash = hashJSON(target.Spec)
		}
		roll.RollbackStartedAt = now.Format(time.RFC3339Nano)
		roll.RollbackCompletedAt = ""
		roll.RollbackFailureReason = ""
		switch {
		case targetFound && roll.ResourceUID != "" && target.UID != roll.ResourceUID:
			roll.RollbackStatus = "failed"
			roll.RollbackFailureReason = "rollout target UID changed; rollback was not applied to the replacement object"
			roll.RollbackCompletedAt = now.Format(time.RFC3339Nano)
		case !strings.EqualFold(roll.ResourceKind, "Deployment"):
			roll.RollbackStatus = "failed"
			roll.RollbackFailureReason = "StatefulSet·DaemonSet 자동 롤백은 안전 정책상 지원하지 않습니다."
			roll.RollbackCompletedAt = now.Format(time.RFC3339Nano)
		case len(roll.PreviousTemplate) == 0:
			roll.RollbackStatus = "failed"
			roll.RollbackFailureReason = "저장된 이전 Pod Template이 없습니다."
			roll.RollbackCompletedAt = now.Format(time.RFC3339Nano)
		default:
			roll.RollbackStatus = "requested"
			rollbackJustRequested = true
		}
	}

	if roll.RollbackStatus == "monitoring" {
		rollbackStart, ok := parseRolloutTime(roll.RollbackStartedAt)
		rollbackTimeout := time.Duration(roll.TimeoutSeconds) * time.Second
		if rollbackTimeout < rolloutRollbackMinimumTimeout {
			rollbackTimeout = rolloutRollbackMinimumTimeout
		}
		rollbackTimedOut := ok && now.Sub(rollbackStart) > rollbackTimeout
		switch {
		case targetFound && observation.RollbackObserved && rolloutConditionFailed(target):
			roll.RollbackStatus = "failed"
			roll.RollbackFailureReason = "rollback controller reported ProgressDeadlineExceeded 또는 ReplicaFailure"
			roll.RollbackCompletedAt = now.Format(time.RFC3339Nano)
		case targetFound && observation.RollbackObserved && observation.Healthy:
			roll.RollbackStatus = "succeeded"
			roll.RollbackFailureReason = ""
			roll.RollbackCompletedAt = now.Format(time.RFC3339Nano)
		case rollbackTimedOut:
			roll.RollbackStatus = "failed"
			roll.RollbackFailureReason = "rollback timeout"
			roll.RollbackCompletedAt = now.Format(time.RFC3339Nano)
		}
	}

	updated, err := s.persistRolloutCAS(ctx, before, roll)
	if err != nil {
		return roll, err
	}
	if !updated {
		return s.db.GetK8sRolloutAction(ctx, roll.ID)
	}
	current, err := s.db.GetK8sRolloutAction(ctx, roll.ID)
	if err != nil {
		return roll, err
	}
	evidence := observation.evidence(current, target)
	if current.Status != previousStatus {
		_ = s.db.AppendK8sRolloutEvent(ctx, store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: current.ID,
			Status: current.Status, Stage: rolloutEventStage(current.Status), Message: firstNonEmpty(current.FailureReason, "롤아웃 상태 전환"),
			Evidence: evidence})
		s.notifyRolloutTransition(ctx, current)
	}
	if current.RollbackStatus != previousRollbackStatus {
		_ = s.db.AppendK8sRolloutEvent(ctx, store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: current.ID,
			Status: current.Status, Stage: "rollback_" + current.RollbackStatus,
			Message:  firstNonEmpty(current.RollbackFailureReason, "자동 롤백 상태 전환"),
			Evidence: evidence})
	}
	if initiateRollback && (rollbackJustRequested || current.RollbackStatus == "requested") {
		return s.requestAutoRollback(ctx, actor, current)
	}
	return current, nil
}

func (s *Server) persistRolloutCAS(ctx context.Context, before, after store.K8sRolloutAction) (bool, error) {
	if before.UpdatedAt == "" {
		current, err := s.db.GetK8sRolloutAction(ctx, before.ID)
		if err != nil {
			return false, err
		}
		if current.Status != before.Status || current.RollbackStatus != before.RollbackStatus {
			return false, nil
		}
		before.UpdatedAt = current.UpdatedAt
	}
	return s.db.UpdateK8sRolloutProgressCAS(ctx, after, before.Status, before.RollbackStatus, before.UpdatedAt)
}

func (s *Server) requestAutoRollback(ctx context.Context, actor string, roll store.K8sRolloutAction) (store.K8sRolloutAction, error) {
	if roll.RollbackStatus != "requested" {
		return roll, nil
	}
	requested := roll
	roll.RollbackStatus = "running"
	roll.RollbackCompletedAt = ""
	claimed, err := s.persistRolloutCAS(ctx, requested, roll)
	if err != nil {
		return roll, err
	}
	if !claimed {
		return s.db.GetK8sRolloutAction(ctx, roll.ID)
	}
	roll, err = s.db.GetK8sRolloutAction(ctx, roll.ID)
	if err != nil {
		return roll, err
	}
	_ = s.db.AppendK8sRolloutEvent(ctx, store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: roll.ID,
		Status: roll.Status, Stage: "rollback_running", Message: "자동 롤백 실행 소유권 획득",
		Evidence: map[string]any{"rollback_status": roll.RollbackStatus}})

	claimedState := roll
	requestCtx, cancelRequest := context.WithTimeout(ctx, rolloutRollbackRequestTimeout)
	defer cancelRequest()
	cluster, err := s.db.GetK8sCluster(requestCtx, roll.ClusterID)
	if err == nil {
		var client kube.Client
		client, err = s.k8sClientForCluster(requestCtx, cluster)
		if err == nil {
			getter, canReadLive := client.(kube.ResourceGetter)
			if !canReadLive {
				err = errors.New("cluster client cannot verify the live rollout target UID")
			} else {
				var live map[string]any
				live, err = getter.GetResource(requestCtx, "apps/v1", "Deployment", roll.Namespace, roll.ResourceName)
				if err == nil {
					liveUID := textMap(asMapAny(live["metadata"]), "uid")
					if roll.ResourceUID != "" && liveUID != roll.ResourceUID {
						err = fmt.Errorf("rollout target UID changed from %s to %s; refusing rollback", roll.ResourceUID, firstNonEmpty(liveUID, "<missing>"))
					}
				}
			}
			if err == nil {
				exec, ok := client.(kube.RolloutRollbackExecutor)
				if !ok {
					err = errors.New("cluster client does not support rollout rollback")
				} else {
					err = exec.RollbackDeploymentTemplate(requestCtx, roll.Namespace, roll.ResourceName, roll.PreviousTemplate,
						kube.RolloutRestartMetadata{RestartedBy: actor, ActionID: roll.ID, Reason: "automatic rollback"})
				}
			}
		}
	}
	if err != nil && rollbackPatchOutcomeAmbiguous(err) {
		// The API server may have accepted the patch before the client deadline.
		// Keep the target lock and let inventory/controller evidence decide.
		roll.RollbackStatus = "monitoring"
		roll.RollbackFailureReason = "rollback request outcome is unknown: " + err.Error()
		roll.RollbackCompletedAt = ""
	} else if err != nil {
		roll.RollbackStatus = "failed"
		roll.RollbackFailureReason = err.Error()
		roll.RollbackCompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	} else {
		roll.RollbackStatus = "monitoring"
		roll.RollbackFailureReason = ""
		roll.RollbackCompletedAt = ""
	}
	finalizeCtx, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), k8sActionFinalizeTimeout)
	defer cancelFinalize()
	updated, updateErr := s.persistRolloutCAS(finalizeCtx, claimedState, roll)
	if updateErr != nil {
		return roll, updateErr
	}
	if !updated {
		return s.db.GetK8sRolloutAction(finalizeCtx, roll.ID)
	}
	current, getErr := s.db.GetK8sRolloutAction(finalizeCtx, roll.ID)
	if getErr != nil {
		return roll, getErr
	}
	_ = s.db.AppendK8sRolloutEvent(finalizeCtx, store.K8sRolloutEvent{ID: newID("rollevent"), ActionID: current.ID,
		Status: current.Status, Stage: "rollback_" + current.RollbackStatus,
		Message:  firstNonEmpty(current.RollbackFailureReason, "이전 Pod Template 복원 요청 완료"),
		Evidence: map[string]any{"rollback_status": current.RollbackStatus}})
	s.notifyMattermost(finalizeCtx, "k8s_rollout", fmt.Sprintf("Deployment 자동 롤백 %s: %s/%s %s · %s",
		current.RollbackStatus, current.ClusterID, current.Namespace, current.ResourceName,
		firstNonEmpty(current.RollbackFailureReason, "이전 Pod Template 복원 요청")))
	return current, nil
}

func rollbackPatchOutcomeAmbiguous(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// syncRolloutActionRequest closes an Action Center row that was deliberately
// left running because the Kubernetes mutation response was ambiguous. The
// rollout ledger is the durable source of truth and the worker keeps terminal
// rollout rows due until this synchronization succeeds.
func (s *Server) syncRolloutActionRequest(ctx context.Context, roll store.K8sRolloutAction) error {
	if roll.ActionRequestID == "" || !rolloutTerminal(roll.Status) {
		return nil
	}
	action, err := s.db.GetK8sActionRequest(ctx, roll.ActionRequestID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil || action.Status != "running" {
		return err
	}

	executionObserved := roll.Status == "succeeded" || roll.TargetSpecHash != ""
	if target, targetErr := s.db.GetK8sInventoryItem(ctx, roll.ClusterID, roll.ResourceKind, roll.Namespace, roll.ResourceName); targetErr == nil {
		executionObserved = executionObserved || observeRollout(roll, target).MutationObserved
	} else if !errors.Is(targetErr, store.ErrNotFound) {
		return targetErr
	}

	actionStatus := "failed"
	result := "rollout mutation could not be confirmed: " + firstNonEmpty(roll.FailureReason, roll.Status)
	if executionObserved {
		actionStatus = "executed"
		result = "rollout mutation confirmed by inventory/controller evidence (" + roll.Status + ")"
	}
	finalizeCtx, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), k8sActionFinalizeTimeout)
	defer cancelFinalize()
	if err := s.db.UpdateK8sActionStatus(finalizeCtx, action.ID, actionStatus, "system:rollout-reconciler", result); err != nil {
		if errors.Is(err, store.ErrInvalidTransition) {
			latest, getErr := s.db.GetK8sActionRequest(finalizeCtx, action.ID)
			if getErr == nil && latest.Status != "running" {
				return nil
			}
		}
		return err
	}
	if _, err := s.db.UpdateK8sServiceOperationsByRequestID(finalizeCtx, action.ID, actionStatus, result); err != nil {
		slog.Warn("service operation ledger status update failed", "error", err)
	}
	return nil
}

func (s *Server) recordRolloutPods(ctx context.Context, roll store.K8sRolloutAction, target store.K8sInventoryItem) {
	all, _ := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: roll.ClusterID, Kind: "Pod", Namespace: roll.Namespace, Limit: 2000})
	for _, pod := range all {
		if !podOwnedByWorkload(pod, target) {
			continue
		}
		life, _ := s.db.GetK8sPodLifecycleByName(ctx, roll.ClusterID, pod.Namespace, pod.Name, pod.UID)
		_ = s.db.UpsertK8sRolloutPodTransition(ctx, store.K8sRolloutPodTransition{ID: "rollpod_" + roll.ID + "_" + pod.UID, ActionID: roll.ID, PodUID: pod.UID, PodName: pod.Name,
			NodeName: textMap(pod.Spec, "nodeName"), Revision: firstNonEmpty(pod.Labels["pod-template-hash"], pod.Labels["controller-revision-hash"]),
			CreatedAt: life.CreatedAt, ScheduledAt: life.ScheduledAt, ContainerStartedAt: firstContainerStarted(pod.StatusObject), ReadyAt: life.ReadyAt,
			TerminatingAt: pod.DeletionTimestamp, Result: pod.Status, FailureReason: textMap(pod.StatusObject, "reason"), ObservedAt: pod.ObservedAt})
	}
}

func (s *Server) notifyRolloutTransition(ctx context.Context, roll store.K8sRolloutAction) {
	switch roll.Status {
	case "succeeded":
		s.notifyMattermost(ctx, "k8s_rollout", fmt.Sprintf("롤아웃 성공: %s/%s %s/%s · Ready %d/%d · %s",
			roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, roll.ReadyReplicas, roll.DesiredReplicas,
			(time.Duration(roll.DurationMS)*time.Millisecond).Round(time.Second)))
	case "failed", "timed_out":
		s.notifyMattermost(ctx, "k8s_rollout", fmt.Sprintf("롤아웃 %s: %s/%s %s/%s · %s",
			roll.Status, roll.ClusterID, roll.Namespace, roll.ResourceKind, roll.ResourceName, roll.FailureReason))
	}
}

func (s *Server) validateRolloutExecutionTarget(ctx context.Context, roll store.K8sRolloutAction) error {
	target, err := s.db.GetK8sInventoryItem(ctx, roll.ClusterID, roll.ResourceKind, roll.Namespace, roll.ResourceName)
	if err != nil {
		return fmt.Errorf("reload rollout target: %w", err)
	}
	if roll.ResourceUID != "" && target.UID != roll.ResourceUID {
		return fmt.Errorf("target UID drifted from %s to %s", roll.ResourceUID, target.UID)
	}
	currentHash := hashJSON(target.Spec)
	if roll.PreviousSpecHash != "" && currentHash != roll.PreviousSpecHash {
		return fmt.Errorf("target spec drifted from %s to %s", roll.PreviousSpecHash, currentHash)
	}
	if hazard := s.rolloutExecutionHazard(ctx, roll, target); hazard != "" {
		return errors.New(hazard)
	}
	return nil
}

// rolloutExecutionHazard re-checks, immediately before the mutation, the
// precheck blockers that describe a cluster which cannot absorb a disruption
// right now. The full precheck runs when the rollout is requested, but an
// approval can be granted hours later, and these three conditions can appear in
// the meantime without changing the target's spec — so the drift check above
// cannot see them.
//
// Deliberately narrower than the request-time precheck: an unhealthy workload
// or a replica shortfall is often the very reason an operator is restarting it,
// so those stay request-time advice rather than an execution-time block.
func (s *Server) rolloutExecutionHazard(ctx context.Context, roll store.K8sRolloutAction, target store.K8sInventoryItem) string {
	if target.DeletionTimestamp != "" {
		return "target is being deleted"
	}
	if rolloutTemplateRolloutInFlight(target) {
		return "another Kubernetes rollout is already in progress on the target"
	}
	all, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: roll.ClusterID, Limit: 5000})
	if err != nil {
		// Without inventory the PDB verdict is unknown. Report it rather than
		// letting an unverified disruption through.
		return "PodDisruptionBudget safety could not be verified: " + err.Error()
	}
	if pdb := pdbSafety(target, all); pdb.Blocked {
		return pdb.Reason
	}
	return ""
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
		if !rolloutNeedsReconcile(current) {
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

// rolloutTemplateRolloutInFlight reports an actual in-flight template rollout,
// which rolloutInProgress cannot: that predicate also fires when replicas are
// merely unavailable, so a workload that is simply broken looks identical to one
// mid-rollout. At request time the two are reported together and either way the
// operator is stopped, but the execution-time hazard check must not block a
// restart of a degraded workload — that is often the reason for the restart.
//
// Pods still running the previous template is the signal that distinguishes them.
func rolloutTemplateRolloutInFlight(it store.K8sInventoryItem) bool {
	return rolloutUpdated(it) < rolloutDesired(it)
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

func observeRollout(roll store.K8sRolloutAction, target store.K8sInventoryItem) rolloutObservation {
	fresh := inventoryObservedAtOrAfter(target, roll.StartedAt)
	actionID := rolloutTemplateAnnotation(target.Spec, "clustara.io/actionId")
	actionAnnotation := actionID != "" && (actionID == roll.ActionRequestID || actionID == roll.ID)
	specHash := hashJSON(target.Spec)
	specChanged := roll.PreviousSpecHash != "" && specHash != roll.PreviousSpecHash
	revision := rolloutRevision(target)
	revisionChanged := roll.PreviousRevision != "" && revision != "" && revision != roll.PreviousRevision
	previousGeneration := intAny(roll.Precheck["observed_generation"])
	currentGeneration := intAny(target.StatusObject["observedGeneration"])
	generationAdvanced := previousGeneration > 0 && currentGeneration > previousGeneration
	healthy := rolloutHealthy(roll)

	rollbackFresh := inventoryObservedAtOrAfter(target, roll.RollbackStartedAt)
	rollbackAction := actionID == roll.ID && rolloutTemplateAnnotation(target.Spec, "clustara.io/rollbackAt") != ""
	rollbackRestored := rolloutTemplatesEquivalent(roll.PreviousTemplate, rolloutTemplate(target.Spec))
	currentRevision := rolloutRevision(target)
	rollbackControllerObserved := rollbackFresh && roll.TargetRevision != "" && currentRevision != "" && currentRevision != roll.TargetRevision
	rollbackMutationObserved := rollbackFresh && (rollbackAction || rollbackRestored) &&
		(roll.TargetSpecHash == "" || hashJSON(target.Spec) != roll.TargetSpecHash)
	mutationObserved := fresh && (actionAnnotation || specChanged)
	controllerObserved := fresh && (revisionChanged || generationAdvanced)
	return rolloutObservation{
		Fresh: fresh, ActionAnnotation: actionAnnotation, SpecChanged: specChanged,
		RevisionChanged: revisionChanged, GenerationAdvanced: generationAdvanced,
		MutationObserved:           mutationObserved,
		ControllerObserved:         controllerObserved,
		ExecutionObserved:          mutationObserved && controllerObserved,
		Healthy:                    healthy,
		RollbackMutationObserved:   rollbackMutationObserved,
		RollbackControllerObserved: rollbackControllerObserved,
		RollbackObserved:           rollbackMutationObserved && rollbackControllerObserved,
	}
}

func rolloutHealthy(roll store.K8sRolloutAction) bool {
	return roll.DesiredReplicas > 0 &&
		roll.UpdatedReplicas >= roll.DesiredReplicas &&
		roll.ReadyReplicas >= roll.DesiredReplicas &&
		roll.AvailableReplicas >= roll.DesiredReplicas
}

func inventoryObservedAtOrAfter(target store.K8sInventoryItem, since string) bool {
	start, ok := parseRolloutTime(since)
	if !ok {
		return false
	}
	for _, raw := range []string{target.ObservedAt, target.UpdatedAt} {
		observed, parsed := parseRolloutTime(raw)
		if parsed {
			return !observed.Before(start)
		}
	}
	return false
}

func parseRolloutTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func rolloutTemplate(spec map[string]any) map[string]any {
	template, _ := spec["template"].(map[string]any)
	return template
}

func rolloutTemplateAnnotation(spec map[string]any, key string) string {
	template := rolloutTemplate(spec)
	metadata, _ := template["metadata"].(map[string]any)
	switch annotations := metadata["annotations"].(type) {
	case map[string]any:
		value, ok := annotations[key]
		if !ok || value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(value))
	case map[string]string:
		return strings.TrimSpace(annotations[key])
	default:
		return ""
	}
}

func rolloutTemplatesEquivalent(left, right map[string]any) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	return hashJSON(normalizeRolloutTemplate(left)) == hashJSON(normalizeRolloutTemplate(right))
}

func normalizeRolloutTemplate(template map[string]any) map[string]any {
	raw, _ := json.Marshal(template)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	metadata, _ := out["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	for _, key := range []string{
		"clustara.io/restartedAt", "kubectl.kubernetes.io/restartedAt", "clustara.io/restartedBy",
		"clustara.io/reason", "clustara.io/actionId", "clustara.io/rollbackAt", "clustara.io/rollbackBy",
	} {
		delete(annotations, key)
	}
	if len(annotations) == 0 && metadata != nil {
		delete(metadata, "annotations")
	}
	return out
}

func rolloutTerminal(status string) bool {
	switch status {
	case "succeeded", "failed", "timed_out", "rejected", "cancelled":
		return true
	default:
		return false
	}
}

func rolloutActive(status string) bool {
	switch status {
	case "requested", "pending", "approval_required", "approved", "running", "monitoring":
		return true
	}
	return false
}

func rolloutNeedsReconcile(roll store.K8sRolloutAction) bool {
	if rolloutActive(roll.Status) || roll.Status == "rollback_running" {
		return true
	}
	switch roll.RollbackStatus {
	case "requested", "monitoring", "running":
		return true
	}
	return (roll.Status == "failed" || roll.Status == "timed_out") && roll.AutoRollback && roll.RollbackStatus == ""
}

func rolloutReconcileDue(roll store.K8sRolloutAction) bool {
	switch roll.RollbackStatus {
	case "requested", "monitoring", "running":
		return true
	}
	if (roll.Status == "failed" || roll.Status == "timed_out") && roll.AutoRollback && roll.RollbackStatus == "" {
		return true
	}
	return roll.StartedAt != "" && !rolloutTerminal(roll.Status)
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

// pdbVerdict is the PodDisruptionBudget safety answer for one rollout target.
// Reason names the deciding budget so an operator can act on it.
type pdbVerdict struct {
	Found   bool
	Blocked bool
	Reason  string
}

// pdbSafety reports whether any PodDisruptionBudget covering the target forbids
// a disruption right now.
//
// Every matching budget is considered and the most restrictive wins. Returning
// on the first match let a permissive budget mask a restrictive one covering the
// same pods, which is the wrong direction for a safety check.
//
// A budget whose status has not been populated yet is treated as blocking, but
// is reported as unknown rather than as an explicit zero — an operator chasing
// "disruptionsAllowed=0" on a field that is simply absent would be misled.
func pdbSafety(target store.K8sInventoryItem, all []store.K8sInventoryItem) pdbVerdict {
	verdict := pdbVerdict{}
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
				break
			}
		}
		if !same {
			continue
		}
		verdict.Found = true
		allowed, reported := it.StatusObject["disruptionsAllowed"]
		switch {
		case !reported:
			verdict.Blocked = true
			verdict.Reason = "PodDisruptionBudget " + it.Name + " has not reported disruptionsAllowed yet"
			return verdict
		case intAny(allowed) == 0:
			verdict.Blocked = true
			verdict.Reason = "PodDisruptionBudget " + it.Name + " allows no disruptions (disruptionsAllowed=0)"
			return verdict
		}
	}
	return verdict
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
