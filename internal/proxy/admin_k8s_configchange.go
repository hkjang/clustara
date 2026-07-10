package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sConfigChanges lists or creates ConfigMap/Secret change-control requests.
// POST attaches Config Impact at creation time and gates Secret / impacted changes for approval.
// GET/POST /admin/k8s/config-changes
func (s *Server) handleK8sConfigChanges(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		rows, err := s.db.ListK8sConfigChangeRequests(r.Context(), store.K8sConfigChangeFilter{
			ClusterID: q.Get("cluster_id"), Status: q.Get("status"), SourceKind: q.Get("kind"),
			Namespace: q.Get("namespace"), Limit: intParam(q.Get("limit"), 100),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_changes_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": rows, "count": len(rows)})
	case http.MethodPost:
		s.createK8sConfigChange(w, r)
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) createK8sConfigChange(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ClusterID       string `json:"cluster_id"`
		Namespace       string `json:"namespace"`
		Kind            string `json:"kind"`
		SourceKind      string `json:"source_kind"`
		Name            string `json:"name"`
		SourceName      string `json:"source_name"`
		ChangeType      string `json:"change_type"`
		ProposedSummary string `json:"proposed_summary"`
		ProposedHash    string `json:"proposed_hash"`
		Reason          string `json:"reason"`
		IdempotencyKey  string `json:"idempotency_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	kind := normalizeConfigSourceKind(firstNonEmpty(p.SourceKind, p.Kind))
	name := strings.TrimSpace(firstNonEmpty(p.SourceName, p.Name))
	clusterID := strings.TrimSpace(p.ClusterID)
	namespace := strings.TrimSpace(p.Namespace)
	if clusterID == "" || kind == "" || name == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id, kind/source_kind and name/source_name are required", "invalid_request_error", "missing_fields")
		return
	}
	idempotencyKey := strings.TrimSpace(firstNonEmpty(p.IdempotencyKey, r.Header.Get("Idempotency-Key")))
	if idempotencyKey != "" {
		existing, err := s.db.GetK8sConfigChangeRequestByIdempotencyKey(r.Context(), idempotencyKey)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"request": existing, "idempotent_replay": true})
			return
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_change_idempotency_lookup_failed")
			return
		}
	}
	if _, err := s.db.GetK8sCluster(r.Context(), clusterID); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+clusterID, "invalid_request_error", "cluster_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	impact := analyzer.AnalyzeConfigImpactInNamespace(items, kind, namespace, name)
	requiresApproval := strings.EqualFold(kind, "Secret") || impact.Count > 0
	status := "pending"
	if requiresApproval {
		status = "approval_required"
	}
	target := findConfigSource(items, kind, namespace, name)
	reqID := newID("k8scfg")
	req := store.K8sConfigChangeRequest{
		ID: reqID, ClusterID: clusterID, Namespace: namespace, SourceKind: kind, SourceName: name,
		ChangeType: strings.TrimSpace(p.ChangeType), ProposedSummary: strings.TrimSpace(p.ProposedSummary),
		ProposedHash: strings.TrimSpace(p.ProposedHash), Reason: strings.TrimSpace(p.Reason),
		RiskLevel: configChangeRiskLevel(kind, impact), Status: status, RequiresApproval: requiresApproval,
		ImpactCount: impact.Count, RestartNeeded: impact.RestartNeeded, RequestedBy: adminID(r),
		IdempotencyKey: idempotencyKey, SourceUID: target.UID, SourceResourceVersion: k8sActionTargetResourceVersion(target),
		Result: configChangeGateReason(kind, impact),
	}
	if req.ProposedHash == "" {
		req.ProposedHash = configChangeHash(req)
	}
	impacts := make([]store.K8sConfigChangeImpact, 0, len(impact.Workloads))
	for _, wl := range impact.Workloads {
		impacts = append(impacts, store.K8sConfigChangeImpact{
			ID: newID("k8scfgimp"), RequestID: req.ID, ClusterID: clusterID,
			Namespace: wl.Namespace, Kind: wl.Kind, Name: wl.Name, Via: wl.Via,
		})
	}
	if err := s.db.CreateK8sConfigChangeRequest(r.Context(), req, impacts); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_change_save_failed")
		return
	}
	s.auditAdmin(r, "k8s.config_change.request", "", auditJSON(map[string]any{
		"id": req.ID, "kind": kind, "namespace": namespace, "name": name, "status": status, "impact_count": impact.Count,
	}))
	writeJSON(w, http.StatusCreated, map[string]any{
		"request": req, "impact": impact, "impacts": impacts,
		"note": "Secret 값 또는 원문 payload는 저장하지 않습니다. proposed_summary/proposed_hash와 영향도 스냅샷만 감사 증적으로 남깁니다.",
	})
}

// handleK8sConfigChangeByID returns one request and dispatches approve/apply/verify commands.
// GET /admin/k8s/config-changes/{id}
// POST /admin/k8s/config-changes/{id}/approve|reject|apply|verify
func (s *Server) handleK8sConfigChangeByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/config-changes/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "config change id required", "invalid_request_error", "missing_config_change_id")
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.writeK8sConfigChangeDetail(w, r, id)
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	switch parts[1] {
	case "approve", "reject", "apply":
		s.transitionK8sConfigChange(w, r, id, parts[1])
	case "verify":
		s.verifyK8sConfigChange(w, r, id)
	default:
		writeOpenAIError(w, http.StatusNotFound, "unknown config change command", "invalid_request_error", "unknown_config_change_command")
	}
}

func (s *Server) writeK8sConfigChangeDetail(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sConfigChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "config change request not found: "+id, "invalid_request_error", "config_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_change_failed")
		return
	}
	impacts, _ := s.db.ListK8sConfigChangeImpacts(r.Context(), id)
	verifications, _ := s.db.ListK8sConfigChangeVerifications(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"request": req, "impacts": impacts, "verifications": verifications})
}

func (s *Server) transitionK8sConfigChange(w http.ResponseWriter, r *http.Request, id, command string) {
	var p struct {
		Result string `json:"result"`
		Note   string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	status := command
	if command == "approve" {
		status = "approved"
	} else if command == "reject" {
		status = "rejected"
	} else if command == "apply" {
		status = "applied"
	}
	msg := strings.TrimSpace(firstNonEmpty(p.Result, p.Note))
	if command == "apply" && msg == "" {
		msg = "적용 완료로 기록됨. Secret/Config payload 원문은 Clustara에 저장하지 않습니다."
	}
	if err := s.db.UpdateK8sConfigChangeStatus(r.Context(), id, status, adminID(r), msg); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "config change request not found: "+id, "invalid_request_error", "config_change_not_found")
		return
	} else if errors.Is(err, store.ErrInvalidTransition) {
		writeOpenAIError(w, http.StatusConflict, "config change cannot transition from current state", "invalid_request_error", "config_change_bad_state")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_change_update_failed")
		return
	}
	s.auditAdmin(r, "k8s.config_change."+command, "", auditJSON(map[string]string{"id": id, "status": status}))
	req, _ := s.db.GetK8sConfigChangeRequest(r.Context(), id)
	if command == "apply" {
		// Change-aware burst: speed up verification of the applied config change.
		s.registerCollectBurst(r.Context(), req.ClusterID, req.Namespace, "config_change", "config_change:"+req.SourceKind+"/"+req.SourceName)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": status, "request": req})
}

func (s *Server) verifyK8sConfigChange(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sConfigChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "config change request not found: "+id, "invalid_request_error", "config_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_change_failed")
		return
	}
	if req.Status != "applied" && req.Status != "verification_failed" {
		writeOpenAIError(w, http.StatusConflict, "config change must be applied before verification (current: "+req.Status+")", "invalid_request_error", "config_change_not_applied")
		return
	}
	impacts, _ := s.db.ListK8sConfigChangeImpacts(r.Context(), id)
	verification := s.buildK8sConfigChangeVerification(r, req, impacts)
	if err := s.db.InsertK8sConfigChangeVerification(r.Context(), verification); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_change_verify_save_failed")
		return
	}
	nextStatus := "verified"
	if verification.Status != "passed" {
		nextStatus = "verification_failed"
	}
	if err := s.db.UpdateK8sConfigChangeStatus(r.Context(), id, nextStatus, adminID(r), "verification: "+verification.Status); errors.Is(err, store.ErrInvalidTransition) {
		writeOpenAIError(w, http.StatusConflict, "config change cannot transition from current state", "invalid_request_error", "config_change_bad_state")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_config_change_verify_update_failed")
		return
	}
	s.auditAdmin(r, "k8s.config_change.verify", "", auditJSON(map[string]any{"id": id, "status": verification.Status}))
	updated, _ := s.db.GetK8sConfigChangeRequest(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": nextStatus, "request": updated, "verification": verification})
}

func (s *Server) buildK8sConfigChangeVerification(r *http.Request, req store.K8sConfigChangeRequest, impacts []store.K8sConfigChangeImpact) store.K8sConfigChangeVerification {
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: req.ClusterID, Limit: 5000})
	events, _ := s.db.ListK8sEvents(r.Context(), req.ClusterID, 500)
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: req.ClusterID, Status: "open", Limit: 200})
	appliedAt := parseConfigChangeTime(firstNonEmpty(req.AppliedAt, req.UpdatedAt, req.CreatedAt))

	itemByKey := map[string]store.K8sInventoryItem{}
	for _, it := range items {
		itemByKey[configChangeResourceKey(it.Namespace, it.Kind, it.Name)] = it
	}
	staleImpacts, refreshedImpacts, unhealthyImpacts := 0, 0, 0
	for _, im := range impacts {
		it, ok := itemByKey[configChangeResourceKey(im.Namespace, im.Kind, im.Name)]
		if !ok {
			staleImpacts++
			continue
		}
		if !appliedAt.IsZero() && !parseConfigChangeTime(firstNonEmpty(it.ObservedAt, it.UpdatedAt)).Before(appliedAt) {
			refreshedImpacts++
		} else if !appliedAt.IsZero() {
			staleImpacts++
		}
		if configChangeUnhealthy(it) {
			unhealthyImpacts++
		}
	}
	sourceRefreshed := false
	if src := findConfigSource(items, req.SourceKind, req.Namespace, req.SourceName); src.Name != "" && !appliedAt.IsZero() {
		sourceRefreshed = !parseConfigChangeTime(firstNonEmpty(src.ObservedAt, src.UpdatedAt)).Before(appliedAt)
	}
	warningEvents := 0
	for _, ev := range events {
		if !appliedAt.IsZero() && parseConfigChangeTime(firstNonEmpty(ev.LastSeen, ev.CreatedAt)).Before(appliedAt) {
			continue
		}
		if configChangeEventMatchesImpacts(ev, impacts) {
			warningEvents++
		}
	}
	openIncidentCount := 0
	for _, inc := range incidents {
		if configChangeIncidentMatchesImpacts(inc, impacts) {
			openIncidentCount++
		}
	}
	status := "passed"
	if unhealthyImpacts > 0 || warningEvents > 0 || openIncidentCount > 0 {
		status = "attention_required"
	} else if req.RestartNeeded > 0 && staleImpacts > 0 {
		status = "pending_observation"
	}
	return store.K8sConfigChangeVerification{
		ID: newID("k8scfgver"), RequestID: req.ID, Status: status, CreatedBy: adminID(r),
		Summary: map[string]any{
			"impact_count":          len(impacts),
			"restart_needed":        req.RestartNeeded,
			"refreshed_workloads":   refreshedImpacts,
			"stale_workloads":       staleImpacts,
			"unhealthy_workloads":   unhealthyImpacts,
			"warning_events":        warningEvents,
			"open_incidents":        openIncidentCount,
			"source_refreshed":      sourceRefreshed,
			"checked_after_applied": !appliedAt.IsZero(),
		},
	}
}

func normalizeConfigSourceKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "configmap", "config_map":
		return "ConfigMap"
	case "secret":
		return "Secret"
	default:
		return ""
	}
}

func configChangeRiskLevel(kind string, impact analyzer.ConfigImpactReport) string {
	if strings.EqualFold(kind, "Secret") && impact.Count > 0 {
		return "high"
	}
	if strings.EqualFold(kind, "Secret") || impact.RestartNeeded > 0 {
		return "medium"
	}
	if impact.Count > 0 {
		return "medium"
	}
	return "low"
}

func configChangeGateReason(kind string, impact analyzer.ConfigImpactReport) string {
	reasons := []string{}
	if strings.EqualFold(kind, "Secret") {
		reasons = append(reasons, "Secret 변경")
	}
	if impact.Count > 0 {
		reasons = append(reasons, "참조 워크로드 "+strconv.Itoa(impact.Count)+"개")
	}
	if impact.RestartNeeded > 0 {
		reasons = append(reasons, "재시작 필요 "+strconv.Itoa(impact.RestartNeeded)+"개")
	}
	if len(reasons) == 0 {
		return "영향 워크로드 없음: 승인 없이 적용 가능"
	}
	return "승인 필요: " + strings.Join(reasons, " · ")
}

func configChangeHash(req store.K8sConfigChangeRequest) string {
	payload := strings.Join([]string{
		req.ClusterID, req.Namespace, req.SourceKind, req.SourceName, req.ChangeType,
		req.ProposedSummary, req.Reason,
	}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func findConfigSource(items []store.K8sInventoryItem, kind, namespace, name string) store.K8sInventoryItem {
	for _, it := range items {
		if !strings.EqualFold(it.Kind, kind) || it.Name != name {
			continue
		}
		if namespace == "" || it.Namespace == namespace {
			return it
		}
	}
	return store.K8sInventoryItem{}
}

func configChangeResourceKey(namespace, kind, name string) string {
	return namespace + "\x00" + strings.ToLower(kind) + "\x00" + name
}

func configChangeUnhealthy(it store.K8sInventoryItem) bool {
	unhealthy, _, _ := configChangeHealth(it)
	return unhealthy
}

// configChangeHealth applies kind-specific semantics and returns evidence suitable for operators.
// A completed Job is healthy even when generic workload scoring still reflects its terminated Pods.
func configChangeHealth(it store.K8sInventoryItem) (bool, string, []string) {
	if strings.EqualFold(it.Kind, "Job") {
		return configChangeJobHealth(it)
	}
	if it.HealthScore > 0 && it.HealthScore < 80 {
		return true, "unhealthy", []string{"health_score_below_80"}
	}
	switch strings.ToLower(it.RiskLevel) {
	case "medium", "high", "critical":
		return true, "unhealthy", []string{"risk_level_" + strings.ToLower(it.RiskLevel)}
	}
	status := strings.ToLower(it.Status)
	for _, marker := range []string{"crash", "error", "fail", "unavail", "pending", "backoff", "oom", "imagepull"} {
		if strings.Contains(status, marker) {
			return true, "unhealthy", []string{"status_" + marker}
		}
	}
	return false, "healthy", nil
}

func configChangeJobHealth(it store.K8sInventoryItem) (bool, string, []string) {
	status := it.StatusObject
	for _, raw := range anySlice(status["conditions"]) {
		condition, _ := raw.(map[string]any)
		if !strings.EqualFold(fmt.Sprint(condition["status"]), "True") {
			continue
		}
		typ := fmt.Sprint(condition["type"])
		reason := fmt.Sprint(condition["reason"])
		if strings.EqualFold(typ, "Failed") {
			code := "job_failed"
			if reason != "" {
				code = "job_" + strings.ToLower(reason)
			}
			return true, "failed", []string{code}
		}
		if strings.EqualFold(typ, "Complete") {
			return false, "succeeded", []string{"job_complete"}
		}
	}
	succeeded := anyInt(status["succeeded"])
	active := anyInt(status["active"])
	completions := anyInt(it.Spec["completions"])
	// status.failed is a failed Pod attempt count, not a terminal Job verdict. A Job may retry and
	// later complete successfully, so only the Failed condition (above) or an explicit status wins.
	if strings.Contains(strings.ToLower(it.Status), "fail") {
		return true, "failed", []string{"job_failed"}
	}
	if succeeded > 0 && (completions == 0 || succeeded >= completions) {
		return false, "succeeded", []string{"job_succeeded"}
	}
	if active > 0 || strings.EqualFold(it.Status, "Running") {
		return false, "active", []string{"job_active"}
	}
	if truthy(status["suspended"]) {
		return false, "suspended", []string{"job_suspended"}
	}
	return false, "pending", []string{"job_pending"}
}

func anySlice(v any) []any {
	if out, ok := v.([]any); ok {
		return out
	}
	return nil
}

func anyInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

func truthy(v any) bool {
	b, _ := v.(bool)
	return b || strings.EqualFold(fmt.Sprint(v), "true")
}

func configChangeEventMatchesImpacts(ev store.K8sEvent, impacts []store.K8sConfigChangeImpact) bool {
	if !strings.EqualFold(ev.Type, "Warning") {
		return false
	}
	for _, im := range impacts {
		if ev.Namespace != im.Namespace {
			continue
		}
		if strings.EqualFold(ev.InvolvedKind, im.Kind) && ev.InvolvedName == im.Name {
			return true
		}
		if strings.EqualFold(ev.InvolvedKind, "Pod") && strings.HasPrefix(ev.InvolvedName, im.Name+"-") {
			return true
		}
	}
	return false
}

func configChangeIncidentMatchesImpacts(inc store.K8sIncident, impacts []store.K8sConfigChangeImpact) bool {
	for _, im := range impacts {
		if inc.ClusterID != im.ClusterID || inc.Namespace != im.Namespace {
			continue
		}
		if strings.EqualFold(inc.Kind, im.Kind) && inc.Name == im.Name {
			return true
		}
	}
	return false
}

func parseConfigChangeTime(raw string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	return t
}
