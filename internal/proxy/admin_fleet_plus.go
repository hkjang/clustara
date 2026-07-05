package proxy

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"clustara/internal/audit"
	"clustara/internal/store"
)

func (s *Server) handleFleetLifecycle(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusters, groups, _, err := s.fleetBaseData(r)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_lifecycle_failed")
		return
	}
	groupByID := map[string]string{}
	for _, g := range groups {
		groupByID[g.ID] = g.Name
	}
	rows := []map[string]any{}
	for _, c := range clusters {
		age := fleetFreshnessSeconds(c.LastConnectedAt)
		cred := "unknown"
		if c.AuthMode != "" {
			cred = "configured"
		}
		rbac := "unknown"
		if c.Status == "ready" || c.Status == "connected" {
			rbac = "ok"
		} else if strings.Contains(strings.ToLower(c.LastError), "forbidden") || strings.Contains(strings.ToLower(c.LastError), "rbac") {
			rbac = "insufficient"
		}
		fresh := "ok"
		if c.LastConnectedAt == "" || age > 3600 {
			fresh = "stale"
		}
		recs := []string{}
		if fresh == "stale" {
			recs = append(recs, "수집 freshness 확인")
		}
		if rbac == "insufficient" {
			recs = append(recs, "read-only RBAC preflight 재실행")
		}
		if cred == "unknown" {
			recs = append(recs, "credential rotation 상태 확인")
		}
		rows = append(rows, map[string]any{
			"cluster": c, "group_name": groupByID[c.GroupID], "credential_status": cred,
			"rbac_status": rbac, "collection_freshness": fresh, "freshness_seconds": age,
			"agent_version_status": "unknown", "upgrade_readiness": fleetUpgradeReadiness(c, fresh, rbac),
			"recommendations": recs,
		})
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "fleet", "*", map[string]any{"clusters": rows}))
}

func (s *Server) handleFleetCompare(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	leftID, rightID := strings.TrimSpace(r.URL.Query().Get("left_cluster_id")), strings.TrimSpace(r.URL.Query().Get("right_cluster_id"))
	if leftID == "" || rightID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "left_cluster_id and right_cluster_id are required", "invalid_request_error", "missing_cluster")
		return
	}
	left, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: leftID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_compare_left_failed")
		return
	}
	right, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: rightID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_compare_right_failed")
		return
	}
	lm, rm := fleetInventoryMap(left), fleetInventoryMap(right)
	rows := []map[string]any{}
	seen := map[string]bool{}
	for key, l := range lm {
		seen[key] = true
		if ritem, ok := rm[key]; !ok {
			rows = append(rows, map[string]any{"key": key, "state": "left_only", "left": l})
		} else if audit.HashText(fleetJSON(l.Spec)) != audit.HashText(fleetJSON(ritem.Spec)) || l.Status != ritem.Status {
			rows = append(rows, map[string]any{"key": key, "state": "spec_or_status_diff", "left_status": l.Status, "right_status": ritem.Status, "left_hash": audit.HashText(fleetJSON(l.Spec))[:16], "right_hash": audit.HashText(fleetJSON(ritem.Spec))[:16]})
		}
	}
	for key, ritem := range rm {
		if !seen[key] {
			rows = append(rows, map[string]any{"key": key, "state": "right_only", "right": ritem})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return toString(rows[i]["key"]) < toString(rows[j]["key"]) })
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "cluster_compare", leftID+".."+rightID, map[string]any{"left_cluster_id": leftID, "right_cluster_id": rightID, "diffs": rows, "count": len(rows)}))
}

func (s *Server) handleFleetBlastRadius(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := strings.ToLower(strings.TrimSpace(firstNonEmptyStr(r.URL.Query().Get("image"), r.URL.Query().Get("secret"), r.URL.Query().Get("config"), r.URL.Query().Get("ingress"), r.URL.Query().Get("cve"))))
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_blast_inventory_failed")
		return
	}
	owners, _ := s.db.ListK8sNamespaceOwnership(r.Context(), clusterID, "")
	ownerByNS := map[string]store.K8sNamespaceOwnership{}
	for _, o := range owners {
		ownerByNS[o.ClusterID+"/"+o.Namespace] = o
	}
	affected := []map[string]any{}
	for _, it := range items {
		hay := strings.ToLower(strings.Join([]string{it.Kind, it.Namespace, it.Name, fleetJSON(it.Labels), fleetJSON(it.Annotations), fleetJSON(it.Spec), fleetJSON(it.StatusObject)}, " "))
		if q == "" || strings.Contains(hay, q) {
			own := ownerByNS[it.ClusterID+"/"+it.Namespace]
			affected = append(affected, map[string]any{"cluster_id": it.ClusterID, "namespace": it.Namespace, "kind": it.Kind, "name": it.Name, "team": own.Team, "service": own.ServiceName, "risk_level": it.RiskLevel})
		}
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "blast_radius", q, map[string]any{"query": q, "affected": affected, "count": len(affected)}))
}

func (s *Server) handleFleetScore(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusters, groups, _, err := s.fleetBaseData(r)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_score_failed")
		return
	}
	groupCount := map[string]int{}
	for _, c := range clusters {
		groupCount[c.GroupID]++
	}
	rows := []map[string]any{}
	for _, c := range clusters {
		score := 100
		reasons := []string{}
		if c.Status != "ready" && c.Status != "connected" {
			score -= 30
			reasons = append(reasons, "not_ready")
		}
		if c.LastConnectedAt == "" || fleetFreshnessSeconds(c.LastConnectedAt) > 3600 {
			score -= 20
			reasons = append(reasons, "stale_collection")
		}
		rows = append(rows, map[string]any{"cluster_id": c.ID, "cluster_name": c.Name, "group_id": c.GroupID, "score": maxInt(score, 0), "reasons": reasons})
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "fleet", "*", map[string]any{"clusters": rows, "groups": groups, "group_counts": groupCount}))
}

func (s *Server) handleFleetActionDryRun(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		ClusterID string `json:"cluster_id"`
		GroupID   string `json:"group_id"`
		Action    string `json:"action"`
		Namespace string `json:"namespace"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		RiskLevel string `json:"risk_level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	blockers, warnings := []string{}, []string{}
	if in.Action == "" {
		blockers = append(blockers, "action is required")
	}
	if in.ClusterID == "" && in.GroupID == "" {
		blockers = append(blockers, "cluster_id or group_id is required")
	}
	if strings.Contains(strings.ToLower(in.RiskLevel), "critical") {
		blockers = append(blockers, "critical risk requires CAB/break-glass approval")
	}
	if in.Namespace == "prod" || strings.Contains(strings.ToLower(in.Namespace), "prod") {
		warnings = append(warnings, "prod namespace: owner approval and change window required")
	}
	writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "allowed": len(blockers) == 0, "blockers": blockers, "warnings": warnings, "rollback_hint": "capture live manifest revision before execution", "evidence_ref": "ev_" + audit.HashText(fleetJSON(in))[:16]})
}

func (s *Server) handleFleetProgressiveActions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "fleet_progressive_action")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"progressive_actions": rows})
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "fleet_progressive_action", "draft", "fleet.progressive_action.upsert")
		if !ok {
			return
		}
		if _, has := rec.Payload["stages"]; !has {
			rec.Payload["stages"] = []map[string]any{{"name": "canary", "percent": 1}, {"name": "ten_percent", "percent": 10}, {"name": "half", "percent": 50}, {"name": "full", "percent": 100}}
			_ = s.db.UpsertEnterpriseRecord(r.Context(), rec)
		}
		writeJSON(w, http.StatusCreated, map[string]any{"progressive_action": rec})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func fleetInventoryMap(items []store.K8sInventoryItem) map[string]store.K8sInventoryItem {
	out := map[string]store.K8sInventoryItem{}
	for _, it := range items {
		out[strings.Join([]string{it.Namespace, it.Kind, it.Name}, "/")] = it
	}
	return out
}

func fleetUpgradeReadiness(c store.K8sCluster, freshness, rbac string) string {
	if c.Status != "ready" && c.Status != "connected" {
		return "blocked"
	}
	if freshness == "stale" || rbac == "insufficient" {
		return "needs_attention"
	}
	return "ready"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
