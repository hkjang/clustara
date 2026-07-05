package proxy

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"clustara/internal/store"
)

func (s *Server) handleFinOpsBillingImports(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "finops_billing_import")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "finops_billing_import", "*", map[string]any{"imports": rows, "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "finops_billing_import", "imported", "finops.billing_import.upsert")
		if !ok {
			return
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "finops_billing_import", rec.ID, map[string]any{"import": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleFinOpsIdleResources(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 20000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_idle_inventory_failed")
		return
	}
	pvcRefs := map[string]bool{}
	for _, it := range items {
		if it.Kind == "Pod" {
			for _, ref := range finopsPVCRefs(it.Spec) {
				pvcRefs[it.ClusterID+"/"+it.Namespace+"/"+ref] = true
			}
		}
	}
	rows := []map[string]any{}
	for _, it := range items {
		specText := strings.ToLower(fleetJSON(it.Spec))
		switch it.Kind {
		case "Deployment", "StatefulSet", "ReplicaSet":
			replicas := finopsInt(it.Spec["replicas"])
			ready := finopsInt(secopsMap(it.StatusObject)["readyReplicas"])
			if replicas == 0 || (replicas > 0 && ready == 0 && strings.Contains(strings.ToLower(it.Status), "unavailable")) {
				rows = append(rows, map[string]any{"cluster_id": it.ClusterID, "namespace": it.Namespace, "kind": it.Kind, "name": it.Name, "reason": "zero_or_unready_replicas", "estimated_monthly_savings_krw": 0, "risk": "medium"})
			}
		case "PersistentVolumeClaim":
			if !pvcRefs[it.ClusterID+"/"+it.Namespace+"/"+it.Name] {
				rows = append(rows, map[string]any{"cluster_id": it.ClusterID, "namespace": it.Namespace, "kind": it.Kind, "name": it.Name, "reason": "pvc_not_referenced_by_running_pod", "estimated_monthly_savings_krw": 0, "risk": "low"})
			}
		case "Job", "CronJob":
			if strings.Contains(specText, "suspend\":true") || strings.Contains(strings.ToLower(it.Status), "complete") {
				rows = append(rows, map[string]any{"cluster_id": it.ClusterID, "namespace": it.Namespace, "kind": it.Kind, "name": it.Name, "reason": "inactive_batch_workload", "estimated_monthly_savings_krw": 0, "risk": "low"})
			}
		}
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "idle_resources", clusterID, map[string]any{"resources": rows, "count": len(rows)}))
}

func (s *Server) handleFinOpsGPUCosts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 20000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_gpu_inventory_failed")
		return
	}
	rows := []map[string]any{}
	totalGPU := 0.0
	for _, it := range items {
		if it.Kind != "Pod" && it.Kind != "Deployment" && it.Kind != "StatefulSet" && it.Kind != "Job" {
			continue
		}
		gpu := finopsGPURequest(it.Spec)
		if gpu <= 0 {
			continue
		}
		totalGPU += gpu
		rows = append(rows, map[string]any{
			"cluster_id": it.ClusterID, "namespace": it.Namespace, "kind": it.Kind, "name": it.Name,
			"gpu_request": gpu, "estimated_monthly_krw": roundMoney(gpu * 24 * 30 * 1200),
		})
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gpu_costs", clusterID, map[string]any{
		"workloads": rows, "total_gpu_request": totalGPU, "estimated_monthly_krw": roundMoney(totalGPU * 24 * 30 * 1200),
		"pricing_note": "기본 추정치입니다. 실제 cloud billing import가 있으면 chargeback에서 보정합니다.",
	}))
}

func (s *Server) handleFinOpsUnitEconomics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	report, _, _, _, err := s.finOpsSnapshot(r, strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_unit_failed")
		return
	}
	requests := finopsFloatParam(r.URL.Query().Get("requests"), 0)
	users := finopsFloatParam(r.URL.Query().Get("users"), 0)
	tenants := finopsFloatParam(r.URL.Query().Get("tenants"), 0)
	unit := map[string]any{"monthly_krw": report.TotalMonthlyKRW}
	if requests > 0 {
		unit["cost_per_request_krw"] = roundMoney(report.TotalMonthlyKRW / requests)
	}
	if users > 0 {
		unit["cost_per_user_krw"] = roundMoney(report.TotalMonthlyKRW / users)
	}
	if tenants > 0 {
		unit["cost_per_tenant_krw"] = roundMoney(report.TotalMonthlyKRW / tenants)
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "unit_economics", "*", map[string]any{"unit_economics": unit, "cost": report}))
}

func (s *Server) handleFinOpsChargeback(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	report, _, _, budgets, err := s.finOpsSnapshot(r, strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_chargeback_failed")
		return
	}
	lines := []map[string]any{}
	for _, t := range report.ByTeam {
		lines = append(lines, map[string]any{"scope": "team", "scope_value": t.Key, "monthly_krw": t.MonthlyKRW, "source": "k8s_request"})
	}
	for _, cc := range report.ByCostCenter {
		lines = append(lines, map[string]any{"scope": "cost_center", "scope_value": cc.Key, "monthly_krw": cc.MonthlyKRW, "source": "k8s_request"})
	}
	sort.Slice(lines, func(i, j int) bool {
		return finopsAnyFloat(lines[i]["monthly_krw"]) > finopsAnyFloat(lines[j]["monthly_krw"])
	})
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "chargeback", "*", map[string]any{
		"lines": lines, "budgets": budgets, "total_monthly_krw": report.TotalMonthlyKRW,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}))
}

func (s *Server) handleFinOpsSavingsWorkflows(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "finops_savings_workflow")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "finops_savings_workflow", "*", map[string]any{"workflows": rows, "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "finops_savings_workflow", "approval_required", "finops.savings_workflow.upsert")
		if !ok {
			return
		}
		if rec.Payload["approval_required"] == nil {
			rec.Payload["approval_required"] = true
		}
		_ = s.db.UpsertEnterpriseRecord(r.Context(), rec)
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "finops_savings_workflow", rec.ID, map[string]any{"workflow": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func finopsPVCRefs(spec map[string]any) []string {
	out := []string{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if claim, ok := x["persistentVolumeClaim"].(map[string]any); ok {
				if name := toString(claim["claimName"]); name != "" {
					out = append(out, name)
				}
			}
			for _, vv := range x {
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		}
	}
	walk(spec)
	return out
}

func finopsGPURequest(spec map[string]any) float64 {
	text := strings.ToLower(fleetJSON(spec))
	if !strings.Contains(text, "nvidia.com/gpu") && !strings.Contains(text, "amd.com/gpu") {
		return 0
	}
	total := 0.0
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				lk := strings.ToLower(k)
				if lk == "nvidia.com/gpu" || lk == "amd.com/gpu" {
					total += finopsAnyFloat(vv)
				}
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		}
	}
	walk(spec)
	return total
}

func finopsInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case float32:
		return int(x)
	}
	return 0
}

func finopsAnyFloat(v any) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case float64:
		return x
	case float32:
		return float64(x)
	case string:
		return finopsFloatParam(x, 0)
	default:
		return 0
	}
}

func finopsFloatParam(value string, fallback float64) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	out, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return out
}
