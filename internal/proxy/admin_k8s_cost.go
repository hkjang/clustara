package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// costContext loads the inventory plus the lookup maps (team/cost-center/group) and unit
// prices needed to estimate cost. Shared by the cost dashboard and the ops home.
func (s *Server) costContext(ctx context.Context, clusterID string) ([]store.K8sInventoryItem, analyzer.CostPrices, map[string]string, map[string]string, map[string]string, error) {
	items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		return nil, analyzer.CostPrices{}, nil, nil, nil, err
	}
	owners, _ := s.db.ListK8sNamespaceOwnership(ctx, clusterID, "")
	nsTeam, nsCC := map[string]string{}, map[string]string{}
	for _, o := range owners {
		nsTeam[o.ClusterID+"|"+o.Namespace] = o.Team
		nsCC[o.ClusterID+"|"+o.Namespace] = o.CostCenter
	}
	groups, _ := s.db.ListK8sClusterGroups(ctx)
	groupName := map[string]string{}
	for _, g := range groups {
		groupName[g.ID] = g.Name
	}
	clusters, _ := s.db.ListK8sClusters(ctx)
	clusterGroup := map[string]string{}
	for _, c := range clusters {
		clusterGroup[c.ID] = groupName[c.GroupID]
	}
	prices := analyzer.DefaultCostPrices
	if v := s.flagValue(ctx, "k8s_cost_cpu_krw"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			prices.CPUCoreMonthlyKRW = f
		}
	}
	if v := s.flagValue(ctx, "k8s_cost_mem_krw"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			prices.MemGBMonthlyKRW = f
		}
	}
	return items, prices, nsTeam, nsCC, clusterGroup, nil
}

// handleK8sCost returns the estimated monthly cost broken down by namespace/team/group/cost
// center. GET /admin/k8s/cost?cluster_id=
func (s *Server) handleK8sCost(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	items, prices, nsTeam, nsCC, clusterGroup, err := s.costContext(r.Context(), r.URL.Query().Get("cluster_id"))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	report := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)
	writeJSON(w, http.StatusOK, map[string]any{
		"report": report,
		"note":   "워크로드 resource request × 단가로 추정한 월 비용입니다. 단가는 설정에서 조정하세요.",
	})
}

// handleK8sCostSnapshot records today's per-namespace cost as a daily snapshot so cost trend /
// increase can be computed locally (no ClickHouse required). POST /admin/k8s/cost/snapshot?cluster_id=
func (s *Server) handleK8sCostSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, prices, nsTeam, nsCC, clusterGroup, err := s.costContext(r.Context(), clusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	report := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)
	n := 0
	for _, l := range report.ByNamespace {
		if err := s.db.RecordK8sCostSnapshot(r.Context(), store.K8sCostSnapshot{
			ClusterID: clusterID, Dimension: "namespace", Key: l.Key, MonthlyKRW: l.MonthlyKRW,
		}); err == nil {
			n++
		}
	}
	s.auditAdmin(r, "k8s.cost.snapshot", "", auditJSON(map[string]any{"cluster_id": clusterID, "recorded": n}))
	writeJSON(w, http.StatusOK, map[string]any{"recorded": n})
}

// handleK8sCostTrend returns day-over-day cost change per namespace (DW-08 비용 증가).
// GET /admin/k8s/cost/trend?cluster_id=
func (s *Server) handleK8sCostTrend(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	snaps, err := s.db.ListK8sCostSnapshots(r.Context(), r.URL.Query().Get("cluster_id"), "namespace", 2000)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cost_trend_failed")
		return
	}
	trend := analyzer.ComputeCostTrend(snaps)
	writeJSON(w, http.StatusOK, map[string]any{
		"trend": trend,
		"note":  "일별 비용 스냅샷(POST /admin/k8s/cost/snapshot)을 누적해 산출합니다. 2일 이상 누적되면 증가율이 표시됩니다.",
	})
}

// handleK8sCostConfig reads/sets the cost unit prices. GET/POST /admin/k8s/cost/config
func (s *Server) handleK8sCostConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		_, prices, _, _, _, err := s.costContext(r.Context(), "")
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cost_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"prices": prices})
	case http.MethodPost:
		var p struct {
			CPUCoreMonthlyKRW *float64 `json:"cpu_core_monthly_krw"`
			MemGBMonthlyKRW   *float64 `json:"mem_gb_monthly_krw"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		set := func(key string, val float64) error {
			return s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: key, Value: strconv.FormatFloat(val, 'f', -1, 64), UpdatedAt: time.Now().UTC(), UpdatedBy: adminID(r)})
		}
		if p.CPUCoreMonthlyKRW != nil {
			if err := set("k8s_cost_cpu_krw", *p.CPUCoreMonthlyKRW); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		if p.MemGBMonthlyKRW != nil {
			if err := set("k8s_cost_mem_krw", *p.MemGBMonthlyKRW); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}
