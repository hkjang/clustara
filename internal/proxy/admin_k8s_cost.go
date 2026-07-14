package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

const (
	k8sCostSnapshotEnabledFlag  = "k8s_cost_snapshot_enabled"
	k8sCostSnapshotIntervalFlag = "k8s_cost_snapshot_interval_seconds"
	k8sCostSnapshotLastRunFlag  = "k8s_cost_snapshot_last_run"
	k8sCostSnapshotLastOKFlag   = "k8s_cost_snapshot_last_success"
	k8sCostSnapshotLastErrFlag  = "k8s_cost_snapshot_last_error"
	k8sCostSnapshotDefaultSecs  = 86400
)

func (s *Server) k8sCostSnapshotScheduler() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	// Run once shortly after startup; the persisted last-success timestamp prevents duplicate work.
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if err := s.runAutomaticK8sCostSnapshots(ctx, false); err != nil && ctx.Err() == nil {
			slog.Warn("automatic k8s cost snapshot failed", "error", err)
		}
		cancel()
	}
}

func (s *Server) runAutomaticK8sCostSnapshots(ctx context.Context, force bool) error {
	if !force && !s.monitoringBool(ctx, k8sCostSnapshotEnabledFlag, true) {
		return nil
	}
	interval := s.monitoringInt(ctx, k8sCostSnapshotIntervalFlag, k8sCostSnapshotDefaultSecs)
	if interval < 3600 {
		interval = 3600
	}
	if !force && !k8sCostSnapshotDue(s.flagValue(ctx, k8sCostSnapshotLastOKFlag), time.Now().UTC(), time.Duration(interval)*time.Second) {
		return nil
	}
	now := time.Now().UTC()
	_ = s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sCostSnapshotLastRunFlag, Value: now.Format(time.RFC3339Nano), UpdatedBy: "k8s-cost-scheduler"})
	clusters, err := s.db.ListK8sClusters(ctx)
	if err != nil {
		return err
	}
	total := 0
	for _, cluster := range clusters {
		n, snapshotErr := s.recordK8sCostSnapshot(ctx, cluster.ID)
		if snapshotErr != nil {
			message := cluster.ID + ": " + snapshotErr.Error()
			_ = s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sCostSnapshotLastErrFlag, Value: message, UpdatedBy: "k8s-cost-scheduler"})
			return fmt.Errorf("snapshot cluster %s: %w", cluster.ID, snapshotErr)
		}
		total += n
	}
	completed := time.Now().UTC().Format(time.RFC3339Nano)
	_ = s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sCostSnapshotLastOKFlag, Value: completed, UpdatedBy: "k8s-cost-scheduler"})
	_ = s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sCostSnapshotLastErrFlag, Value: "", UpdatedBy: "k8s-cost-scheduler", Note: fmt.Sprintf("recorded=%d", total)})
	return nil
}

func k8sCostSnapshotDue(lastSuccess string, now time.Time, interval time.Duration) bool {
	last, err := time.Parse(time.RFC3339Nano, lastSuccess)
	return err != nil || !now.Before(last.Add(interval))
}

func (s *Server) recordK8sCostSnapshot(ctx context.Context, clusterID string) (int, error) {
	items, prices, nsTeam, nsCC, clusterGroup, err := s.costContext(ctx, clusterID)
	if err != nil {
		return 0, err
	}
	report := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)
	recorded := 0
	for _, line := range report.ByNamespace {
		if err := s.db.RecordK8sCostSnapshot(ctx, store.K8sCostSnapshot{ClusterID: clusterID, Dimension: "namespace", Key: line.Key, MonthlyKRW: line.MonthlyKRW}); err != nil {
			return recorded, err
		}
		recorded++
	}
	return recorded, nil
}

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
	if v := s.flagValue(ctx, "k8s_cost_storage_krw"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			prices.StorageGBMonthlyKRW = f
		}
	}
	if v := s.flagValue(ctx, "k8s_cost_gpu_krw"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			prices.GPUUnitMonthlyKRW = f
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
	metrics, _ := s.db.ListK8sMetricSamples(r.Context(), r.URL.Query().Get("cluster_id"), 10000)
	forecast := analyzer.BuildCostForecast(items, metrics, prices)
	writeJSON(w, http.StatusOK, map[string]any{
		"report":   report,
		"forecast": forecast,
		"note":     "기준 비용은 resource request × 단가, 실사용 조정치는 최신 CPU·Memory usage에 안정성 headroom 30%를 적용합니다. 스토리지·네트워크·라이선스·클라우드 할인은 포함하지 않은 운영 추정치입니다.",
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
	n := 0
	if clusterID != "" {
		var err error
		n, err = s.recordK8sCostSnapshot(r.Context(), clusterID)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cost_snapshot_failed")
			return
		}
	} else {
		clusters, err := s.db.ListK8sClusters(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_clusters_failed")
			return
		}
		for _, cluster := range clusters {
			count, err := s.recordK8sCostSnapshot(r.Context(), cluster.ID)
			if err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cost_snapshot_failed")
				return
			}
			n += count
		}
	}
	s.auditAdmin(r, "k8s.cost.snapshot", "", auditJSON(map[string]any{"cluster_id": clusterID, "recorded": n}))
	writeJSON(w, http.StatusOK, map[string]any{"recorded": n})
}

// handleK8sCostRecommendations returns right-sizing recommendations (request vs usage) with the
// monthly saving per workload (FinOps Rightsizing). GET /admin/k8s/cost/recommendations?cluster_id=
func (s *Server) handleK8sCostRecommendations(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, prices, _, _, _, err := s.costContext(r.Context(), clusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	metrics, _ := s.db.ListK8sMetricSamples(r.Context(), clusterID, 4000)
	recs := analyzer.RecommendRightsizing(items, metrics, prices)
	total := 0.0
	for _, rec := range recs {
		total += rec.MonthlySavingsKRW
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recommendations":           recs,
		"count":                     len(recs),
		"total_monthly_savings_krw": total,
		"note":                      "request 대비 실사용(usage×1.3) 기준 권장값입니다. down=절감 후보, up=과소할당(증설 권고).",
	})
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
	daily, monthly := buildK8sCostHistory(snaps)
	writeJSON(w, http.StatusOK, map[string]any{
		"trend":          trend,
		"daily_series":   daily,
		"monthly_series": monthly,
		"history_days":   len(daily),
		"note":           "일별 비용 스냅샷을 합산한 월 환산 추정치입니다. 월별 값은 해당 월의 마지막 스냅샷이며 실제 청구액이 아닙니다.",
	})
}

type k8sCostHistoryPoint struct {
	Period     string  `json:"period"`
	MonthlyKRW float64 `json:"monthly_krw"`
	DailyKRW   float64 `json:"daily_krw"`
	HourlyKRW  float64 `json:"hourly_krw"`
}

func buildK8sCostHistory(snaps []store.K8sCostSnapshot) ([]k8sCostHistoryPoint, []k8sCostHistoryPoint) {
	dayTotals := map[string]float64{}
	for _, snap := range snaps {
		if len(snap.Day) >= 10 {
			dayTotals[snap.Day[:10]] += snap.MonthlyKRW
		}
	}
	days := make([]string, 0, len(dayTotals))
	for day := range dayTotals {
		days = append(days, day)
	}
	sort.Strings(days)
	daily := make([]k8sCostHistoryPoint, 0, len(days))
	monthLatest := map[string]k8sCostHistoryPoint{}
	for _, day := range days {
		monthly := dayTotals[day]
		point := k8sCostHistoryPoint{Period: day, MonthlyKRW: monthly, DailyKRW: monthly / 30.4375, HourlyKRW: monthly / 730}
		daily = append(daily, point)
		monthLatest[day[:7]] = point
	}
	months := make([]string, 0, len(monthLatest))
	for month := range monthLatest {
		months = append(months, month)
	}
	sort.Strings(months)
	monthly := make([]k8sCostHistoryPoint, 0, len(months))
	for _, month := range months {
		point := monthLatest[month]
		point.Period = month
		monthly = append(monthly, point)
	}
	return daily, monthly
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
		interval := s.monitoringInt(r.Context(), k8sCostSnapshotIntervalFlag, k8sCostSnapshotDefaultSecs)
		lastSuccess := s.flagValue(r.Context(), k8sCostSnapshotLastOKFlag)
		nextRun := ""
		if last, parseErr := time.Parse(time.RFC3339Nano, lastSuccess); parseErr == nil {
			nextRun = last.Add(time.Duration(interval) * time.Second).Format(time.RFC3339Nano)
		}
		writeJSON(w, http.StatusOK, map[string]any{"prices": prices, "automation": map[string]any{"enabled": s.monitoringBool(r.Context(), k8sCostSnapshotEnabledFlag, true), "interval_seconds": interval, "last_run": s.flagValue(r.Context(), k8sCostSnapshotLastRunFlag), "last_success": lastSuccess, "last_error": s.flagValue(r.Context(), k8sCostSnapshotLastErrFlag), "next_run": nextRun, "idempotent": true}})
	case http.MethodPost:
		var p struct {
			CPUCoreMonthlyKRW   *float64 `json:"cpu_core_monthly_krw"`
			MemGBMonthlyKRW     *float64 `json:"mem_gb_monthly_krw"`
			StorageGBMonthlyKRW *float64 `json:"storage_gb_monthly_krw"`
			GPUUnitMonthlyKRW   *float64 `json:"gpu_unit_monthly_krw"`
			SnapshotEnabled     *bool    `json:"snapshot_enabled"`
			SnapshotInterval    *int     `json:"snapshot_interval_seconds"`
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
		if p.StorageGBMonthlyKRW != nil {
			if err := set("k8s_cost_storage_krw", *p.StorageGBMonthlyKRW); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		if p.GPUUnitMonthlyKRW != nil {
			if err := set("k8s_cost_gpu_krw", *p.GPUUnitMonthlyKRW); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		if p.SnapshotEnabled != nil {
			if err := s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: k8sCostSnapshotEnabledFlag, Value: strconv.FormatBool(*p.SnapshotEnabled), UpdatedAt: time.Now().UTC(), UpdatedBy: adminID(r)}); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		if p.SnapshotInterval != nil {
			if *p.SnapshotInterval < 3600 || *p.SnapshotInterval > 2592000 {
				writeOpenAIError(w, http.StatusBadRequest, "snapshot_interval_seconds must be between 3600 and 2592000", "invalid_request_error", "invalid_interval")
				return
			}
			if err := s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: k8sCostSnapshotIntervalFlag, Value: strconv.Itoa(*p.SnapshotInterval), UpdatedAt: time.Now().UTC(), UpdatedBy: adminID(r)}); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}
