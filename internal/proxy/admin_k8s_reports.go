package proxy

import (
	"net/http"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sReports assembles a deterministic operations report (일간 장애·주간 비용·월간 안정성)
// from locally stored data — no external warehouse required (리포트 센터, 섹션 7).
// GET /admin/k8s/reports?cluster_id=
func (s *Server) handleK8sReports(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	now := time.Now().UTC()

	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Limit: 2000})
	actions, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: clusterID, Limit: 1000})

	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, now, 24*time.Hour)
	sec := analyzer.AnalyzeSecurity(items)
	stability := analyzer.StabilityBuckets(items)

	// Daily: failure conditions + high/critical count + open action backlog.
	highRCA := 0
	for _, c := range rca {
		if c.Severity == "high" || c.Severity == "critical" {
			highRCA++
		}
	}
	openActions := 0
	for _, a := range actions {
		if a.Status == "pending" || a.Status == "approval_required" || a.Status == "approved" {
			openActions++
		}
	}

	// Weekly: cost total + 7-day increases; recent changes (last 7d).
	_, prices, nsTeam, nsCC, clusterGroup, _ := s.costContext(r.Context(), clusterID)
	cost := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)
	snaps, _ := s.db.ListK8sCostSnapshots(r.Context(), clusterID, "namespace", 2000)
	costTrend := analyzer.ComputeCostTrend(snaps)
	costIncreases := []analyzer.CostTrendLine{}
	for _, t := range costTrend {
		if t.Delta > 0 {
			costIncreases = append(costIncreases, t)
		}
		if len(costIncreases) >= 10 {
			break
		}
	}
	weekAgo := now.Add(-7 * 24 * time.Hour)
	recentChanges := 0
	for _, rev := range revisions {
		if rev.ChangeKind == "updated" {
			if t, e := time.Parse(time.RFC3339Nano, rev.ObservedAt); e == nil && t.After(weekAgo) {
				recentChanges++
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": now.Format(time.RFC3339Nano),
		"summary": map[string]any{
			"workloads":        stability.Workloads,
			"high_failures":    highRCA,
			"security_score":   sec.Summary.Score,
			"high_rbac":        sec.Summary.RBACFindings,
			"open_actions":     openActions,
			"monthly_cost_krw": cost.TotalMonthlyKRW,
		},
		"daily_failures": map[string]any{
			"conditions":  analyzer.RCAConditionCounts(rca),
			"high_count":  highRCA,
			"open_actions": openActions,
		},
		"weekly_cost": map[string]any{
			"total_monthly_krw": cost.TotalMonthlyKRW,
			"increases":         costIncreases,
			"recent_changes_7d": recentChanges,
		},
		"monthly_stability": stability,
		"note":              "로컬 저장 데이터(RCA·보안·비용 스냅샷·인벤토리)로 산출한 결정적 리포트입니다. 'AI 내러티브'로 서술형 요약을 생성할 수 있습니다.",
	})
}
