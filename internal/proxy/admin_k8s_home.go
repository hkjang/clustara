package proxy

import (
	"net/http"
	"sort"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sHome aggregates the cross-cluster operations home: clusters at risk (TOP5), failure
// candidates (TOP10) and recent changes (TOP10). Cost (TOP10) is a placeholder until PR10.
// GET /admin/k8s/home
func (s *Server) handleK8sHome(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusters, err := s.db.ListK8sClusters(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_clusters_failed")
		return
	}
	name := map[string]string{}
	for _, c := range clusters {
		name[c.ID] = c.Name
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{Limit: 4000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), "", 1000)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{Limit: 1000})

	rca := analyzer.AnalyzeRCA(items, events)
	rca = analyzer.EnrichWithConfigChanges(rca, revisions, time.Now().UTC(), 24*time.Hour)

	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

	// Failure candidates TOP10 (severity-sorted).
	failures := append([]analyzer.RCAFinding{}, rca...)
	sort.SliceStable(failures, func(i, j int) bool { return sevRank[failures[i].Severity] < sevRank[failures[j].Severity] })
	type failOut struct {
		analyzer.RCAFinding
		ClusterName string `json:"cluster_name"`
	}
	failList := []failOut{}
	for _, f := range failures {
		if len(failList) >= 10 {
			break
		}
		failList = append(failList, failOut{RCAFinding: f, ClusterName: name[f.ClusterID]})
	}

	// Clusters at risk TOP5 (RCA high/critical + risky inventory + error status).
	riskScore := map[string]int{}
	for _, f := range rca {
		if f.Severity == "high" || f.Severity == "critical" {
			riskScore[f.ClusterID] += 3
		}
	}
	for _, it := range items {
		if it.RiskLevel == "high" || it.RiskLevel == "critical" {
			riskScore[it.ClusterID]++
		}
	}
	for _, c := range clusters {
		if c.Status == "error" {
			riskScore[c.ID] += 5
		}
	}
	type clusterRisk struct {
		ClusterID string `json:"cluster_id"`
		Name      string `json:"name"`
		Score     int    `json:"score"`
		Status    string `json:"status"`
	}
	risks := []clusterRisk{}
	for _, c := range clusters {
		if riskScore[c.ID] > 0 {
			risks = append(risks, clusterRisk{ClusterID: c.ID, Name: c.Name, Score: riskScore[c.ID], Status: c.Status})
		}
	}
	sort.SliceStable(risks, func(i, j int) bool { return risks[i].Score > risks[j].Score })
	if len(risks) > 5 {
		risks = risks[:5]
	}

	// Recent changes TOP10 (revisions are already newest-first; keep real changes).
	type changeOut struct {
		store.K8sResourceRevision
		ClusterName string `json:"cluster_name"`
	}
	changes := []changeOut{}
	for _, rev := range revisions {
		if rev.ChangeKind != "updated" {
			continue
		}
		if len(changes) >= 10 {
			break
		}
		rev.Spec = nil
		changes = append(changes, changeOut{K8sResourceRevision: rev, ClusterName: name[rev.ClusterID]})
	}

	// Cost TOP (by namespace). True period-over-period "increase" needs history (ClickHouse).
	costTop := []analyzer.CostLine{}
	if _, prices, nsTeam, nsCC, clusterGroup, cerr := s.costContext(r.Context(), ""); cerr == nil {
		cost := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)
		costTop = cost.ByNamespace
		if len(costTop) > 10 {
			costTop = costTop[:10]
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":       time.Now().UTC().Format(time.RFC3339Nano),
		"clusters_at_risk":   risks,
		"failure_candidates": failList,
		"recent_changes":     changes,
		"cost_top":           costTop,
		"cost_note":          "namespace별 월 추정 비용 TOP. 전일 대비 증가율은 이력 적재(ClickHouse) 후 제공됩니다.",
	})
}
