package proxy

import (
	"net/http"
	"sort"
	"strings"
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
	riskScope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("risk_scope")))
	if riskScope != "all" && riskScope != "system" {
		riskScope = "application"
	}
	ownerByPod := k8sPodOwnerIndex(items)

	rca := analyzer.AnalyzeRCA(items, events)
	rca = analyzer.EnrichWithConfigChanges(rca, revisions, time.Now().UTC(), 24*time.Hour)

	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

	// Failure candidates TOP10 (severity-sorted).
	failures := append([]analyzer.RCAFinding{}, rca...)
	analyzer.AttachFindingResources(failures, items) // CPU/mem tags (e.g. OOMKilled memory limit)
	sort.SliceStable(failures, func(i, j int) bool { return sevRank[failures[i].Severity] < sevRank[failures[j].Severity] })
	type failOut struct {
		analyzer.RCAFinding
		ClusterName string `json:"cluster_name"`
	}
	failList := []failOut{}
	for _, f := range failures {
		if suppressBatchPodRisk(f, ownerByPod) || !k8sRiskScopeMatches(f.Namespace, riskScope) {
			continue
		}
		if len(failList) >= 10 {
			break
		}
		failList = append(failList, failOut{RCAFinding: f, ClusterName: name[f.ClusterID]})
	}

	// Clusters at risk TOP5 (RCA high/critical + risky inventory + error status).
	riskScore := map[string]int{}
	for _, f := range rca {
		if suppressBatchPodRisk(f, ownerByPod) || !k8sRiskScopeMatches(f.Namespace, riskScope) {
			continue
		}
		if f.Severity == "high" || f.Severity == "critical" {
			riskScore[f.ClusterID] += 3
		}
	}
	for _, it := range items {
		if !k8sRiskScopeMatches(it.Namespace, riskScope) || isBatchWorkloadItem(it, ownerByPod) {
			continue
		}
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
		if rev.ChangeKind != "updated" || !k8sRiskScopeMatches(rev.Namespace, riskScope) {
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

	// Cost increase TOP from accumulated daily snapshots (local, no ClickHouse needed).
	costIncrease := []analyzer.CostTrendLine{}
	if snaps, serr := s.db.ListK8sCostSnapshots(r.Context(), "", "namespace", 2000); serr == nil && len(snaps) > 0 {
		for _, t := range analyzer.ComputeCostTrend(snaps) {
			if t.Delta > 0 {
				costIncrease = append(costIncrease, t)
			}
			if len(costIncrease) >= 10 {
				break
			}
		}
	}
	freshness := summarizeK8sHomeFreshness(items, name)
	agentSummary := k8sHomeAgentSummary{}
	if hbs, herr := s.db.ListK8sAgentHeartbeats(r.Context(), ""); herr == nil {
		agentSummary = summarizeK8sHomeAgents(hbs, time.Now().UTC())
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":       time.Now().UTC().Format(time.RFC3339Nano),
		"data_freshness":     freshness,
		"agents":             agentSummary,
		"clusters_at_risk":   risks,
		"failure_candidates": failList,
		"risk_scope":         riskScope,
		"recent_changes":     changes,
		"cost_top":           costTop,
		"cost_increase":      costIncrease,
		"cost_note":          "namespace별 월 추정 비용 TOP. 증가 TOP은 일별 스냅샷(POST /admin/k8s/cost/snapshot) 2일 이상 누적 시 표시됩니다.",
	})
}

type k8sHomeFreshness struct {
	InventoryItems      int                       `json:"inventory_items"`
	NewestObservedAt    string                    `json:"newest_observed_at"`
	NewestAgeSeconds    int                       `json:"newest_age_seconds"`
	OldestObservedAt    string                    `json:"oldest_observed_at"`
	OldestAgeSeconds    int                       `json:"oldest_age_seconds"`
	ClustersWithData    int                       `json:"clusters_with_data"`
	ClustersWithoutData int                       `json:"clusters_without_data"`
	ByCluster           []k8sHomeClusterFreshness `json:"by_cluster"`
}

type k8sHomeClusterFreshness struct {
	ClusterID      string `json:"cluster_id"`
	ClusterName    string `json:"cluster_name"`
	Items          int    `json:"items"`
	LastObservedAt string `json:"last_observed_at"`
	AgeSeconds     int    `json:"age_seconds"`
}

type k8sHomeAgentSummary struct {
	Count              int    `json:"count"`
	Live               int    `json:"live"`
	Stale              int    `json:"stale"`
	MaxWatchLagMS      int64  `json:"max_watch_lag_ms"`
	LastSeen           string `json:"last_seen"`
	LastSeenAgeSeconds int    `json:"last_seen_age_seconds"`
	LastErrorCount     int    `json:"last_error_count"`
	StaleAfterSeconds  int    `json:"stale_after_seconds"`
}

func summarizeK8sHomeFreshness(items []store.K8sInventoryItem, clusterNames map[string]string) k8sHomeFreshness {
	now := time.Now().UTC()
	out := k8sHomeFreshness{InventoryItems: len(items), NewestAgeSeconds: -1, OldestAgeSeconds: -1}
	byCluster := map[string]*k8sHomeClusterFreshness{}
	var newest, oldest time.Time
	for _, item := range items {
		cf := byCluster[item.ClusterID]
		if cf == nil {
			cf = &k8sHomeClusterFreshness{ClusterID: item.ClusterID, ClusterName: clusterNames[item.ClusterID], AgeSeconds: -1}
			byCluster[item.ClusterID] = cf
		}
		cf.Items++
		ts, ok := parseK8sHomeTime(item.ObservedAt)
		if !ok {
			continue
		}
		if newest.IsZero() || ts.After(newest) {
			newest = ts
			out.NewestObservedAt = item.ObservedAt
		}
		if oldest.IsZero() || ts.Before(oldest) {
			oldest = ts
			out.OldestObservedAt = item.ObservedAt
		}
		if cf.LastObservedAt == "" {
			cf.LastObservedAt = item.ObservedAt
			cf.AgeSeconds = int(now.Sub(ts).Seconds())
			continue
		}
		if cur, ok := parseK8sHomeTime(cf.LastObservedAt); ok && ts.After(cur) {
			cf.LastObservedAt = item.ObservedAt
			cf.AgeSeconds = int(now.Sub(ts).Seconds())
		}
	}
	if !newest.IsZero() {
		out.NewestAgeSeconds = int(now.Sub(newest).Seconds())
	}
	if !oldest.IsZero() {
		out.OldestAgeSeconds = int(now.Sub(oldest).Seconds())
	}
	for clusterID, clusterName := range clusterNames {
		if cf := byCluster[clusterID]; cf != nil {
			out.ClustersWithData++
			out.ByCluster = append(out.ByCluster, *cf)
		} else {
			out.ClustersWithoutData++
			out.ByCluster = append(out.ByCluster, k8sHomeClusterFreshness{ClusterID: clusterID, ClusterName: clusterName, AgeSeconds: -1})
		}
	}
	sort.SliceStable(out.ByCluster, func(i, j int) bool {
		a, b := out.ByCluster[i], out.ByCluster[j]
		if a.LastObservedAt == "" {
			return false
		}
		if b.LastObservedAt == "" {
			return true
		}
		return a.LastObservedAt > b.LastObservedAt
	})
	return out
}

func summarizeK8sHomeAgents(hbs []store.K8sAgentHeartbeat, now time.Time) k8sHomeAgentSummary {
	out := k8sHomeAgentSummary{Count: len(hbs), LastSeenAgeSeconds: -1, StaleAfterSeconds: int(agentStaleAfter.Seconds())}
	var lastSeen time.Time
	for _, h := range hbs {
		if h.LastError != "" {
			out.LastErrorCount++
		}
		if h.WatchLagMS > out.MaxWatchLagMS {
			out.MaxWatchLagMS = h.WatchLagMS
		}
		ts, ok := parseK8sHomeTime(h.LastSeen)
		isStale := true
		if ok {
			isStale = now.Sub(ts) > agentStaleAfter
			if lastSeen.IsZero() || ts.After(lastSeen) {
				lastSeen = ts
				out.LastSeen = h.LastSeen
				out.LastSeenAgeSeconds = int(now.Sub(ts).Seconds())
			}
		}
		if isStale {
			out.Stale++
		} else {
			out.Live++
		}
	}
	return out
}

func parseK8sHomeTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts, true
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts, true
	}
	return time.Time{}, false
}
