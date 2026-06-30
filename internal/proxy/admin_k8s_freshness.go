package proxy

import (
	"net/http"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Inventory Freshness Score (CLU-REQ-01) + Stale Warning (CLU-REQ-10).
//
// Builds analyzer.FreshnessInput values from the real collection-timing signals — newest
// ObservedAt in the inventory, realtime-agent heartbeat liveness, and the cluster's adaptive
// collect cadence — and returns a per-cluster (and, for a focused cluster, per-namespace and
// per-kind) freshness score plus an overall summary. Other screens attach the same per-cluster
// score as a stale-warning badge via clusterFreshnessBadge.

// clusterCollectSignals captures the timing inputs the freshness scorer needs for one cluster,
// derived once so the cadence/agent lookups aren't repeated per scope.
type clusterCollectSignals struct {
	agentAlive    bool
	agentAttached bool
	agentLastSeen time.Time
	interval      time.Duration
}

// collectSignalsForCluster resolves agent liveness + the adaptive collect cadence for a cluster.
func (s *Server) collectSignalsForCluster(r *http.Request, clusterID string, now time.Time) clusterCollectSignals {
	noAgentSecs := s.k8sPollFlagInt(r.Context(), k8sPollNoAgentSecsFlag, k8sPollNoAgentDefaultSecs)
	withAgentSecs := s.k8sPollFlagInt(r.Context(), k8sPollWithAgentSecsFlag, k8sPollWithAgentDefaultSec)
	sig := clusterCollectSignals{interval: time.Duration(noAgentSecs) * time.Second}
	hbs, err := s.db.ListK8sAgentHeartbeats(r.Context(), clusterID)
	if err == nil {
		for _, h := range hbs {
			sig.agentAttached = true
			if ts, ok := parseK8sHomeTime(h.LastSeen); ok {
				if ts.After(sig.agentLastSeen) {
					sig.agentLastSeen = ts
				}
				if now.Sub(ts) <= agentStaleAfter {
					sig.agentAlive = true
				}
			}
		}
	}
	if sig.agentAlive {
		sig.interval = time.Duration(withAgentSecs) * time.Second
	}
	return sig
}

// newestObserved returns the most recent ObservedAt/UpdatedAt across the given inventory items.
func newestObserved(items []store.K8sInventoryItem) time.Time {
	var newest time.Time
	for _, it := range items {
		for _, raw := range []string{it.ObservedAt, it.UpdatedAt} {
			if ts, ok := parseK8sHomeTime(raw); ok && ts.After(newest) {
				newest = ts
			}
		}
	}
	return newest
}

// clusterFreshness scores one cluster from its inventory + collect signals.
func (s *Server) clusterFreshness(r *http.Request, cluster store.K8sCluster, now time.Time) analyzer.Freshness {
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: cluster.ID, Limit: 10000})
	sig := s.collectSignalsForCluster(r, cluster.ID, now)
	last := newestObserved(items)
	if last.IsZero() {
		// Fall back to the cluster's last successful connect when no inventory rows carry a time.
		if ts, ok := parseK8sHomeTime(cluster.LastConnectedAt); ok {
			last = ts
		}
	}
	// A recorded connect error means the latest collect attempt did not land.
	failed := 0
	if cluster.LastError != "" {
		failed = 1
	}
	return analyzer.ScoreFreshness(analyzer.FreshnessInput{
		Scope:            "cluster",
		Key:              firstNonEmpty(cluster.Name, cluster.ID),
		ClusterID:        cluster.ID,
		LastCollectedAt:  last,
		AgentAlive:       sig.agentAlive,
		AgentAttached:    sig.agentAttached,
		AgentLastSeen:    sig.agentLastSeen,
		ExpectedInterval: sig.interval,
		FailedAttempts:   failed,
		ResourceCount:    len(items),
		Now:              now,
	})
}

// clusterFreshnessBadge returns a compact freshness badge for embedding in other screens
// (Pod detail, RCA, Stack drift, Config impact) so they can show a data timestamp + stale
// warning. Returns the zero value with band "unknown" on a missing cluster.
func (s *Server) clusterFreshnessBadge(r *http.Request, clusterID string, now time.Time) analyzer.Freshness {
	cluster, err := s.db.GetK8sCluster(r.Context(), clusterID)
	if err != nil {
		return analyzer.Freshness{Scope: "cluster", Key: clusterID, ClusterID: clusterID, Band: "unknown", Stale: true, Score: 0, AgeSeconds: -1, Reason: "클러스터를 찾을 수 없습니다."}
	}
	return s.clusterFreshness(r, cluster, now)
}

// handleK8sFreshness serves inventory freshness scores. Without cluster_id it returns one score
// per cluster plus an overall summary; with cluster_id it adds per-namespace and per-kind scores.
// GET /admin/k8s/freshness?cluster_id=
func (s *Server) handleK8sFreshness(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	now := time.Now().UTC()
	clusterID := r.URL.Query().Get("cluster_id")

	clusters, err := s.db.ListK8sClusters(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_clusters_failed")
		return
	}

	clusterScores := make([]analyzer.Freshness, 0, len(clusters))
	for _, c := range clusters {
		if clusterID != "" && c.ID != clusterID {
			continue
		}
		clusterScores = append(clusterScores, s.clusterFreshness(r, c, now))
	}
	summary := analyzer.SummarizeFreshness(clusterScores)

	resp := map[string]any{
		"clusters": clusterScores,
		"summary":  summary,
		"as_of":    now.Format(time.RFC3339),
		"note":     "freshness score는 마지막 수집 시각, 수집 주기, 실시간 agent 생존 여부를 종합한 데이터 신뢰도(0~100)입니다. 50 미만은 오래된 데이터(stale)로 표시됩니다.",
	}

	// Focused view: break the cluster down by namespace and kind for drill-in.
	if clusterID != "" {
		cluster, gErr := s.db.GetK8sCluster(r.Context(), clusterID)
		if gErr == nil {
			items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
			sig := s.collectSignalsForCluster(r, clusterID, now)
			resp["namespaces"] = scopeFreshness(items, sig, now, clusterID, func(it store.K8sInventoryItem) string {
				return firstNonEmpty(it.Namespace, "(cluster-scoped)")
			}, "namespace")
			resp["kinds"] = scopeFreshness(items, sig, now, clusterID, func(it store.K8sInventoryItem) string {
				return firstNonEmpty(it.Kind, "(unknown)")
			}, "kind")
			resp["cluster_name"] = firstNonEmpty(cluster.Name, cluster.ID)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// scopeFreshness groups inventory by a key function and scores each group with the shared
// cluster collect signals (agent liveness + cadence apply cluster-wide).
func scopeFreshness(items []store.K8sInventoryItem, sig clusterCollectSignals, now time.Time, clusterID string, keyOf func(store.K8sInventoryItem) string, scope string) []analyzer.Freshness {
	type bucket struct {
		newest time.Time
		count  int
	}
	buckets := map[string]*bucket{}
	order := []string{}
	for _, it := range items {
		k := keyOf(it)
		b, ok := buckets[k]
		if !ok {
			b = &bucket{}
			buckets[k] = b
			order = append(order, k)
		}
		b.count++
		for _, raw := range []string{it.ObservedAt, it.UpdatedAt} {
			if ts, tok := parseK8sHomeTime(raw); tok && ts.After(b.newest) {
				b.newest = ts
			}
		}
	}
	out := make([]analyzer.Freshness, 0, len(order))
	for _, k := range order {
		b := buckets[k]
		out = append(out, analyzer.ScoreFreshness(analyzer.FreshnessInput{
			Scope:            scope,
			Key:              k,
			ClusterID:        clusterID,
			LastCollectedAt:  b.newest,
			AgentAlive:       sig.agentAlive,
			AgentAttached:    sig.agentAttached,
			AgentLastSeen:    sig.agentLastSeen,
			ExpectedInterval: sig.interval,
			ResourceCount:    b.count,
			Now:              now,
		}))
	}
	return out
}
