package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Adaptive inventory collection scheduler. Clusters WITHOUT a live realtime agent (clustara-agent
// pushing watch deltas) go stale between manual collects, so the scheduler polls them frequently;
// clusters WITH a live agent only need an occasional reconcile poll (the agent keeps them fresh).
// Cadence is runtime-configurable via flags and read fresh each tick so changes apply without a
// restart (and across pods).
const (
	k8sCollectTickInterval     = 20 * time.Second
	k8sPollEnabledFlag         = "k8s_poll_enabled"
	k8sPollNoAgentSecsFlag     = "k8s_poll_no_agent_secs"
	k8sPollWithAgentSecsFlag   = "k8s_poll_with_agent_secs"
	k8sPollBurstSecsFlag       = "k8s_poll_burst_secs"
	k8sBurstWindowSecsFlag     = "k8s_burst_window_secs"
	k8sPollNoAgentDefaultSecs  = 60   // no live agent → poll every 60s (keep inventory fresh)
	k8sPollWithAgentDefaultSec = 1800 // live agent → reconcile poll every 30m
	k8sPollBurstDefaultSecs    = 20   // change-aware burst → poll as fast as the tick allows
	k8sBurstWindowDefaultSecs  = 300  // burst lasts 5m after a change
)

// k8sCollectScheduler runs the adaptive polling loop. Started once at server startup.
func (s *Server) k8sCollectScheduler() {
	lastAttempt := map[string]time.Time{} // local rate-limit (survives client-stage failures, resets on restart)
	t := time.NewTicker(k8sCollectTickInterval)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		s.runK8sCollectTick(ctx, lastAttempt, time.Now().UTC())
		cancel()
	}
}

func (s *Server) runK8sCollectTick(ctx context.Context, lastAttempt map[string]time.Time, now time.Time) {
	if !s.k8sPollFlagBool(ctx, k8sPollEnabledFlag, true) {
		return
	}
	noAgentSecs := s.k8sPollFlagInt(ctx, k8sPollNoAgentSecsFlag, k8sPollNoAgentDefaultSecs)
	withAgentSecs := s.k8sPollFlagInt(ctx, k8sPollWithAgentSecsFlag, k8sPollWithAgentDefaultSec)
	burstSecs := s.k8sPollFlagInt(ctx, k8sPollBurstSecsFlag, k8sPollBurstDefaultSecs)

	// Change-aware burst: collect clusters with an active burst at high frequency for a short
	// window after a change, so post-change verification sees fresh inventory quickly.
	nowStr := now.Format(time.RFC3339Nano)
	_ = s.db.PruneExpiredK8sCollectBursts(ctx, nowStr)
	bursting := map[string]bool{}
	if bursts, err := s.db.ListActiveK8sCollectBursts(ctx, "", nowStr); err == nil {
		for _, b := range bursts {
			bursting[b.ClusterID] = true
		}
	}

	// Adaptive policy (CLU-REQ-04): open incidents per cluster shorten cadence cluster-wide.
	openIncidents := map[string]int{}
	if incs, err := s.db.ListK8sIncidents(ctx, store.K8sIncidentFilter{Status: "open", Limit: 2000}); err == nil {
		for _, inc := range incs {
			openIncidents[inc.ClusterID]++
		}
	}

	clusters, err := s.db.ListK8sClusters(ctx)
	if err != nil {
		slog.Warn("k8s collect scheduler: list clusters failed", "error", err)
		return
	}
	for _, cluster := range clusters {
		// Adaptive cadence from agent liveness + cluster priority + open incidents + watch entries.
		watchCount := 0
		if ws, err := s.db.ListK8sPodWatches(ctx, store.K8sPodWatchFilter{ClusterID: cluster.ID, Limit: 200}); err == nil {
			watchCount = len(ws)
		}
		secs, _ := analyzer.EffectiveCollectInterval(analyzer.CollectPolicyInput{
			BaseSecs: noAgentSecs, WithAgentSecs: withAgentSecs,
			AgentAlive:    s.clusterHasLiveAgent(ctx, cluster.ID, now),
			Priority:      strings.ToLower(strings.TrimSpace(cluster.Labels["priority"])),
			OpenIncidents: openIncidents[cluster.ID],
			WatchCount:    watchCount,
		})
		interval := time.Duration(secs) * time.Second
		// An active burst overrides the normal cadence with the (shorter) burst interval.
		if bursting[cluster.ID] {
			if burst := time.Duration(burstSecs) * time.Second; burst < interval {
				interval = burst
			}
		}
		// Gate on the later of: last local attempt (rate-limits failing clusters) and the
		// DB-recorded last connect (dedups across pods for collects that reached the cluster).
		last := lastAttempt[cluster.ID]
		if dbTS, ok := parseK8sHomeTime(cluster.LastConnectedAt); ok && dbTS.After(last) {
			last = dbTS
		}
		if !last.IsZero() && now.Sub(last) < interval {
			continue
		}
		lastAttempt[cluster.ID] = now
		out := s.collectClusterInventoryTriggered(ctx, cluster, "scheduled")
		if out.Err != nil {
			slog.Warn("k8s scheduled collect failed", "cluster", cluster.ID, "stage", out.Stage, "error", out.Err)
			continue
		}
		slog.Debug("k8s scheduled collect ok", "cluster", cluster.ID, "interval_s", int(interval.Seconds()))
	}
}

// clusterHasLiveAgent reports whether any realtime agent heartbeat for the cluster is within the
// stale threshold (i.e. an in-cluster agent is actively pushing watch deltas).
func (s *Server) clusterHasLiveAgent(ctx context.Context, clusterID string, now time.Time) bool {
	hbs, err := s.db.ListK8sAgentHeartbeats(ctx, clusterID)
	if err != nil {
		return false
	}
	for _, h := range hbs {
		if ts, ok := parseK8sHomeTime(h.LastSeen); ok && now.Sub(ts) <= agentStaleAfter {
			return true
		}
	}
	return false
}

// registerCollectBurst opens a change-aware burst window for a cluster so the scheduler collects
// it at high frequency until the window expires. Best-effort: errors are swallowed (telemetry).
func (s *Server) registerCollectBurst(ctx context.Context, clusterID, namespace, trigger, reason string) {
	if strings.TrimSpace(clusterID) == "" {
		return
	}
	windowSecs := s.k8sPollFlagInt(ctx, k8sBurstWindowSecsFlag, k8sBurstWindowDefaultSecs)
	now := time.Now().UTC()
	_ = s.db.RegisterK8sCollectBurst(ctx, store.K8sCollectBurst{
		ID:        newID("k8sburst"),
		ClusterID: clusterID,
		Namespace: namespace,
		Reason:    reason,
		Trigger:   trigger,
		StartedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Duration(windowSecs) * time.Second).Format(time.RFC3339Nano),
	})
}

func (s *Server) k8sPollFlagBool(ctx context.Context, key string, def bool) bool {
	if flag, found, err := s.db.GetFlag(ctx, key); err == nil && found {
		switch flag.Value {
		case "true", "1":
			return true
		case "false", "0":
			return false
		}
	}
	return def
}

func (s *Server) k8sPollFlagInt(ctx context.Context, key string, def int) int {
	if flag, found, err := s.db.GetFlag(ctx, key); err == nil && found {
		if n, err := strconv.Atoi(flag.Value); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// k8sPollConfig returns the effective scheduler config (for the settings UI).
func (s *Server) k8sPollConfig(ctx context.Context) map[string]any {
	return map[string]any{
		"enabled":           s.k8sPollFlagBool(ctx, k8sPollEnabledFlag, true),
		"no_agent_secs":     s.k8sPollFlagInt(ctx, k8sPollNoAgentSecsFlag, k8sPollNoAgentDefaultSecs),
		"with_agent_secs":   s.k8sPollFlagInt(ctx, k8sPollWithAgentSecsFlag, k8sPollWithAgentDefaultSec),
		"burst_secs":        s.k8sPollFlagInt(ctx, k8sPollBurstSecsFlag, k8sPollBurstDefaultSecs),
		"burst_window_secs": s.k8sPollFlagInt(ctx, k8sBurstWindowSecsFlag, k8sBurstWindowDefaultSecs),
		"agent_stale_secs":  int(agentStaleAfter.Seconds()),
		"tick_secs":         int(k8sCollectTickInterval.Seconds()),
	}
}

// handleK8sCollectConfig serves the adaptive collection scheduler config.
// GET/POST /admin/k8s/collect-config {enabled, no_agent_secs, with_agent_secs}
func (s *Server) handleK8sCollectConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"config": s.k8sPollConfig(r.Context()),
			"cadences": s.effectiveCadencePreview(r.Context()),
			"note":     "실시간 agent가 없는 클러스터는 no_agent_secs 주기로 자주 수집하고, agent가 살아있으면 with_agent_secs 주기로만 보정 수집합니다. 적응형 정책(CLU-REQ-04): 우선순위(label priority)·미해결 incident·watch 등록에 따라 주기를 자동 조정합니다."})
	case http.MethodPost:
		var in struct {
			Enabled         *bool `json:"enabled"`
			NoAgentSecs     *int  `json:"no_agent_secs"`
			WithAgentSecs   *int  `json:"with_agent_secs"`
			BurstSecs       *int  `json:"burst_secs"`
			BurstWindowSecs *int  `json:"burst_window_secs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if in.NoAgentSecs != nil && *in.NoAgentSecs < 15 {
			writeOpenAIError(w, http.StatusBadRequest, "no_agent_secs는 15초 이상이어야 합니다", "invalid_request_error", "interval_too_small")
			return
		}
		if in.BurstSecs != nil && *in.BurstSecs < 10 {
			writeOpenAIError(w, http.StatusBadRequest, "burst_secs는 10초 이상이어야 합니다", "invalid_request_error", "interval_too_small")
			return
		}
		if err := s.setK8sPollConfig(r.Context(), adminID(r), in.Enabled, in.NoAgentSecs, in.WithAgentSecs, in.BurstSecs, in.BurstWindowSecs); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "collect_config_failed")
			return
		}
		s.auditAdmin(r, "k8s.collect.config", "", auditJSON(s.k8sPollConfig(r.Context())))
		writeJSON(w, http.StatusOK, map[string]any{"config": s.k8sPollConfig(r.Context())})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// effectiveCadencePreview computes the adaptive collect cadence + reason per cluster (for the UI).
func (s *Server) effectiveCadencePreview(ctx context.Context) []map[string]any {
	noAgentSecs := s.k8sPollFlagInt(ctx, k8sPollNoAgentSecsFlag, k8sPollNoAgentDefaultSecs)
	withAgentSecs := s.k8sPollFlagInt(ctx, k8sPollWithAgentSecsFlag, k8sPollWithAgentDefaultSec)
	now := time.Now().UTC()
	openIncidents := map[string]int{}
	if incs, err := s.db.ListK8sIncidents(ctx, store.K8sIncidentFilter{Status: "open", Limit: 2000}); err == nil {
		for _, inc := range incs {
			openIncidents[inc.ClusterID]++
		}
	}
	clusters, err := s.db.ListK8sClusters(ctx)
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(clusters))
	for _, c := range clusters {
		watchCount := 0
		if ws, e := s.db.ListK8sPodWatches(ctx, store.K8sPodWatchFilter{ClusterID: c.ID, Limit: 200}); e == nil {
			watchCount = len(ws)
		}
		agentAlive := s.clusterHasLiveAgent(ctx, c.ID, now)
		secs, reason := analyzer.EffectiveCollectInterval(analyzer.CollectPolicyInput{
			BaseSecs: noAgentSecs, WithAgentSecs: withAgentSecs, AgentAlive: agentAlive,
			Priority: strings.ToLower(strings.TrimSpace(c.Labels["priority"])), OpenIncidents: openIncidents[c.ID], WatchCount: watchCount,
		})
		out = append(out, map[string]any{
			"cluster_id": c.ID, "cluster_name": firstNonEmpty(c.Name, c.ID),
			"priority": firstNonEmpty(strings.ToLower(strings.TrimSpace(c.Labels["priority"])), "normal"),
			"agent_alive": agentAlive, "open_incidents": openIncidents[c.ID], "watch_count": watchCount,
			"effective_secs": secs, "reason": reason,
		})
	}
	return out
}

// handleK8sCollectBursts lists active change-aware burst windows, or (POST) opens one manually.
// GET  /admin/k8s/collect-bursts?cluster_id=
// POST /admin/k8s/collect-bursts {cluster_id, namespace, reason}
func (s *Server) handleK8sCollectBursts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		bursts, err := s.db.ListActiveK8sCollectBursts(r.Context(), strings.TrimSpace(r.URL.Query().Get("cluster_id")), "")
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "collect_bursts_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"bursts": bursts, "config": s.k8sPollConfig(r.Context()),
			"note": "변경(Config/Stack/Action) 직후 해당 클러스터를 짧은 기간 고빈도 수집하는 burst 창입니다.",
		})
	case http.MethodPost:
		var in struct {
			ClusterID string `json:"cluster_id"`
			Namespace string `json:"namespace"`
			Reason    string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.ClusterID) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required", "invalid_request_error", "missing_cluster_id")
			return
		}
		s.registerCollectBurst(r.Context(), in.ClusterID, in.Namespace, "manual", firstNonEmpty(in.Reason, "manual burst"))
		s.auditAdmin(r, "k8s.collect.burst", in.ClusterID, auditJSON(map[string]string{"namespace": in.Namespace, "trigger": "manual"}))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": s.k8sPollConfig(r.Context())})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// setK8sPollConfig persists scheduler config flags.
func (s *Server) setK8sPollConfig(ctx context.Context, actor string, enabled *bool, noAgentSecs, withAgentSecs, burstSecs, burstWindowSecs *int) error {
	if enabled != nil {
		v := "false"
		if *enabled {
			v = "true"
		}
		if err := s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sPollEnabledFlag, Value: v, UpdatedBy: actor}); err != nil {
			return err
		}
	}
	intFlags := []struct {
		key string
		val *int
	}{
		{k8sPollNoAgentSecsFlag, noAgentSecs},
		{k8sPollWithAgentSecsFlag, withAgentSecs},
		{k8sPollBurstSecsFlag, burstSecs},
		{k8sBurstWindowSecsFlag, burstWindowSecs},
	}
	for _, f := range intFlags {
		if f.val != nil && *f.val > 0 {
			if err := s.db.SetFlag(ctx, store.RuntimeFlag{Key: f.key, Value: strconv.Itoa(*f.val), UpdatedBy: actor}); err != nil {
				return err
			}
		}
	}
	return nil
}
