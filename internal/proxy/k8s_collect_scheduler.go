package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

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
	k8sPollNoAgentDefaultSecs  = 60   // no live agent → poll every 60s (keep inventory fresh)
	k8sPollWithAgentDefaultSec = 1800 // live agent → reconcile poll every 30m
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

	clusters, err := s.db.ListK8sClusters(ctx)
	if err != nil {
		slog.Warn("k8s collect scheduler: list clusters failed", "error", err)
		return
	}
	for _, cluster := range clusters {
		interval := time.Duration(noAgentSecs) * time.Second
		if s.clusterHasLiveAgent(ctx, cluster.ID, now) {
			interval = time.Duration(withAgentSecs) * time.Second
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
		"enabled":          s.k8sPollFlagBool(ctx, k8sPollEnabledFlag, true),
		"no_agent_secs":    s.k8sPollFlagInt(ctx, k8sPollNoAgentSecsFlag, k8sPollNoAgentDefaultSecs),
		"with_agent_secs":  s.k8sPollFlagInt(ctx, k8sPollWithAgentSecsFlag, k8sPollWithAgentDefaultSec),
		"agent_stale_secs": int(agentStaleAfter.Seconds()),
		"tick_secs":        int(k8sCollectTickInterval.Seconds()),
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
			"note": "실시간 agent가 없는 클러스터는 no_agent_secs 주기로 자주 수집하고, agent가 살아있으면 with_agent_secs 주기로만 보정 수집합니다."})
	case http.MethodPost:
		var in struct {
			Enabled       *bool `json:"enabled"`
			NoAgentSecs   *int  `json:"no_agent_secs"`
			WithAgentSecs *int  `json:"with_agent_secs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if in.NoAgentSecs != nil && *in.NoAgentSecs < 15 {
			writeOpenAIError(w, http.StatusBadRequest, "no_agent_secs는 15초 이상이어야 합니다", "invalid_request_error", "interval_too_small")
			return
		}
		if err := s.setK8sPollConfig(r.Context(), adminID(r), in.Enabled, in.NoAgentSecs, in.WithAgentSecs); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "collect_config_failed")
			return
		}
		s.auditAdmin(r, "k8s.collect.config", "", auditJSON(s.k8sPollConfig(r.Context())))
		writeJSON(w, http.StatusOK, map[string]any{"config": s.k8sPollConfig(r.Context())})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// setK8sPollConfig persists scheduler config flags.
func (s *Server) setK8sPollConfig(ctx context.Context, actor string, enabled *bool, noAgentSecs, withAgentSecs *int) error {
	if enabled != nil {
		v := "false"
		if *enabled {
			v = "true"
		}
		if err := s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sPollEnabledFlag, Value: v, UpdatedBy: actor}); err != nil {
			return err
		}
	}
	if noAgentSecs != nil && *noAgentSecs > 0 {
		if err := s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sPollNoAgentSecsFlag, Value: strconv.Itoa(*noAgentSecs), UpdatedBy: actor}); err != nil {
			return err
		}
	}
	if withAgentSecs != nil && *withAgentSecs > 0 {
		if err := s.db.SetFlag(ctx, store.RuntimeFlag{Key: k8sPollWithAgentSecsFlag, Value: strconv.Itoa(*withAgentSecs), UpdatedBy: actor}); err != nil {
			return err
		}
	}
	return nil
}
