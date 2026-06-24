package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"clustara/internal/collector"
	"clustara/internal/store"
)

// agentStaleAfter is how long without a heartbeat before an agent is considered stale/offline.
const agentStaleAfter = 90 * time.Second

// handleK8sAgentEvents ingests a realtime watch-delta batch from an in-cluster collector agent.
// POST /admin/k8s/agent/events
func (s *Server) handleK8sAgentEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var batch collector.AgentBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if _, err := s.db.GetK8sCluster(r.Context(), batch.ClusterID); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+batch.ClusterID, "invalid_request_error", "cluster_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	result, err := collector.ApplyAgentBatch(r.Context(), s.db, batch, newID)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_agent_batch_failed")
		return
	}
	opened, updated, evaluated, _ := s.scanK8sIncidentsForCluster(r.Context(), batch.ClusterID)
	writeJSON(w, http.StatusOK, map[string]any{
		"result": result,
		"incidents": map[string]int{
			"opened": opened, "updated": updated, "evaluated": evaluated,
		},
	})
}

// handleK8sAgentStatus reports collector agent liveness + watch telemetry, flagging stale agents.
// GET /admin/k8s/agent/status?cluster_id=
func (s *Server) handleK8sAgentStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	hbs, err := s.db.ListK8sAgentHeartbeats(r.Context(), r.URL.Query().Get("cluster_id"))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_agent_status_failed")
		return
	}
	now := time.Now().UTC()
	type agentView struct {
		store.K8sAgentHeartbeat
		Stale      bool `json:"stale"`
		AgeSeconds int  `json:"age_seconds"`
	}
	views := make([]agentView, 0, len(hbs))
	stale := 0
	for _, h := range hbs {
		age := -1
		isStale := true
		if t, e := time.Parse(time.RFC3339Nano, h.LastSeen); e == nil {
			age = int(now.Sub(t).Seconds())
			isStale = now.Sub(t) > agentStaleAfter
		}
		if isStale {
			stale++
		}
		views = append(views, agentView{K8sAgentHeartbeat: h, Stale: isStale, AgeSeconds: age})
	}
	offsets, _ := s.db.ListK8sCollectorOffsets(r.Context(), r.URL.Query().Get("cluster_id"))
	recent, _ := s.db.ListK8sWatchEvents(r.Context(), r.URL.Query().Get("cluster_id"), 50)
	writeJSON(w, http.StatusOK, map[string]any{
		"agents":           views,
		"offsets":          offsets,
		"recent_events":    recent,
		"count":            len(views),
		"stale":            stale,
		"stale_after_secs": int(agentStaleAfter.Seconds()),
		"note":             "실시간 watch agent의 하트비트 — 마지막 수신 후 90초 경과 시 stale(오프라인)로 표시됩니다.",
	})
}
