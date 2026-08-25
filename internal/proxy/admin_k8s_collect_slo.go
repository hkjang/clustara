package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
)

// Collector SLO Dashboard (CLU-REQ-02) + Collect Gap RCA (CLU-REQ-03).
//
// Reads the recorded collect-run history, aggregates per-cluster SLOs (success rate, latency,
// last success/failure, dominant failure cause), and classifies recent failures into concrete
// causes so operators can separate "collection failed" from "the cluster is in trouble".

// handleK8sCollectSLO serves the collector SLO summary + recent classified failures.
// GET /admin/k8s/collect-slo?cluster_id=&window_hours=&limit=
func (s *Server) handleK8sCollectSLO(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	now := time.Now().UTC()
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	windowHours := intQueryDefault(r, "window_hours", 24, 1, 720)
	limit := intQueryDefault(r, "limit", 1000, 1, 5000)

	runs, err := s.db.ListK8sCollectRuns(r.Context(), clusterID, limit)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "collect_runs_failed")
		return
	}

	// Map cluster ids → names for friendly labels in the SLO rows.
	names := map[string]string{}
	if clusters, cErr := s.db.ListK8sClusters(r.Context()); cErr == nil {
		for _, c := range clusters {
			names[c.ID] = firstNonEmpty(c.Name, c.ID)
		}
	}

	samples := make([]analyzer.CollectRunSample, 0, len(runs))
	type failView struct {
		ID            string `json:"id"`
		ClusterID     string `json:"cluster_id"`
		ClusterName   string `json:"cluster_name"`
		Trigger       string `json:"trigger"`
		Stage         string `json:"stage"`
		OK            bool   `json:"ok"`
		ErrorText     string `json:"error_text,omitempty"`
		LatencyMS     int64  `json:"latency_ms"`
		ResourceCount int    `json:"resource_count"`
		StartedAt     string `json:"started_at"`
		analyzer.CollectGap
	}
	recentFailures := []failView{}
	for _, run := range runs {
		started, _ := parseK8sHomeTime(run.StartedAt)
		samples = append(samples, analyzer.CollectRunSample{
			ClusterID:   run.ClusterID,
			ClusterName: names[run.ClusterID],
			Stage:       run.Stage,
			OK:          run.OK,
			Category:    run.Category,
			LatencyMS:   run.LatencyMS,
			Trigger:     run.Trigger,
			StartedAt:   started,
		})
		if !run.OK && len(recentFailures) < 25 {
			recentFailures = append(recentFailures, failView{
				ID:            run.ID,
				ClusterID:     run.ClusterID,
				ClusterName:   firstNonEmpty(names[run.ClusterID], run.ClusterID),
				Trigger:       run.Trigger,
				Stage:         run.Stage,
				OK:            run.OK,
				ErrorText:     run.ErrorText,
				LatencyMS:     run.LatencyMS,
				ResourceCount: run.ResourceCount,
				StartedAt:     run.StartedAt,
				CollectGap:    analyzer.ClassifyCollectGap(run.Stage, run.ErrorText),
			})
		}
	}

	summary := analyzer.SummarizeCollectSLO(samples, windowHours, now)
	writeJSON(w, http.StatusOK, map[string]any{
		"slo":             summary,
		"recent_failures": recentFailures,
		"as_of":           now.Format(time.RFC3339),
		"note":            "수집 성공률·지연·실패 원인(RCA)을 종합한 Collector SLO입니다. cluster_issue=true 실패는 클러스터/인프라 쪽 신호, false는 수집 설정·권한 쪽 신호입니다.",
	})
}

// intQueryDefault parses an int query param, clamped to [min,max], with a default fallback.
func intQueryDefault(r *http.Request, key string, def, min, max int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}
