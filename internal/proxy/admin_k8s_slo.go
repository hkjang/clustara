package proxy

import (
	"net/http"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sSLO rolls up incident history into per-namespace SLO / error-budget lines over a window.
// GET /admin/k8s/slo?cluster_id=&days=30&target=99.9
func (s *Server) handleK8sSLO(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	days := intParam(q.Get("days"), 30)
	if days <= 0 || days > 365 {
		days = 30
	}
	target := floatParam(q.Get("target"), 99.9)
	window := time.Duration(days) * 24 * time.Hour

	// Pull both open and resolved incidents in the window; ComputeSLO filters by opened_at.
	incs, err := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{
		ClusterID: q.Get("cluster_id"), Limit: 1000,
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_slo_failed")
		return
	}
	lines := analyzer.ComputeSLO(incs, time.Now().UTC(), window, target)

	breached := 0
	worst := 100.0
	for _, l := range lines {
		if l.Breached {
			breached++
		}
		if l.AvailabilityPct < worst {
			worst = l.AvailabilityPct
		}
	}
	if len(lines) == 0 {
		worst = 100.0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window_days":     days,
		"target_pct":      target,
		"services":        lines,
		"count":           len(lines),
		"breached":        breached,
		"worst_avail_pct": worst,
		"note":            "가용성은 장애(인시던트) 지속시간을 다운타임 프록시로 산출 — 에러버짓 = 목표 대비 허용 다운타임",
	})
}
