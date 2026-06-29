package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// buildK8sReportDigest assembles the compact operations digest KPIs from local data and renders the
// Mattermost-friendly text (mirrors the report center, condensed for delivery).
func (s *Server) buildK8sReportDigest(ctx context.Context, clusterID string) (string, error) {
	now := time.Now().UTC()
	items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		return "", err
	}
	events, _ := s.db.ListK8sEvents(ctx, clusterID, 1000)
	revisions, _ := s.db.ListK8sRevisions(ctx, store.K8sRevisionFilter{ClusterID: clusterID, Limit: 2000})
	actions, _ := s.db.ListK8sActionRequests(ctx, store.K8sActionFilter{ClusterID: clusterID, Limit: 1000})
	incidents, _ := s.db.ListK8sIncidents(ctx, store.K8sIncidentFilter{ClusterID: clusterID, Limit: 1000})

	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, now, 24*time.Hour)
	sec := analyzer.AnalyzeSecurity(items)
	stability := analyzer.StabilityBuckets(items)

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
	_, prices, nsTeam, nsCC, clusterGroup, _ := s.costContext(ctx, clusterID)
	cost := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)
	snaps, _ := s.db.ListK8sCostSnapshots(ctx, clusterID, "namespace", 2000)
	topIncrease := ""
	for _, t := range analyzer.ComputeCostTrend(snaps) {
		if t.Delta > 0 {
			topIncrease = fmt.Sprintf("%s +%.0f%%", t.Key, t.PctChange)
			break
		}
	}
	sloBreaches := 0
	for _, l := range analyzer.ComputeSLO(incidents, now, 30*24*time.Hour, 99.9) {
		if l.Breached {
			sloBreaches++
		}
	}

	return analyzer.FormatReportDigest(analyzer.ReportDigestInput{
		ClusterID: clusterID, GeneratedAt: now.Format("2006-01-02 15:04 UTC"),
		Workloads: stability.Workloads, HighFailures: highRCA, SecurityScore: sec.Summary.Score,
		OpenActions: openActions, MonthlyCostKRW: cost.TotalMonthlyKRW, TopCostIncrease: topIncrease,
		SLOBreaches: sloBreaches,
	}), nil
}

// k8sReportScheduler periodically delivers the operations digest for due schedules to Mattermost.
func (s *Server) k8sReportScheduler() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		schedules, err := s.db.ListK8sReportSchedules(ctx, true)
		if err != nil {
			cancel()
			continue
		}
		now := time.Now().UTC()
		for _, sc := range schedules {
			if !k8sReportDue(sc, now) {
				continue
			}
			s.deliverK8sReport(ctx, sc)
		}
		cancel()
	}
}

// k8sReportDue reports whether a schedule's interval has elapsed since its last delivery.
func k8sReportDue(sc store.K8sReportSchedule, now time.Time) bool {
	d, err := time.ParseDuration(strings.TrimSpace(sc.Interval))
	if err != nil || d <= 0 {
		return false // manual-only / invalid interval
	}
	if sc.LastRunAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339Nano, sc.LastRunAt)
	if err != nil {
		return true
	}
	return now.Sub(last) >= d
}

// deliverK8sReport builds and posts the digest, always marking the run so a failure doesn't retry
// every tick.
func (s *Server) deliverK8sReport(ctx context.Context, sc store.K8sReportSchedule) {
	_ = s.db.MarkK8sReportScheduleRun(ctx, sc.ID, time.Now().UTC().Format(time.RFC3339Nano))
	digest, err := s.buildK8sReportDigest(ctx, sc.ClusterID)
	if err != nil {
		slog.Warn("k8s report digest failed", "schedule", sc.ID, "error", err)
		return
	}
	s.notifyMattermostTo(ctx, "k8s_failure", sc.Channel, digest)
}

// handleK8sReportSchedules lists/creates report delivery schedules. GET/POST /admin/k8s/report-schedules
func (s *Server) handleK8sReportSchedules(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListK8sReportSchedules(r.Context(), false)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_report_schedules_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schedules": rows})
	case http.MethodPost:
		var in struct {
			ClusterID string `json:"cluster_id"`
			Channel   string `json:"channel"`
			Interval  string `json:"interval"`
			Enabled   *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.Interval) != "" {
			if d, err := time.ParseDuration(strings.TrimSpace(in.Interval)); err != nil || d <= 0 {
				writeOpenAIError(w, http.StatusBadRequest, "interval must be a positive duration (예: 24h)", "invalid_request_error", "invalid_interval")
				return
			}
		}
		enabled := true
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		sc := &store.K8sReportSchedule{
			ID: newID("k8srepsched"), ClusterID: strings.TrimSpace(in.ClusterID),
			Channel: strings.TrimSpace(in.Channel), Interval: strings.TrimSpace(in.Interval), Enabled: enabled,
		}
		if err := s.db.UpsertK8sReportSchedule(r.Context(), sc); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_report_schedule_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.report_schedule.upsert", "", auditJSON(sc))
		writeJSON(w, http.StatusCreated, map[string]any{"schedule": sc})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sReportScheduleByID deletes a schedule or sends it now.
// DELETE /admin/k8s/report-schedules/{id} · POST /admin/k8s/report-schedules/{id}/send
func (s *Server) handleK8sReportScheduleByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/report-schedules/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "schedule id is required", "invalid_request_error", "missing_schedule")
		return
	}
	if len(parts) > 1 && parts[1] == "send" {
		if r.Method != http.MethodPost {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		schedules, _ := s.db.ListK8sReportSchedules(r.Context(), false)
		var target *store.K8sReportSchedule
		for i := range schedules {
			if schedules[i].ID == id {
				target = &schedules[i]
				break
			}
		}
		if target == nil {
			writeOpenAIError(w, http.StatusNotFound, "schedule not found", "invalid_request_error", "schedule_not_found")
			return
		}
		digest, err := s.buildK8sReportDigest(r.Context(), target.ClusterID)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_report_digest_failed")
			return
		}
		s.notifyMattermostTo(r.Context(), "k8s_failure", target.Channel, digest)
		_ = s.db.MarkK8sReportScheduleRun(r.Context(), id, time.Now().UTC().Format(time.RFC3339Nano))
		s.auditAdmin(r, "k8s.report_schedule.send", "", auditJSON(map[string]string{"id": id}))
		writeJSON(w, http.StatusOK, map[string]any{"sent": true, "preview": digest})
		return
	}
	if r.Method != http.MethodDelete {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if err := s.db.DeleteK8sReportSchedule(r.Context(), id); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_report_schedule_delete_failed")
		return
	}
	s.auditAdmin(r, "k8s.report_schedule.delete", "", auditJSON(map[string]string{"id": id}))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
