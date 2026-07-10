package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

type adminCalendarEvent struct {
	personalCalendarEvent
	Actors map[string]string `json:"actors"`
}

// handleAdminWorkCalendar returns the complete operational work calendar across users.
// GET /admin/work-calendar?window_days=180&cluster_id=&namespace=&kind=&lane=&actor=&q=&limit=1000
func (s *Server) handleAdminWorkCalendar(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "admin authorization required", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	limit := intQuery(r, "limit", 1000)
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	windowDays := intQuery(r, "window_days", 180)
	if windowDays <= 0 || windowDays > 730 {
		windowDays = 180
	}
	since := time.Now().UTC().Add(-time.Duration(windowDays) * 24 * time.Hour)
	filters := map[string]string{
		"cluster_id": strings.TrimSpace(r.URL.Query().Get("cluster_id")),
		"namespace":  strings.TrimSpace(r.URL.Query().Get("namespace")),
		"kind":       strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind"))),
		"lane":       strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lane"))),
		"actor":      strings.ToLower(strings.TrimSpace(r.URL.Query().Get("actor"))),
		"q":          strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))),
	}

	events := []adminCalendarEvent{}
	options := map[string]map[string]bool{"clusters": {}, "namespaces": {}, "kinds": {}, "actors": {}}
	add := func(item k8sActionFlowItem, actors map[string]string) {
		item = annotateActionFlowSLA(item, time.Now().UTC())
		item = annotateActionFlowActor(item)
		t, ok := personalCalendarItemTime(item)
		if !ok || t.Before(since) {
			return
		}
		cleanActors := map[string]string{}
		for role, actor := range actors {
			actor = strings.TrimSpace(actor)
			if actor != "" {
				cleanActors[role] = actor
				options["actors"][actor] = true
			}
		}
		if item.ClusterID != "" {
			options["clusters"][item.ClusterID] = true
		}
		if item.Namespace != "" {
			options["namespaces"][item.Namespace] = true
		}
		options["kinds"][item.Kind] = true
		ev := adminCalendarEvent{personalCalendarEvent: personalCalendarEvent{
			ID: item.ID, Kind: item.Kind, Lane: item.Lane, Status: item.Status, RiskLevel: item.RiskLevel,
			Title: item.Title, Target: item.Target, ClusterID: item.ClusterID, Namespace: item.Namespace,
			Date: t.Format("2006-01-02"), StartedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
			Href: item.Href, ActorHint: item.ActorHint, SLAStatus: item.SLAStatus, SLAReason: item.SLAReason,
			Description: firstNonEmpty(item.Detail, item.NextAction),
		}, Actors: cleanActors}
		if !adminCalendarMatches(ev, filters) {
			return
		}
		events = append(events, ev)
	}

	actions, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{Limit: limit})
	for _, x := range actions {
		add(flowItemFromAction(x), map[string]string{"requested": x.RequestedBy, "approved": x.ApprovedBy, "executed": x.ExecutedBy})
	}
	configs, _ := s.db.ListK8sConfigChangeRequests(r.Context(), store.K8sConfigChangeFilter{Limit: limit})
	for _, x := range configs {
		add(flowItemFromConfigChange(x), map[string]string{"requested": x.RequestedBy, "approved": x.ApprovedBy, "applied": x.AppliedBy, "verified": x.VerifiedBy})
	}
	manifests, _ := s.db.ListK8sManifestChangeRequests(r.Context(), store.K8sManifestChangeFilter{Limit: limit})
	for _, x := range manifests {
		add(flowItemFromManifestChange(x), map[string]string{"created": x.CreatedBy, "approved": x.ApprovedBy, "applied": x.AppliedBy, "verified": x.VerifiedBy})
	}
	execs, _ := s.db.ListK8sPodExecSessions(r.Context(), store.K8sPodExecSessionFilter{Limit: limit})
	for _, x := range execs {
		add(flowItemFromExecSession(x), map[string]string{"requested": x.RequestedBy, "decided": x.DecidedBy, "executed": x.ExecutedBy})
	}
	debugs, _ := s.db.ListK8sDebugSessions(r.Context(), store.K8sDebugSessionFilter{Limit: limit})
	for _, x := range debugs {
		add(flowItemFromDebugSession(x), map[string]string{"requested": x.RequestedBy, "approved": x.ApprovedBy})
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Date != events[j].Date {
			return events[i].Date > events[j].Date
		}
		if lanePriority(events[i].Lane) != lanePriority(events[j].Lane) {
			return lanePriority(events[i].Lane) < lanePriority(events[j].Lane)
		}
		return events[i].Title < events[j].Title
	})
	if len(events) > limit {
		events = events[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events, "summary": personalCalendarSummary(adminPersonalEvents(events)),
		"options": adminCalendarOptions(options), "filters": filters, "window_days": windowDays,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func adminCalendarMatches(ev adminCalendarEvent, f map[string]string) bool {
	if f["cluster_id"] != "" && ev.ClusterID != f["cluster_id"] {
		return false
	}
	if f["namespace"] != "" && ev.Namespace != f["namespace"] {
		return false
	}
	if f["kind"] != "" && strings.ToLower(ev.Kind) != f["kind"] {
		return false
	}
	if f["lane"] != "" && strings.ToLower(ev.Lane) != f["lane"] {
		return false
	}
	actorText := ""
	for role, actor := range ev.Actors {
		actorText += " " + role + " " + actor
	}
	if f["actor"] != "" && !strings.Contains(strings.ToLower(actorText), f["actor"]) {
		return false
	}
	search := strings.ToLower(strings.Join([]string{ev.ID, ev.Title, ev.Target, ev.Description, ev.Status, ev.ClusterID, ev.Namespace, actorText}, " "))
	return f["q"] == "" || strings.Contains(search, f["q"])
}

func adminPersonalEvents(events []adminCalendarEvent) []personalCalendarEvent {
	out := make([]personalCalendarEvent, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.personalCalendarEvent)
	}
	return out
}

func adminCalendarOptions(raw map[string]map[string]bool) map[string][]string {
	out := map[string][]string{}
	for key, values := range raw {
		for value := range values {
			out[key] = append(out[key], value)
		}
		sort.Strings(out[key])
	}
	return out
}
