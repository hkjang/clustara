package proxy

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

type adminCalendarEvent struct {
	personalCalendarEvent
	Actors     map[string]string `json:"actors"`
	ActorNames map[string]string `json:"actor_names"`
}

type adminCalendarActorOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type adminCalendarTimelineEvent struct {
	ID          string `json:"id"`
	At          string `json:"at"`
	Date        string `json:"date"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	ClusterID   string `json:"cluster_id"`
	Namespace   string `json:"namespace"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	ImageSet    string `json:"image_set,omitempty"`
	Previous    string `json:"previous_image_set,omitempty"`
	Href        string `json:"href"`
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
	actorDirectory := s.adminCalendarActorDirectory(r)
	options := map[string]map[string]bool{"clusters": {}, "namespaces": {}, "kinds": {}, "actors": {}}
	add := func(item k8sActionFlowItem, actors map[string]string) {
		item = annotateActionFlowSLA(item, time.Now().UTC())
		item = annotateActionFlowActor(item)
		t, ok := personalCalendarItemTime(item)
		if !ok || t.Before(since) {
			return
		}
		cleanActors := map[string]string{}
		actorNames := map[string]string{}
		for role, actor := range actors {
			actor = strings.TrimSpace(actor)
			if actor != "" {
				cleanActors[role] = actor
				actorNames[role] = adminCalendarActorName(actor, actorDirectory)
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
		}, Actors: cleanActors, ActorNames: actorNames}
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
	timelineEvents := s.adminWorkCalendarTimeline(r, since, filters, limit)

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
	optionPayload := adminCalendarOptions(options)
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events, "summary": personalCalendarSummary(adminPersonalEvents(events)),
		"timeline_events": timelineEvents, "timeline_summary": adminCalendarTimelineSummary(timelineEvents),
		"options": optionPayload, "actor_options": adminCalendarActorOptions(options["actors"], actorDirectory),
		"filters": filters, "window_days": windowDays,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) adminWorkCalendarTimeline(r *http.Request, since time.Time, filters map[string]string, limit int) []adminCalendarTimelineEvent {
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: filters["cluster_id"], Namespace: filters["namespace"], Limit: limit})
	result := make([]adminCalendarTimelineEvent, 0, len(revisions))
	previousImage := map[string]string{}
	// Revisions are newest-first. Walk backwards first so image transitions retain the prior image.
	for i := len(revisions) - 1; i >= 0; i-- {
		rev := revisions[i]
		at, err := time.Parse(time.RFC3339Nano, firstNonEmpty(rev.ObservedAt, rev.CreatedAt))
		if err != nil || !adminTimelineDimensionMatches(rev.ClusterID, rev.Namespace, rev.Kind, rev.Name, filters) {
			continue
		}
		key := strings.Join([]string{rev.ClusterID, rev.Namespace, rev.Kind, rev.Name}, "|")
		oldImage := previousImage[key]
		created := strings.EqualFold(rev.ChangeKind, "created")
		imageChanged := rev.ImageSet != "" && oldImage != "" && rev.ImageSet != oldImage
		previousImage[key] = rev.ImageSet
		if at.Before(since) || (!created && !imageChanged) {
			continue
		}
		title, category, detail := rev.Kind+" 새로 생성", "resource_created", rev.Name+"이(가) 새로 관측됨"
		if imageChanged {
			title, category = rev.Kind+" 이미지 버전 변경", "image_changed"
			detail = oldImage + " → " + rev.ImageSet
		} else if rev.ImageSet != "" {
			detail += " · 이미지 " + rev.ImageSet
		}
		result = append(result, adminCalendarTimelineEvent{ID: rev.ID, At: at.Format(time.RFC3339Nano), Date: at.Format("2006-01-02"), Category: category, Severity: "info", Title: title, Description: detail, ClusterID: rev.ClusterID, Namespace: rev.Namespace, Kind: rev.Kind, Name: rev.Name, ImageSet: rev.ImageSet, Previous: oldImage, Href: adminCalendarTimelineHref(rev.ClusterID, rev.Namespace, rev.Kind, rev.Name)})
	}
	events, _ := s.db.ListK8sEvents(r.Context(), filters["cluster_id"], limit)
	for _, event := range events {
		at, err := time.Parse(time.RFC3339Nano, firstNonEmpty(event.LastSeen, event.FirstSeen, event.CreatedAt))
		if err != nil || at.Before(since) || !adminTimelineDimensionMatches(event.ClusterID, event.Namespace, event.InvolvedKind, event.InvolvedName, filters) || !adminCalendarMajorK8sEvent(event) {
			continue
		}
		severity := "warning"
		if !strings.EqualFold(event.Type, "Warning") {
			severity = "info"
		}
		result = append(result, adminCalendarTimelineEvent{ID: event.ID, At: at.Format(time.RFC3339Nano), Date: at.Format("2006-01-02"), Category: "k8s_event", Severity: severity, Title: event.Reason, Description: event.Message, ClusterID: event.ClusterID, Namespace: event.Namespace, Kind: event.InvolvedKind, Name: event.InvolvedName, Href: adminCalendarTimelineHref(event.ClusterID, event.Namespace, event.InvolvedKind, event.InvolvedName)})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].At > result[j].At })
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func adminTimelineDimensionMatches(clusterID, namespace, kind, name string, filters map[string]string) bool {
	if filters["cluster_id"] != "" && clusterID != filters["cluster_id"] {
		return false
	}
	if filters["namespace"] != "" && namespace != filters["namespace"] {
		return false
	}
	if filters["kind"] != "" && !strings.EqualFold(kind, filters["kind"]) {
		return false
	}
	q := filters["q"]
	return q == "" || strings.Contains(strings.ToLower(strings.Join([]string{clusterID, namespace, kind, name}, " ")), q)
}

func adminCalendarMajorK8sEvent(event store.K8sEvent) bool {
	if strings.EqualFold(event.Type, "Warning") {
		return true
	}
	reason := strings.ToLower(event.Reason)
	for _, signal := range []string{"scalingreplicaset", "successfulcreate", "killing", "evicted", "backoff", "deadlineexceeded"} {
		if strings.Contains(reason, signal) {
			return true
		}
	}
	return false
}

func adminCalendarTimelineHref(clusterID, namespace, kind, name string) string {
	return "#/k8s-timeline?cluster_id=" + url.QueryEscape(clusterID) + "&namespace=" + url.QueryEscape(namespace) + "&kind=" + url.QueryEscape(kind) + "&name=" + url.QueryEscape(name)
}

func adminCalendarTimelineSummary(events []adminCalendarTimelineEvent) map[string]int {
	out := map[string]int{"total": len(events)}
	for _, event := range events {
		out[event.Category]++
		if event.Severity == "warning" {
			out["warning"]++
		}
	}
	return out
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
		actorText += " " + role + " " + actor + " " + ev.ActorNames[role]
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

func adminCalendarOptions(raw map[string]map[string]bool) map[string]any {
	out := map[string]any{}
	for key, values := range raw {
		rows := []string{}
		for value := range values {
			rows = append(rows, value)
		}
		sort.Strings(rows)
		out[key] = rows
	}
	return out
}

func (s *Server) adminCalendarActorDirectory(r *http.Request) map[string]string {
	out := map[string]string{}
	claims, hasClaims := s.currentAccessClaims(r)
	add := func(id, name string) {
		id, name = strings.TrimSpace(id), strings.TrimSpace(name)
		if id != "" && name != "" {
			out[strings.ToLower(id)] = name
		}
	}
	if users, err := s.db.ListAuthUsers(r.Context()); err == nil {
		for _, user := range users {
			if hasClaims && claims.Role == "team_admin" {
				teamID, _ := s.db.PrimaryTeamForUser(r.Context(), user.ID)
				if teamID != claims.TeamID {
					continue
				}
			}
			name := firstNonEmpty(user.Name, user.Email)
			add(user.ID, name)
			add(user.Email, name)
		}
	}
	if users, err := s.db.ListUsers(r.Context()); err == nil {
		for _, user := range users {
			if hasClaims && claims.Role == "team_admin" && user.Team != claims.TeamID {
				continue
			}
			add(user.APIKeyID, firstNonEmpty(user.Name, user.Owner))
		}
	}
	if hasClaims {
		name := firstNonEmpty(out[strings.ToLower(claims.Subject)], claims.Email, claims.Subject)
		add(adminID(r), name)
		add(claims.Subject, name)
		add(claims.Email, name)
	}
	return out
}

func adminCalendarActorName(actor string, directory map[string]string) string {
	actor = strings.TrimSpace(actor)
	if name := strings.TrimSpace(directory[strings.ToLower(actor)]); name != "" {
		return name
	}
	switch {
	case actor == "anonymous" || actor == "system":
		return "시스템"
	case strings.HasPrefix(strings.ToLower(actor), "admin_"):
		return "관리자"
	default:
		return actor
	}
}

func adminCalendarActorOptions(ids map[string]bool, directory map[string]string) []adminCalendarActorOption {
	out := make([]adminCalendarActorOption, 0, len(ids))
	for id := range ids {
		out = append(out, adminCalendarActorOption{Value: id, Label: adminCalendarActorName(id, directory)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		return out[i].Value < out[j].Value
	})
	return out
}
