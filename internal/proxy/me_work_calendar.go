package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

type personalCalendarEvent struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Lane        string   `json:"lane"`
	Status      string   `json:"status"`
	RiskLevel   string   `json:"risk_level"`
	Title       string   `json:"title"`
	Target      string   `json:"target"`
	ClusterID   string   `json:"cluster_id"`
	Namespace   string   `json:"namespace"`
	Date        string   `json:"date"`
	StartedAt   string   `json:"started_at"`
	UpdatedAt   string   `json:"updated_at"`
	Href        string   `json:"href"`
	Roles       []string `json:"roles"`
	ActorHint   string   `json:"actor_hint"`
	SLAStatus   string   `json:"sla_status"`
	SLAReason   string   `json:"sla_reason"`
	Description string   `json:"description"`
}

// handleMeWorkCalendar returns calendar-ready work items related to the caller: requests
// they created, approvals/executions they handled, and role-matched operational work.
// GET /me/work-calendar?window_days=60&limit=300
func (s *Server) handleMeWorkCalendar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	userID, ok := s.meUserID(r)
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "could not identify caller", "invalid_request_error", "invalid_api_key")
		return
	}
	role := "user"
	if claims, ok := s.currentAccessClaims(r); ok {
		role = strings.TrimSpace(claims.Role)
	} else if me, ok := s.meKeyContext(r); ok && strings.TrimSpace(me.Role) != "" {
		role = strings.TrimSpace(me.Role)
	}
	limit := intQuery(r, "limit", 300)
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	windowDays := intQuery(r, "window_days", 60)
	if windowDays <= 0 || windowDays > 365 {
		windowDays = 60
	}
	since := time.Now().UTC().Add(-time.Duration(windowDays) * 24 * time.Hour)
	aliases := s.personalActorAliases(r, userID)

	events := []personalCalendarEvent{}
	add := func(item k8sActionFlowItem, roles []string) {
		item = annotateActionFlowSLA(item, time.Now().UTC())
		item = annotateActionFlowActor(item)
		if len(roles) == 0 && personalCalendarRoleMatches(item.ActorHint, role) {
			roles = []string{"role:" + role}
		}
		if len(roles) == 0 {
			return
		}
		t, ok := personalCalendarItemTime(item)
		if !ok || t.Before(since) {
			return
		}
		events = append(events, personalCalendarEvent{
			ID: item.ID, Kind: item.Kind, Lane: item.Lane, Status: item.Status, RiskLevel: item.RiskLevel,
			Title: item.Title, Target: item.Target, ClusterID: item.ClusterID, Namespace: item.Namespace,
			Date: t.Format("2006-01-02"), StartedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
			Href: item.Href, Roles: roles, ActorHint: item.ActorHint, SLAStatus: item.SLAStatus,
			SLAReason: item.SLAReason, Description: firstNonEmpty(item.Detail, item.NextAction),
		})
	}

	actions, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{Limit: limit})
	for _, a := range actions {
		add(flowItemFromAction(a), personalCalendarActorRoles(aliases, map[string]string{
			"requested": a.RequestedBy, "approved": a.ApprovedBy, "executed": a.ExecutedBy,
		}))
	}
	configs, _ := s.db.ListK8sConfigChangeRequests(r.Context(), store.K8sConfigChangeFilter{Limit: limit})
	for _, c := range configs {
		add(flowItemFromConfigChange(c), personalCalendarActorRoles(aliases, map[string]string{
			"requested": c.RequestedBy, "approved": c.ApprovedBy, "applied": c.AppliedBy, "verified": c.VerifiedBy,
		}))
	}
	manifests, _ := s.db.ListK8sManifestChangeRequests(r.Context(), store.K8sManifestChangeFilter{Limit: limit})
	for _, m := range manifests {
		add(flowItemFromManifestChange(m), personalCalendarActorRoles(aliases, map[string]string{
			"created": m.CreatedBy, "approved": m.ApprovedBy, "applied": m.AppliedBy, "verified": m.VerifiedBy,
		}))
	}
	execs, _ := s.db.ListK8sPodExecSessions(r.Context(), store.K8sPodExecSessionFilter{Limit: limit})
	for _, e := range execs {
		add(flowItemFromExecSession(e), personalCalendarActorRoles(aliases, map[string]string{
			"requested": e.RequestedBy, "decided": e.DecidedBy, "executed": e.ExecutedBy,
		}))
	}
	debugs, _ := s.db.ListK8sDebugSessions(r.Context(), store.K8sDebugSessionFilter{Limit: limit})
	for _, d := range debugs {
		add(flowItemFromDebugSession(d), personalCalendarActorRoles(aliases, map[string]string{
			"requested": d.RequestedBy, "approved": d.ApprovedBy,
		}))
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
		"user_id":      userID,
		"role":         role,
		"window_days":  windowDays,
		"events":       events,
		"summary":      personalCalendarSummary(events),
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) personalActorAliases(r *http.Request, userID string) map[string]bool {
	out := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" {
			out[strings.ToLower(v)] = true
		}
	}
	add(userID)
	add(adminID(r))
	if claims, ok := s.currentAccessClaims(r); ok {
		add(claims.Subject)
		add(claims.Email)
	}
	if _, authCtx, ok := s.authenticateProxyContext(r); ok && authCtx != nil {
		add(authCtx.UserID)
		add(authCtx.APIKeyID)
	}
	return out
}

func personalCalendarActorRoles(aliases map[string]bool, fields map[string]string) []string {
	roles := []string{}
	seen := map[string]bool{}
	for role, actor := range fields {
		if aliases[strings.ToLower(strings.TrimSpace(actor))] && !seen[role] {
			seen[role] = true
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	return roles
}

func personalCalendarRoleMatches(actorHint, role string) bool {
	hint := strings.ToLower(strings.TrimSpace(actorHint))
	role = strings.ToLower(strings.TrimSpace(role))
	if hint == "" || role == "" {
		return false
	}
	switch {
	case role == "super_admin" || role == "admin":
		return strings.Contains(hint, "admin") || strings.Contains(hint, "operator") || strings.Contains(hint, "approver") || strings.Contains(hint, "security")
	case role == "ops_admin" || role == "operator":
		return strings.Contains(hint, "operator") || strings.Contains(hint, "admin")
	case role == "approver":
		return strings.Contains(hint, "approver") || strings.Contains(hint, "security") || strings.Contains(hint, "admin")
	case strings.Contains(role, "security"):
		return strings.Contains(hint, "security") || strings.Contains(hint, "admin")
	case role == "developer" || role == "viewer":
		return strings.Contains(hint, "requester")
	default:
		return strings.Contains(hint, role)
	}
}

func personalCalendarItemTime(item k8sActionFlowItem) (time.Time, bool) {
	for _, raw := range []string{item.UpdatedAt, item.CreatedAt} {
		if t, ok := parseActionFlowTime(raw); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

func personalCalendarSummary(events []personalCalendarEvent) map[string]int {
	out := map[string]int{"total": len(events), "attention": 0, "approval": 0, "ready": 0, "verify": 0, "done": 0, "sla": 0}
	for _, ev := range events {
		if _, ok := out[ev.Lane]; ok {
			out[ev.Lane]++
		}
		if ev.SLAStatus == "warning" || ev.SLAStatus == "breached" {
			out["sla"]++
		}
	}
	return out
}
