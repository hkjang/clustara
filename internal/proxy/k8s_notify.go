package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// requestBaseURL reconstructs the public base URL from the incoming request for deep links.
func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// inQuietHours reports whether t (local hour) falls in a quiet window "HH-HH" (e.g. "22-08").
// Empty/invalid spec means never quiet. Supports windows that wrap past midnight (NOTI-03).
func inQuietHours(spec string, hour int) bool {
	parts := strings.SplitN(strings.TrimSpace(spec), "-", 2)
	if len(parts) != 2 {
		return false
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return false
	}
	if start == end {
		return false
	}
	if start < end {
		return hour >= start && hour < end
	}
	// wraps midnight, e.g. 22-08
	return hour >= start || hour < end
}

// resolveTeamChannel maps a team to a Mattermost channel via the configured JSON map; returns
// "" when no mapping exists (caller falls back to the default channel) (NOTI-04).
func resolveTeamChannel(teamChannelsJSON, team string) string {
	if strings.TrimSpace(teamChannelsJSON) == "" || team == "" {
		return ""
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(teamChannelsJSON), &m); err != nil {
		return ""
	}
	return m[team]
}

// k8sDeepLink builds an admin SPA deep link to the change timeline of a resource (NOTI-08).
func k8sDeepLink(base, clusterID, namespace, kind, name string) string {
	q := url.Values{}
	q.Set("cluster_id", clusterID)
	q.Set("namespace", namespace)
	q.Set("name", name)
	q.Set("kind", kind)
	return strings.TrimRight(base, "/") + "/admin#/k8s-timeline?" + q.Encode()
}

// handleK8sNotifyScan evaluates current high/critical RCA candidates and security findings for a
// cluster and posts deduplicated, owner-routed, quiet-hours-aware notifications (NOTI-01~08).
// POST /admin/k8s/notify/scan?cluster_id=
func (s *Server) handleK8sNotifyScan(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 2000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 500)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Limit: 1000})

	now := time.Now()
	quiet := s.flagValue(r.Context(), "k8s_quiet_hours")
	teamChannels := s.flagValue(r.Context(), "mattermost_team_channels")
	if inQuietHours(quiet, now.Hour()) {
		writeJSON(w, http.StatusOK, map[string]any{"sent": 0, "suppressed": "quiet_hours", "quiet_hours": quiet})
		return
	}

	rca := analyzer.AnalyzeRCA(items, events)
	rca = analyzer.EnrichWithConfigChanges(rca, revisions, now.UTC(), 24*time.Hour)
	sec := analyzer.AnalyzeSecurity(items)

	sent := 0
	notify := func(category, dedupKey, ns, kind, name, text string) {
		ok, derr := s.db.ShouldSendK8sNotification(r.Context(), clusterID+"|"+dedupKey, now, 6*time.Hour)
		if derr != nil || !ok {
			return // NOTI-02 dedup
		}
		channel := ""
		if ns != "" {
			if owner, oerr := s.db.GetK8sNamespaceOwner(r.Context(), clusterID, ns); oerr == nil {
				channel = resolveTeamChannel(teamChannels, owner.Team) // NOTI-04
			}
		}
		link := k8sDeepLink(requestBaseURL(r), clusterID, ns, kind, name)
		s.notifyMattermostTo(r.Context(), category, channel, text+"\n"+link)
		sent++
	}

	for _, c := range rca {
		if c.Severity != "high" && c.Severity != "critical" {
			continue
		}
		notify("k8s_failure", "rca/"+c.Namespace+"/"+c.ResourceKind+"/"+c.ResourceName+"/"+c.Condition,
			c.Namespace, c.ResourceKind, c.ResourceName,
			"장애 후보["+c.Severity+"] "+c.Condition+" — "+c.Namespace+"/"+c.ResourceKind+"/"+c.ResourceName+"\n"+c.Cause)
	}
	for _, f := range sec.RBAC {
		if f.Severity != "critical" && f.Severity != "high" {
			continue
		}
		notify("k8s_security", "rbac/"+f.Namespace+"/"+f.ResourceName+"/"+f.Rule,
			f.Namespace, f.ResourceKind, f.ResourceName,
			"보안["+f.Severity+"] "+f.Rule+" — "+f.ResourceKind+"/"+f.ResourceName+"\n"+f.Message)
	}
	for _, p := range sec.PodSecurity {
		if p.Level != "privileged" {
			continue
		}
		notify("k8s_security", "podsec/"+p.Namespace+"/"+p.Name,
			p.Namespace, p.Kind, p.Name,
			"보안[high] Privileged 워크로드 — "+p.Namespace+"/"+p.Kind+"/"+p.Name+"\n"+strings.Join(p.Violations, ", "))
	}
	s.auditAdmin(r, "k8s.notify.scan", "", auditJSON(map[string]any{"cluster_id": clusterID, "sent": sent}))
	writeJSON(w, http.StatusOK, map[string]any{"sent": sent, "evaluated_rca": len(rca), "evaluated_security": len(sec.RBAC) + len(sec.PodSecurity)})
}

// handleK8sNotifyConfig reads/sets K8s-specific notification config (quiet hours + team→channel
// routing map). GET/POST /admin/k8s/notify/config
func (s *Server) handleK8sNotifyConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"quiet_hours":    s.flagValue(r.Context(), "k8s_quiet_hours"),
			"team_channels":  s.flagValue(r.Context(), "mattermost_team_channels"),
		})
	case http.MethodPost:
		var p struct {
			QuietHours   *string `json:"quiet_hours"`
			TeamChannels *string `json:"team_channels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		setFlag := func(key, val string) error {
			return s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: key, Value: val, UpdatedAt: time.Now().UTC(), UpdatedBy: adminID(r)})
		}
		if p.QuietHours != nil {
			if err := setFlag("k8s_quiet_hours", strings.TrimSpace(*p.QuietHours)); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		if p.TeamChannels != nil {
			v := strings.TrimSpace(*p.TeamChannels)
			if v != "" && !json.Valid([]byte(v)) {
				writeOpenAIError(w, http.StatusBadRequest, "team_channels must be JSON object", "invalid_request_error", "invalid_team_channels")
				return
			}
			if err := setFlag("mattermost_team_channels", v); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// flagValue is a small helper for reading a string flag (empty when unset).
func (s *Server) flagValue(ctx context.Context, name string) string {
	if f, found, err := s.db.GetFlag(ctx, name); err == nil && found {
		return f.Value
	}
	return ""
}
