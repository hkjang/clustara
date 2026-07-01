package proxy

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sRevisions returns the recorded spec revisions for a resource (or a cluster).
// GET /admin/k8s/revisions?cluster_id=&kind=&namespace=&name=&limit=
func (s *Server) handleK8sRevisions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	revs, err := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{
		ClusterID: q.Get("cluster_id"),
		Kind:      q.Get("kind"),
		Namespace: q.Get("namespace"),
		Name:      q.Get("name"),
		Limit:     intParam(q.Get("limit"), 100),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_revisions_failed")
		return
	}
	// Strip full specs from the list view to keep payloads small; the diff endpoint
	// returns the field-level detail.
	for i := range revs {
		revs[i].Spec = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revs, "count": len(revs)})
}

// handleK8sDiff returns the field-level diff between two revisions of a resource. When
// from/to are omitted it diffs the two most recent revisions for the resource.
// GET /admin/k8s/diff?cluster_id=&kind=&namespace=&name=&from=&to=
func (s *Server) handleK8sDiff(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	fromID, toID := strings.TrimSpace(q.Get("from")), strings.TrimSpace(q.Get("to"))

	var from, to store.K8sResourceRevision
	if fromID != "" && toID != "" {
		var err error
		if from, err = s.db.GetK8sRevision(r.Context(), fromID); err != nil {
			s.writeRevisionLookupError(w, err, fromID)
			return
		}
		if to, err = s.db.GetK8sRevision(r.Context(), toID); err != nil {
			s.writeRevisionLookupError(w, err, toID)
			return
		}
	} else {
		revs, err := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{
			ClusterID: q.Get("cluster_id"),
			Kind:      q.Get("kind"),
			Namespace: q.Get("namespace"),
			Name:      q.Get("name"),
			Limit:     2,
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_revisions_failed")
			return
		}
		if len(revs) < 2 {
			writeJSON(w, http.StatusOK, map[string]any{
				"diff": nil,
				"note": "비교할 이전 리비전이 없습니다. 두 번 이상 수집된 뒤 변경이 있을 때 diff가 생성됩니다.",
			})
			return
		}
		// ListK8sRevisions returns newest-first, so revs[1] is the older side.
		from, to = revs[1], revs[0]
	}

	diff := analyzer.DiffRevisions(from, to)
	maskRevisionDiff(&diff)
	writeJSON(w, http.StatusOK, map[string]any{"diff": diff})
}

func (s *Server) writeRevisionLookupError(w http.ResponseWriter, err error, id string) {
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "revision not found: "+id, "invalid_request_error", "revision_not_found")
		return
	}
	writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_revision_failed")
}

type k8sTimelineEntry struct {
	At        string `json:"at"`
	Category  string `json:"category"` // revision | event | action | manifest_change
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Severity  string `json:"severity"` // info | warning | critical
	Ref       string `json:"ref"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// handleK8sTimeline merges revisions, events and action requests into one time-ordered
// stream so a change can be correlated with the failure around it.
// GET /admin/k8s/timeline?cluster_id=&namespace=&name=&limit=
func (s *Server) handleK8sTimeline(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	clusterID := q.Get("cluster_id")
	ns := strings.TrimSpace(q.Get("namespace"))
	name := strings.TrimSpace(q.Get("name"))
	limit := intParam(q.Get("limit"), 100)

	entries := []k8sTimelineEntry{}

	revs, err := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{
		ClusterID: clusterID, Namespace: ns, Name: name, Limit: limit,
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_revisions_failed")
		return
	}
	for _, rev := range revs {
		detail := "spec 변경"
		if rev.ImageSet != "" {
			detail = "image: " + rev.ImageSet
		}
		if rev.Replica > 0 {
			detail += " · replicas: " + itoa(rev.Replica)
		}
		entries = append(entries, k8sTimelineEntry{
			At: rev.ObservedAt, Category: "revision", Title: revisionTitle(rev.ChangeKind),
			Detail: detail, Severity: "info", Ref: rev.ID,
			Kind: rev.Kind, Namespace: rev.Namespace, Name: rev.Name,
		})
	}

	events, err := s.db.ListK8sEvents(r.Context(), clusterID, 500)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_events_failed")
		return
	}
	for _, e := range events {
		if !matchesResource(ns, name, e.Namespace, e.InvolvedName, e.Message) {
			continue
		}
		sev := "info"
		if strings.EqualFold(e.Type, "Warning") {
			sev = "warning"
		}
		entries = append(entries, k8sTimelineEntry{
			At: firstNonEmpty(e.LastSeen, e.FirstSeen, e.CreatedAt), Category: "event",
			Title: firstNonEmpty(e.Reason, e.Type), Detail: e.Message, Severity: sev,
			Ref: e.ID, Kind: e.InvolvedKind, Namespace: e.Namespace, Name: e.InvolvedName,
		})
	}

	actions, err := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: clusterID, Limit: 200})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_actions_failed")
		return
	}
	for _, a := range actions {
		if !matchesResource(ns, name, a.Namespace, a.ResourceName, "") {
			continue
		}
		entries = append(entries, k8sTimelineEntry{
			At: a.CreatedAt, Category: "action", Title: a.Action,
			Detail: a.Status + " · " + a.Result, Severity: actionSeverity(a.RiskLevel),
			Ref: a.ID, Kind: a.ResourceKind, Namespace: a.Namespace, Name: a.ResourceName,
		})
	}

	manifestChanges, err := s.db.ListK8sManifestChangeRequests(r.Context(), store.K8sManifestChangeFilter{
		ClusterID: clusterID, Namespace: ns, Kind: q.Get("kind"), Limit: 200,
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_changes_failed")
		return
	}
	for _, cr := range manifestChanges {
		if !matchesResource(ns, name, cr.Namespace, cr.Name, "") {
			continue
		}
		entries = append(entries, k8sTimelineEntry{
			At: cr.UpdatedAt, Category: "manifest_change", Title: "YAML 변경 " + cr.Status,
			Detail:   cr.RiskLevel + " · fields " + itoa(len(cr.Diffs)) + " · " + firstNonEmpty(cr.Reason, cr.Result),
			Severity: actionSeverity(cr.RiskLevel), Ref: cr.ID, Kind: cr.Kind, Namespace: cr.Namespace, Name: cr.Name,
		})
	}

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At > entries[j].At })
	if len(entries) > limit {
		entries = entries[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

func revisionTitle(changeKind string) string {
	if changeKind == "created" {
		return "리소스 최초 관측"
	}
	return "spec 변경 감지"
}

func actionSeverity(risk string) string {
	switch strings.ToLower(risk) {
	case "critical", "high":
		return "critical"
	case "medium":
		return "warning"
	}
	return "info"
}

// matchesResource keeps timeline filtering forgiving: when name is empty we match the whole
// namespace; otherwise we match an exact name or a name mentioned in the event message.
func matchesResource(filterNS, filterName, itemNS, itemName, message string) bool {
	if filterNS != "" && itemNS != "" && filterNS != itemNS {
		return false
	}
	if filterName == "" {
		return true
	}
	if itemName == filterName {
		return true
	}
	return message != "" && strings.Contains(message, filterName)
}

// maskRevisionDiff hides likely-sensitive values (secrets, tokens, passwords, env values)
// from the diff output so a config change never leaks a credential. Full manifest masking
// is handled separately by the Manifest Viewer (K8S-20).
func maskRevisionDiff(diff *analyzer.RevisionDiff) {
	for i := range diff.Changes {
		c := &diff.Changes[i]
		if c.Highlight == "env" || isSensitivePath(c.Path) {
			if strings.TrimSpace(c.Old) != "" {
				c.Old = "***"
			}
			if strings.TrimSpace(c.New) != "" {
				c.New = "***"
			}
		}
	}
}

func isSensitivePath(path string) bool {
	p := strings.ToLower(path)
	for _, needle := range []string{"secret", "token", "password", "passwd", "apikey", "api_key", "credential", "private_key", "privatekey"} {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }
