package proxy

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sIncidents lists incidents, or (POST /scan) evaluates current high/critical RCA and
// opens/refreshes incidents. GET/POST /admin/k8s/incidents
func (s *Server) handleK8sIncidents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		incs, err := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{
			ClusterID: q.Get("cluster_id"), Status: q.Get("status"), Limit: intParam(q.Get("limit"), 100),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_incidents_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"incidents": incs, "count": len(incs)})
	case http.MethodPost:
		s.scanK8sIncidents(w, r)
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// scanK8sIncidents builds incidents from current high/critical RCA candidates and upserts them.
// POST /admin/k8s/incidents  (or /incidents/scan)
func (s *Server) scanK8sIncidents(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Limit: 2000})
	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, time.Now().UTC(), 24*time.Hour)
	drafts := analyzer.BuildIncidents(items, rca, events)

	opened, updated := 0, 0
	for _, d := range drafts {
		_, isNew, err := s.db.UpsertK8sIncidentByKey(r.Context(), store.K8sIncident{
			DedupKey: d.Key, ClusterID: d.ClusterID, Namespace: d.Namespace, Kind: d.Kind, Name: d.Name,
			Condition: d.Condition, Severity: d.Severity, Title: d.Title, Evidence: d.Evidence,
		}, newID)
		if err != nil {
			continue
		}
		if isNew {
			opened++
		} else {
			updated++
		}
	}
	s.auditAdmin(r, "k8s.incident.scan", "", auditJSON(map[string]any{"cluster_id": clusterID, "opened": opened, "updated": updated}))
	writeJSON(w, http.StatusOK, map[string]any{"opened": opened, "updated": updated, "evaluated": len(drafts)})
}

// handleK8sIncidentByID returns an incident with related actions, or resolves it.
// GET /admin/k8s/incidents/{id}  ·  POST /admin/k8s/incidents/{id}/resolve
func (s *Server) handleK8sIncidentByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/incidents/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" || id == "scan" {
		writeOpenAIError(w, http.StatusBadRequest, "incident id required", "invalid_request_error", "missing_incident_id")
		return
	}
	if len(parts) > 1 && parts[1] == "resolve" {
		if r.Method != http.MethodPost {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		if err := s.db.ResolveK8sIncident(r.Context(), id); errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "open incident not found: "+id, "invalid_request_error", "incident_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_incident_resolve_failed")
			return
		}
		s.auditAdmin(r, "k8s.incident.resolve", "", auditJSON(map[string]string{"id": id}))
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "resolved"})
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	inc, err := s.db.GetK8sIncident(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "incident not found: "+id, "invalid_request_error", "incident_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_incident_failed")
		return
	}
	// Related action requests for the same resource (the workspace's 조치 탭).
	related := []store.K8sActionRequest{}
	if acts, aerr := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: inc.ClusterID, Limit: 200}); aerr == nil {
		for _, a := range acts {
			if a.ResourceName == inc.Name && strings.EqualFold(a.ResourceKind, inc.Kind) && (inc.Namespace == "" || a.Namespace == inc.Namespace) {
				related = append(related, a)
			}
		}
	}
	relatedEvents := []store.K8sEvent{}
	if events, eerr := s.db.ListK8sEvents(r.Context(), inc.ClusterID, 500); eerr == nil {
		for _, e := range events {
			if k8sEventMatchesIncident(inc, e) {
				relatedEvents = append(relatedEvents, e)
				if len(relatedEvents) >= 20 {
					break
				}
			}
		}
	}
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{
		ClusterID: inc.ClusterID, Kind: inc.Kind, Namespace: inc.Namespace, Name: inc.Name, Limit: 8,
	})
	relatedFindings := []store.K8sSecurityFinding{}
	if findings, ferr := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{ClusterID: inc.ClusterID, Status: "open", Limit: 500}); ferr == nil {
		for _, f := range findings {
			if k8sFindingMatchesIncident(inc, f) {
				relatedFindings = append(relatedFindings, f)
				if len(relatedFindings) >= 20 {
					break
				}
			}
		}
	}
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: inc.ClusterID, Limit: 5000})
	owners, _ := s.db.ListK8sNamespaceOwnership(r.Context(), inc.ClusterID, "")
	graph := analyzer.BuildResourceGraph(items, owners, analyzer.ResourceGraphFocus{
		ClusterID: inc.ClusterID, Kind: inc.Kind, Namespace: inc.Namespace, Name: inc.Name, Radius: 2,
	})
	confidence := analyzer.ScoreIncidentConfidence(analyzer.ConfidenceInput{
		Severity: inc.Severity, OpenedAt: inc.OpenedAt,
		Events: relatedEvents, Revisions: revisions, Findings: relatedFindings,
		EvidenceCount: len(inc.Evidence), ImpactCount: graph.Impact.NodeCount, Now: time.Now().UTC(),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"incident": inc, "actions": related, "events": relatedEvents, "revisions": revisions,
		"findings": relatedFindings, "graph": graph, "impact": graph.Impact, "confidence": confidence,
	})
}

func k8sEventMatchesIncident(inc store.K8sIncident, e store.K8sEvent) bool {
	if e.ClusterID != inc.ClusterID || e.Namespace != inc.Namespace {
		return false
	}
	if strings.EqualFold(e.InvolvedKind, inc.Kind) && e.InvolvedName == inc.Name {
		return true
	}
	if strings.EqualFold(e.InvolvedKind, "Pod") && inc.Kind != "Pod" {
		return strings.HasPrefix(e.InvolvedName, inc.Name+"-")
	}
	return false
}

func k8sFindingMatchesIncident(inc store.K8sIncident, f store.K8sSecurityFinding) bool {
	return f.ClusterID == inc.ClusterID &&
		f.Namespace == inc.Namespace &&
		strings.EqualFold(f.ResourceKind, inc.Kind) &&
		f.ResourceName == inc.Name
}
