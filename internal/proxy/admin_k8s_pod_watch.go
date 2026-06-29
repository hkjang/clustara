package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sPodWatches lists watches with their current health roll-up, or registers a new watch.
// GET/POST /admin/k8s/pod-watches
func (s *Server) handleK8sPodWatches(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		watches, err := s.db.ListK8sPodWatches(r.Context(), store.K8sPodWatchFilter{
			UserID: adminID(r), ClusterID: strings.TrimSpace(q.Get("cluster_id")), Limit: recentLimit(r),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_watches_failed")
			return
		}
		// Evaluate per cluster against the current workload health.
		byCluster := map[string][]analyzer.WatchTarget{}
		clusterOrder := []string{}
		for _, wtch := range watches {
			if _, seen := byCluster[wtch.ClusterID]; !seen {
				clusterOrder = append(clusterOrder, wtch.ClusterID)
			}
			byCluster[wtch.ClusterID] = append(byCluster[wtch.ClusterID], analyzer.WatchTarget{
				ID: wtch.ID, ClusterID: wtch.ClusterID, Namespace: wtch.Namespace,
				OwnerKind: wtch.OwnerKind, OwnerName: wtch.OwnerName, Note: wtch.Note,
			})
		}
		statuses := []analyzer.WatchStatus{}
		for _, clusterID := range clusterOrder {
			wls := s.workloadGroupsForCluster(r.Context(), clusterID)
			statuses = append(statuses, analyzer.EvaluateWatchTargets(byCluster[clusterID], wls)...)
		}
		critical := 0
		for _, st := range statuses {
			if st.Band == "critical" {
				critical++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"watches":  watches,
			"statuses": statuses,
			"summary":  map[string]int{"total": len(watches), "critical": critical},
		})
	case http.MethodPost:
		var in struct {
			ClusterID string `json:"cluster_id"`
			Namespace string `json:"namespace"`
			OwnerKind string `json:"owner_kind"`
			OwnerName string `json:"owner_name"`
			Note      string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		ns := strings.TrimSpace(in.Namespace)
		if strings.TrimSpace(in.ClusterID) == "" || ns == "" {
			writeOpenAIError(w, http.StatusBadRequest, "cluster_id and namespace are required", "invalid_request_error", "missing_target")
			return
		}
		wtch := &store.K8sPodWatch{
			ID: newID("k8swatchlist"), UserID: adminID(r), ClusterID: strings.TrimSpace(in.ClusterID), Namespace: ns,
			OwnerKind: strings.TrimSpace(in.OwnerKind), OwnerName: strings.TrimSpace(in.OwnerName), Note: strings.TrimSpace(in.Note),
		}
		if err := s.db.UpsertK8sPodWatch(r.Context(), wtch); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_watch_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.pod_watch.create", "", auditJSON(wtch))
		writeJSON(w, http.StatusCreated, map[string]any{"watch": wtch})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sPodWatchByID deletes a watch. DELETE /admin/k8s/pod-watches/{id}
func (s *Server) handleK8sPodWatchByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodDelete {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/pod-watches/"), "/")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "watch id is required", "invalid_request_error", "missing_watch")
		return
	}
	if err := s.db.DeleteK8sPodWatch(r.Context(), id, adminID(r)); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_watch_delete_failed")
		return
	}
	s.auditAdmin(r, "k8s.pod_watch.delete", "", auditJSON(map[string]string{"id": id}))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
