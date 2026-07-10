package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"clustara/internal/store"
)

// handleK8sGroups lists cluster groups with a per-group cluster roll-up, and creates/updates
// a group (K8S-16). GET /admin/k8s/groups ; POST /admin/k8s/groups
func (s *Server) handleK8sGroups(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		groups, err := s.db.ListK8sClusterGroups(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_groups_failed")
			return
		}
		clusters, err := s.db.ListK8sClusters(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_clusters_failed")
			return
		}
		type roll struct {
			Group   store.K8sClusterGroup `json:"group"`
			Total   int                   `json:"total"`
			Ready   int                   `json:"ready"`
			Risky   int                   `json:"risky"`
			Members []string              `json:"members"`
		}
		byID := map[string]*roll{}
		for _, g := range groups {
			byID[g.ID] = &roll{Group: g, Members: []string{}}
		}
		ungrouped := &roll{Group: store.K8sClusterGroup{ID: "", Name: "(미분류)"}, Members: []string{}}
		for _, c := range clusters {
			r := byID[c.GroupID]
			if r == nil {
				r = ungrouped
			}
			r.Total++
			r.Members = append(r.Members, c.Name)
			switch c.Status {
			case "ready", "connected":
				r.Ready++
			case "error":
				r.Risky++
			}
		}
		out := []roll{}
		for _, g := range groups {
			out = append(out, *byID[g.ID])
		}
		if ungrouped.Total > 0 {
			out = append(out, *ungrouped)
		}
		writeJSON(w, http.StatusOK, map[string]any{"groups": out})
	case http.MethodPost:
		var g store.K8sClusterGroup
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(g.Name) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name is required", "invalid_request_error", "missing_fields")
			return
		}
		if strings.TrimSpace(g.ID) == "" {
			g.ID = newID("k8sgrp")
		}
		if err := s.db.UpsertK8sClusterGroup(r.Context(), g); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_group_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.group.upsert", "", auditJSON(g))
		writeJSON(w, http.StatusCreated, map[string]any{"group": g})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sGroupByID reads/updates/deletes a group. GET/POST/DELETE /admin/k8s/groups/{id}
func (s *Server) handleK8sGroupByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/groups/"), "/")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "group id required", "invalid_request_error", "missing_group_id")
		return
	}
	switch r.Method {
	case http.MethodGet:
		groups, err := s.db.ListK8sClusterGroups(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_groups_failed")
			return
		}
		for _, g := range groups {
			if g.ID == id {
				writeJSON(w, http.StatusOK, map[string]any{"group": g})
				return
			}
		}
		writeOpenAIError(w, http.StatusNotFound, "group not found: "+id, "invalid_request_error", "k8s_group_not_found")
	case http.MethodPost:
		var g store.K8sClusterGroup
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		g.ID = id
		if strings.TrimSpace(g.Name) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name is required", "invalid_request_error", "missing_fields")
			return
		}
		if err := s.db.UpsertK8sClusterGroup(r.Context(), g); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_group_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.group.update", id, auditJSON(g))
		writeJSON(w, http.StatusOK, map[string]any{"group": g})
	case http.MethodDelete:
		if err := s.db.DeleteK8sClusterGroup(r.Context(), id); err != nil {
			status := http.StatusInternalServerError
			code := "k8s_group_delete_failed"
			errType := "server_error"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "k8s_group_not_found"
				errType = "invalid_request_error"
			}
			writeOpenAIError(w, status, err.Error(), errType, code)
			return
		}
		s.auditAdmin(r, "k8s.group.delete", "", auditJSON(map[string]string{"id": id}))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sOwnership lists/sets namespace ownership (K8S-17). GET/POST /admin/k8s/ownership
func (s *Server) handleK8sOwnership(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		owners, err := s.db.ListK8sNamespaceOwnership(r.Context(), q.Get("cluster_id"), q.Get("team"))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_ownership_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ownership": owners})
	case http.MethodPost:
		var o store.K8sNamespaceOwnership
		if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(o.ClusterID) == "" || strings.TrimSpace(o.Namespace) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "cluster_id and namespace are required", "invalid_request_error", "missing_fields")
			return
		}
		if strings.TrimSpace(o.ID) == "" {
			o.ID = newID("k8sown")
		}
		if err := s.db.UpsertK8sNamespaceOwnership(r.Context(), o); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_ownership_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.ownership.upsert", "", auditJSON(o))
		writeJSON(w, http.StatusCreated, map[string]any{"ownership": o})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sOwnershipByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/ownership/"), "/"), "/")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster id and namespace are required", "invalid_request_error", "missing_ownership_target")
		return
	}
	clusterID := strings.TrimSpace(parts[0])
	namespace := strings.TrimSpace(parts[1])
	switch r.Method {
	case http.MethodDelete:
		if err := s.db.DeleteK8sNamespaceOwnership(r.Context(), clusterID, namespace); err != nil {
			status := http.StatusInternalServerError
			code := "k8s_ownership_delete_failed"
			errType := "server_error"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "k8s_ownership_not_found"
				errType = "invalid_request_error"
			}
			writeOpenAIError(w, status, err.Error(), errType, code)
			return
		}
		s.auditAdmin(r, "k8s.ownership.delete", "", auditJSON(map[string]string{"cluster_id": clusterID, "namespace": namespace}))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "cluster_id": clusterID, "namespace": namespace})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}
