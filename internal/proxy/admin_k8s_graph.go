package proxy

import (
	"net/http"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sResourceGraph returns the current relationship graph derived from inventory.
// GET /admin/k8s/resource-graph?cluster_id=&kind=&namespace=&name=&radius=2
func (s *Server) handleK8sResourceGraph(w http.ResponseWriter, r *http.Request) {
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
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: intParam(q.Get("limit"), 5000)})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	owners, _ := s.db.ListK8sNamespaceOwnership(r.Context(), clusterID, "")
	graph := analyzer.BuildResourceGraph(items, owners, analyzer.ResourceGraphFocus{
		ClusterID: clusterID,
		Kind:      q.Get("kind"),
		Namespace: q.Get("namespace"),
		Name:      q.Get("name"),
		Radius:    intParam(q.Get("radius"), 2),
	})
	writeJSON(w, http.StatusOK, map[string]any{"graph": graph})
}
