package proxy

import (
	"net/http"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

type rbacDiffEntry struct {
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	FromAt    string   `json:"from_observed_at"`
	ToAt      string   `json:"to_observed_at"`
	Added     []string `json:"added"`
	Risky     []string `json:"risky"`
}

// handleK8sRBACDiff reports Role/ClusterRole permission expansions between the two most recent
// revisions of each RBAC object (SEC-08 RBAC Diff). Reuses the PR1 revision history.
// GET /admin/k8s/rbac-diff?cluster_id=
func (s *Server) handleK8sRBACDiff(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	entries := []rbacDiffEntry{}
	for _, it := range items {
		if it.Kind != "Role" && it.Kind != "ClusterRole" {
			continue
		}
		revs, err := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{
			ClusterID: it.ClusterID, Kind: it.Kind, Namespace: it.Namespace, Name: it.Name, Limit: 2,
		})
		if err != nil || len(revs) < 2 {
			continue
		}
		added := analyzer.RBACDiffExpansions(revs[1], revs[0])
		if len(added) == 0 {
			continue
		}
		risky := []string{}
		for _, a := range added {
			if analyzer.IsRiskyPermission(a) {
				risky = append(risky, a)
			}
		}
		entries = append(entries, rbacDiffEntry{
			Namespace: it.Namespace, Kind: it.Kind, Name: it.Name,
			FromAt: revs[1].ObservedAt, ToAt: revs[0].ObservedAt, Added: added, Risky: risky,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"count":   len(entries),
		"note":    "최근 2개 리비전 기준으로 Role/ClusterRole에 추가된 권한입니다. risky는 wildcard·secret·권한상승 verb 추가입니다.",
	})
}
