package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sConfigImpact reports which workloads consume a given ConfigMap/Secret and whether a
// restart is needed — the blast radius of a config/secret change (CFG-REQ-04).
// GET /admin/k8s/config-impact?cluster_id=&kind=ConfigMap|Secret&name=
func (s *Server) handleK8sConfigImpact(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	kind := strings.TrimSpace(q.Get("kind"))
	name := strings.TrimSpace(q.Get("name"))
	if name == "" || (!strings.EqualFold(kind, "ConfigMap") && !strings.EqualFold(kind, "Secret")) {
		writeOpenAIError(w, http.StatusBadRequest, "kind (ConfigMap|Secret) and name are required", "invalid_request_error", "missing_params")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: strings.TrimSpace(q.Get("cluster_id")), Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	report := analyzer.AnalyzeConfigImpact(items, kind, name)
	writeJSON(w, http.StatusOK, map[string]any{
		"impact": report,
		"note":   "env/envFrom로 주입된 워크로드는 변경 반영을 위해 재시작이 필요하고, volume 마운트는 in-place로 갱신될 수 있습니다.",
	})
}
