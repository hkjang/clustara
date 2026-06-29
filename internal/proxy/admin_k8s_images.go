package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sImages reports image→workload usage across the inventory + supply-chain risk flags
// (mutable :latest, no pinned digest). Read-only, no registry credentials. GET /admin/k8s/images
func (s *Server) handleK8sImages(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	images := analyzer.AnalyzeImageUsage(items)
	mutable, pinned := 0, 0
	for _, im := range images {
		if im.Latest {
			mutable++
		}
		if im.Pinned {
			pinned++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"images": images,
		"summary": map[string]int{"total": len(images), "mutable_tag": mutable, "digest_pinned": pinned},
		"note":    "mutable=:latest/untagged(가변 위험), digest_pinned=@sha256(불변). 레지스트리 자격증명 없이 인벤토리 기반으로 산출합니다.",
	})
}
