package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Image Stream Ledger (CLU-OCP-04).
//
// Builds a digest ledger over running Pods: which image each workload runs, mutable-tag risk, and
// tag drift (same repo:tag resolved to different digests across the cluster).

// handleK8sImageLedger serves the image ledger for a cluster.
// GET /admin/k8s/image-ledger?cluster_id=&namespace=
func (s *Server) handleK8sImageLedger(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required", "invalid_request_error", "missing_cluster_id")
		return
	}
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Pod", Namespace: namespace, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	report := analyzer.BuildImageLedger(items)
	writeJSON(w, http.StatusOK, map[string]any{
		"ledger": report,
		"note":   "실행 중인 워크로드의 이미지 digest 원장입니다(OpenShift ImageStream 스타일). mutable 태그(latest/digest 미고정)와 tag drift(같은 repo:tag가 서로 다른 digest로 해석)를 표시합니다.",
	})
}
