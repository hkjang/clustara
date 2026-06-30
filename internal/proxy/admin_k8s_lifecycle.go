package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Platform Lifecycle Center (CLU-OCP-08).
//
// Computes an upgrade-readiness score from kubelet version skew (Node inventory), deprecated API
// usage (the cached Discovery catalog → DetectDeprecatedAPIs), and open critical incidents.

// handleK8sLifecycle serves upgrade readiness for a cluster.
// GET /admin/k8s/lifecycle?cluster_id=
func (s *Server) handleK8sLifecycle(w http.ResponseWriter, r *http.Request) {
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
	cluster, err := s.db.GetK8sCluster(r.Context(), clusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found", "invalid_request_error", "cluster_not_found")
		return
	}

	// Node kubelet versions from Node inventory (.status.nodeInfo.kubeletVersion).
	nodes, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Node", Limit: 5000})
	kubeletVers := []string{}
	for _, n := range nodes {
		if ni := asMapAny(n.StatusObject["nodeInfo"]); len(ni) > 0 {
			if v := strAny(ni["kubeletVersion"]); v != "" {
				kubeletVers = append(kubeletVers, v)
			}
		}
	}

	// Deprecated APIs from the cached discovery catalog.
	apiRows, _ := s.db.ListK8sAPIResources(r.Context(), clusterID)
	deprecated := analyzer.DetectDeprecatedAPIs(toAPIResourceInfos(apiRows))

	// Open critical incidents.
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 2000})
	crit := 0
	for _, inc := range incidents {
		if strings.EqualFold(inc.Severity, "critical") {
			crit++
		}
	}

	readiness := analyzer.ScoreUpgradeReadiness(analyzer.UpgradeReadinessInput{
		KubernetesVersion: cluster.KubernetesVersion,
		NodeKubeletVers:   kubeletVers,
		DeprecatedAPIs:    len(deprecated),
		CriticalIncidents: crit,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"readiness":  readiness,
		"deprecated": deprecated,
		"node_count": len(nodes),
		"note":       "클러스터 업그레이드 준비도입니다(OpenShift ClusterVersion 스타일). deprecated API·kubelet 버전 skew·미해결 critical incident를 종합합니다. deprecated API 갱신은 클러스터 상세의 'API 탐색'으로 수집됩니다.",
	})
}
