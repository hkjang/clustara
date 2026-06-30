package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Exposure Center (CLU-OCP-02).
//
// Collects exposure-capable resources (Ingress, Service LoadBalancer/NodePort, Gateway, HTTPRoute)
// from inventory, extracts hosts/paths/targets/TLS, and scores external-exposure risk.

// handleK8sExposures serves the exposure analysis for a cluster.
// GET /admin/k8s/exposures?cluster_id=
func (s *Server) handleK8sExposures(w http.ResponseWriter, r *http.Request) {
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
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	findings := make([]analyzer.ExposureFinding, 0)
	for _, it := range items {
		switch it.Kind {
		case "Ingress":
			findings = append(findings, analyzer.AnalyzeExposure(ingressExposureInput(it)))
		case "Service":
			t := strAny(it.Spec["type"])
			if strings.EqualFold(t, "LoadBalancer") || strings.EqualFold(t, "NodePort") {
				findings = append(findings, analyzer.AnalyzeExposure(analyzer.ExposureResourceInput{
					Kind: "Service", Namespace: it.Namespace, Name: it.Name, ServiceType: t,
				}))
			}
		}
	}
	analyzer.SortExposureFindings(findings)
	writeJSON(w, http.StatusOK, map[string]any{
		"exposures": findings,
		"summary":   analyzer.SummarizeExposure(findings),
		"change_bridge": map[string]any{"submit_to": "/admin/k8s/stacks", "note": "노출(Ingress/Gateway/Service) 변경은 수정한 매니페스트를 앱 배포(Stack)로 검증(정책·위험)→승인→적용하세요 (CLU-NEXT-11)."},
		"note":      "외부 노출 리소스(Ingress·LoadBalancer/NodePort Service)와 TLS·wildcard·민감 경로 노출 위험입니다(OpenShift Route 스타일). 위험 순으로 정렬됩니다. 변경은 Stack Apply 승인 흐름으로 진행하세요.",
	})
}

// ingressExposureInput extracts hosts/paths/targets/TLS from an Ingress spec (networking.k8s.io/v1).
func ingressExposureInput(it store.K8sInventoryItem) analyzer.ExposureResourceInput {
	in := analyzer.ExposureResourceInput{Kind: "Ingress", Namespace: it.Namespace, Name: it.Name}
	spec := it.Spec
	// TLS blocks → covered hosts.
	for _, tls := range asSliceAny(spec["tls"]) {
		in.HasTLS = true
		for _, h := range asSliceAny(asMapAny(tls)["hosts"]) {
			if hs := strAny(h); hs != "" {
				in.TLSHosts = appendUnique(in.TLSHosts, hs)
			}
		}
	}
	for _, rule := range asSliceAny(spec["rules"]) {
		rm := asMapAny(rule)
		if host := strAny(rm["host"]); host != "" {
			in.Hosts = appendUnique(in.Hosts, host)
		}
		http := asMapAny(rm["http"])
		for _, p := range asSliceAny(http["paths"]) {
			pm := asMapAny(p)
			if path := strAny(pm["path"]); path != "" {
				in.Paths = appendUnique(in.Paths, path)
			}
			if svc := asMapAny(asMapAny(pm["backend"])["service"]); len(svc) > 0 {
				if n := strAny(svc["name"]); n != "" {
					in.TargetServices = appendUnique(in.TargetServices, n)
				}
			}
		}
	}
	return in
}
