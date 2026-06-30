package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
)

// Built-in Observability Profile (CLU-OCP-10).
//
// Generates Prometheus-Operator ServiceMonitor + alert rules + SLO templates per service type.
// Pure generator — returns YAML/templates for the operator to apply (no cluster mutation).

// handleK8sObservability serves observability templates.
// GET /admin/k8s/observability?service_type=&namespace=&workload=&port=
func (s *Server) handleK8sObservability(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	st := strings.TrimSpace(q.Get("service_type"))
	if st == "" {
		// No type → return the supported catalog so the UI can offer choices.
		writeJSON(w, http.StatusOK, map[string]any{
			"service_types": analyzer.SupportedObservabilityTypes(),
			"note":          "service_type을 지정하면 ServiceMonitor·Alert·SLO 템플릿을 생성합니다(OpenShift Monitoring 스타일). web·api·batch·db_client·gpu·generic 지원.",
		})
		return
	}
	prof := analyzer.GenerateObservabilityProfile(analyzer.ObservabilityRequest{
		ServiceType: st,
		Namespace:   strings.TrimSpace(q.Get("namespace")),
		Workload:    strings.TrimSpace(q.Get("workload")),
		PortName:    strings.TrimSpace(q.Get("port")),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":       prof,
		"service_types": analyzer.SupportedObservabilityTypes(),
		"note":          "생성된 템플릿입니다. 적용 전 selector label과 metrics port를 워크로드에 맞게 확인하세요. Clustara는 클러스터를 변경하지 않습니다.",
	})
}
