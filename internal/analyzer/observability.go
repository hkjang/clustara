package analyzer

import "fmt"

// Built-in Observability Profile (CLU-OCP-10).
//
// Absorbs OpenShift's monitoring-profile UX as a generic generator: given a service type, emits a
// Prometheus-Operator ServiceMonitor, a set of alert rules, and SLO templates. Pure string
// generation — operators apply the YAML themselves (no cluster mutation here).

// ObservabilityRequest describes the workload to template observability for.
type ObservabilityRequest struct {
	ServiceType string // web | api | batch | db_client | gpu | generic
	Namespace   string
	Workload    string
	PortName    string // metrics port name (default "metrics")
	PathPrefix  string // app label value (selector); defaults to Workload
}

// AlertRuleTemplate is one generated Prometheus alert rule.
type AlertRuleTemplate struct {
	Name     string `json:"name"`
	Expr     string `json:"expr"`
	For      string `json:"for"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// SLOTemplate is one suggested SLI/SLO.
type SLOTemplate struct {
	Name      string `json:"name"`
	SLI       string `json:"sli"`
	Objective string `json:"objective"`
	Window    string `json:"window"`
}

// ObservabilityProfile is the generated bundle.
type ObservabilityProfile struct {
	ServiceType        string              `json:"service_type"`
	ServiceMonitorYAML string              `json:"service_monitor_yaml"`
	AlertRules         []AlertRuleTemplate `json:"alert_rules"`
	SLOs               []SLOTemplate       `json:"slos"`
	Notes              []string            `json:"notes"`
}

// GenerateObservabilityProfile builds a monitoring template for the requested service type.
func GenerateObservabilityProfile(req ObservabilityRequest) ObservabilityProfile {
	st := req.ServiceType
	if st == "" {
		st = "generic"
	}
	ns := orDefault(req.Namespace, "default")
	wl := orDefault(req.Workload, "app")
	port := orDefault(req.PortName, "metrics")
	app := orDefault(req.PathPrefix, wl)

	prof := ObservabilityProfile{ServiceType: st, Notes: []string{}}
	prof.ServiceMonitorYAML = fmt.Sprintf(`apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: %s
  namespace: %s
  labels:
    app: %s
spec:
  selector:
    matchLabels:
      app: %s
  endpoints:
    - port: %s
      interval: 30s
      path: /metrics
`, wl, ns, app, app, port)

	// Common alerts for any service.
	prof.AlertRules = []AlertRuleTemplate{
		{Name: wl + "PodRestarting", Severity: "warning", For: "10m",
			Expr:    fmt.Sprintf(`increase(kube_pod_container_status_restarts_total{namespace="%s"}[15m]) > 3`, ns),
			Summary: "Pod 재시작 급증"},
		{Name: wl + "PodNotReady", Severity: "warning", For: "10m",
			Expr:    fmt.Sprintf(`kube_pod_status_ready{namespace="%s",condition="false"} == 1`, ns),
			Summary: "Pod Ready 아님"},
		{Name: wl + "OOMKilled", Severity: "critical", For: "0m",
			Expr:    fmt.Sprintf(`kube_pod_container_status_last_terminated_reason{namespace="%s",reason="OOMKilled"} == 1`, ns),
			Summary: "컨테이너 OOMKilled"},
	}

	// Service-type specific alerts + SLOs.
	switch st {
	case "web", "api":
		prof.AlertRules = append(prof.AlertRules,
			AlertRuleTemplate{Name: wl + "HighErrorRate", Severity: "critical", For: "5m",
				Expr:    fmt.Sprintf(`sum(rate(http_requests_total{namespace="%s",code=~"5.."}[5m])) / sum(rate(http_requests_total{namespace="%s"}[5m])) > 0.05`, ns, ns),
				Summary: "5xx 에러율 5% 초과"},
			AlertRuleTemplate{Name: wl + "HighLatencyP95", Severity: "warning", For: "10m",
				Expr:    fmt.Sprintf(`histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{namespace="%s"}[5m])) by (le)) > 1`, ns),
				Summary: "p95 지연 1s 초과"})
		prof.SLOs = []SLOTemplate{
			{Name: "availability", SLI: "성공 요청 비율(non-5xx)", Objective: "99.9%", Window: "30d"},
			{Name: "latency", SLI: "p95 < 500ms 비율", Objective: "99%", Window: "30d"},
		}
	case "batch":
		prof.AlertRules = append(prof.AlertRules,
			AlertRuleTemplate{Name: wl + "JobFailed", Severity: "warning", For: "0m",
				Expr:    fmt.Sprintf(`kube_job_status_failed{namespace="%s"} > 0`, ns),
				Summary: "Job 실패"})
		prof.SLOs = []SLOTemplate{{Name: "job_success", SLI: "Job 성공 비율", Objective: "99%", Window: "30d"}}
	case "db_client":
		prof.AlertRules = append(prof.AlertRules,
			AlertRuleTemplate{Name: wl + "ConnPoolSaturation", Severity: "warning", For: "10m",
				Expr: `db_client_connections_in_use / db_client_connections_max > 0.9`, Summary: "DB 커넥션 풀 포화"})
		prof.SLOs = []SLOTemplate{{Name: "query_success", SLI: "쿼리 성공 비율", Objective: "99.5%", Window: "30d"}}
	case "gpu":
		prof.AlertRules = append(prof.AlertRules,
			AlertRuleTemplate{Name: wl + "GPUUnderutilized", Severity: "info", For: "30m",
				Expr: `avg(DCGM_FI_DEV_GPU_UTIL) < 10`, Summary: "GPU 유휴(비용 낭비)"})
		prof.SLOs = []SLOTemplate{{Name: "gpu_availability", SLI: "GPU 가용 비율", Objective: "99%", Window: "30d"}}
		prof.Notes = append(prof.Notes, "DCGM exporter가 설치되어 있어야 합니다.")
	default:
		prof.SLOs = []SLOTemplate{{Name: "availability", SLI: "Pod Ready 비율", Objective: "99.5%", Window: "30d"}}
	}
	prof.Notes = append(prof.Notes, "Prometheus Operator(monitoring.coreos.com) 환경 기준입니다. 적용 전 selector label과 metrics port를 워크로드에 맞게 확인하세요.")
	return prof
}

// SupportedObservabilityTypes lists the service-type templates available.
func SupportedObservabilityTypes() []string {
	return []string{"web", "api", "batch", "db_client", "gpu", "generic"}
}
