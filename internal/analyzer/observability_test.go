package analyzer

import (
	"strings"
	"testing"
)

func TestGenerateObservabilityProfile(t *testing.T) {
	web := GenerateObservabilityProfile(ObservabilityRequest{ServiceType: "web", Namespace: "prod", Workload: "api", PortName: "http-metrics"})
	if !strings.Contains(web.ServiceMonitorYAML, "kind: ServiceMonitor") || !strings.Contains(web.ServiceMonitorYAML, "namespace: prod") {
		t.Fatalf("ServiceMonitor YAML missing fields: %s", web.ServiceMonitorYAML)
	}
	if !strings.Contains(web.ServiceMonitorYAML, "port: http-metrics") {
		t.Fatalf("ServiceMonitor should use the given port: %s", web.ServiceMonitorYAML)
	}
	// web should have error-rate + latency alerts + availability/latency SLOs.
	names := map[string]bool{}
	for _, a := range web.AlertRules {
		names[a.Name] = true
	}
	if !names["apiHighErrorRate"] || !names["apiHighLatencyP95"] {
		t.Fatalf("web alerts missing: %+v", web.AlertRules)
	}
	if len(web.SLOs) != 2 {
		t.Fatalf("web should have 2 SLOs: %+v", web.SLOs)
	}
	// common OOM alert present for any type.
	if !names["apiOOMKilled"] {
		t.Fatalf("OOM alert should always be present: %+v", web.AlertRules)
	}

	batch := GenerateObservabilityProfile(ObservabilityRequest{ServiceType: "batch", Namespace: "jobs", Workload: "etl"})
	bn := map[string]bool{}
	for _, a := range batch.AlertRules {
		bn[a.Name] = true
	}
	if !bn["etlJobFailed"] {
		t.Fatalf("batch should have JobFailed alert: %+v", batch.AlertRules)
	}

	// generic fallback still produces a profile.
	gen := GenerateObservabilityProfile(ObservabilityRequest{})
	if gen.ServiceType != "generic" || len(gen.SLOs) == 0 || gen.ServiceMonitorYAML == "" {
		t.Fatalf("generic profile incomplete: %+v", gen)
	}
}
