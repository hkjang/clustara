package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func connByCheck(fs []ConnFinding, check string) (ConnFinding, bool) {
	for _, f := range fs {
		if f.Check == check {
			return f, true
		}
	}
	return ConnFinding{}, false
}

func TestAnalyzeServicesEndpoints(t *testing.T) {
	items := []store.K8sInventoryItem{
		// Service whose selector matches a pod -> healthy, no finding.
		{Kind: "Service", Namespace: "default", Name: "ok", Spec: map[string]any{"selector": map[string]any{"app": "web"}}},
		{Kind: "Pod", Namespace: "default", Name: "web-1", Labels: map[string]string{"app": "web", "tier": "fe"}},
		// Service whose selector matches nothing -> ServiceNoEndpoints.
		{Kind: "Service", Namespace: "default", Name: "orphan", Spec: map[string]any{"selector": map[string]any{"app": "missing"}}},
		// Service without selector -> ServiceEmptySelector (low).
		{Kind: "Service", Namespace: "default", Name: "headless", Spec: map[string]any{}},
	}
	out := analyzeServices(items)

	if _, ok := connByCheck(out, "ServiceNoEndpoints"); !ok {
		t.Fatalf("expected ServiceNoEndpoints for orphan, got %+v", out)
	}
	// 'ok' service must not produce a no-endpoints finding.
	for _, f := range out {
		if f.ResourceName == "ok" && f.Check == "ServiceNoEndpoints" {
			t.Fatalf("matching service should be healthy: %+v", f)
		}
	}
	if f, ok := connByCheck(out, "ServiceEmptySelector"); !ok || f.Severity != "low" {
		t.Fatalf("expected low ServiceEmptySelector, got %+v", out)
	}
}

func TestAnalyzeIngresses(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Service", Namespace: "default", Name: "api"},
		// Ingress -> backend "api" exists, backend "ghost" missing, duplicate host with ing2.
		{Kind: "Ingress", Namespace: "default", Name: "ing1", Spec: map[string]any{
			"rules": []any{map[string]any{"host": "example.com", "http": map[string]any{"paths": []any{
				map[string]any{"backend": map[string]any{"service": map[string]any{"name": "api"}}},
				map[string]any{"backend": map[string]any{"service": map[string]any{"name": "ghost"}}},
			}}}},
			"tls": []any{map[string]any{"hosts": []any{"example.com"}}}, // no secretName
		}},
		{Kind: "Ingress", Namespace: "default", Name: "ing2", Spec: map[string]any{
			"rules": []any{map[string]any{"host": "example.com"}},
		}},
	}
	out := analyzeIngresses(items)

	if f, ok := connByCheck(out, "IngressBackendMissing"); !ok || f.Severity != "high" {
		t.Fatalf("expected high IngressBackendMissing (ghost), got %+v", out)
	}
	if _, ok := connByCheck(out, "IngressTLSNoSecret"); !ok {
		t.Fatalf("expected IngressTLSNoSecret, got %+v", out)
	}
	if _, ok := connByCheck(out, "IngressDuplicateHost"); !ok {
		t.Fatalf("expected IngressDuplicateHost for example.com, got %+v", out)
	}
}

func TestAnalyzePVCs(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "PersistentVolumeClaim", Namespace: "default", Name: "data", Status: "Pending", Spec: map[string]any{"storageClassName": "fast"}},
		{Kind: "PersistentVolumeClaim", Namespace: "default", Name: "bound", Status: "Bound"},
	}
	events := []store.K8sEvent{
		{Namespace: "default", Reason: "ProvisioningFailed", Message: "failed to provision volume for data", Type: "Warning"},
	}
	out := analyzePVCs(items, events)
	if len(out) != 1 || out[0].Check != "PVCPending" || out[0].ResourceName != "data" {
		t.Fatalf("expected one PVCPending for data, got %+v", out)
	}
	// storageClass + provisioning event should appear in evidence.
	joined := ""
	for _, e := range out[0].Evidence {
		joined += e + "|"
	}
	if !containsSub([]string{joined}, "fast") || !containsSub([]string{joined}, "ProvisioningFailed") {
		t.Fatalf("expected storageClass + event evidence, got %+v", out[0].Evidence)
	}
}
