package proxy

import (
	"testing"

	"clustara/internal/store"
)

// spec.defaultBackend serves every request that matches no rule, so its Service is exposed —
// the extractor only walked spec.rules and left it out of the exposure targets.
func TestIngressExposureInputIncludesDefaultBackend(t *testing.T) {
	in := ingressExposureInput(store.K8sInventoryItem{
		Kind: "Ingress", Namespace: "prod", Name: "ing",
		Spec: map[string]any{
			"defaultBackend": map[string]any{"service": map[string]any{"name": "fallback"}},
			"rules": []any{map[string]any{"host": "example.com", "http": map[string]any{"paths": []any{
				map[string]any{"path": "/", "backend": map[string]any{"service": map[string]any{"name": "api"}}},
			}}}},
		},
	})
	found := map[string]bool{}
	for _, s := range in.TargetServices {
		found[s] = true
	}
	if !found["fallback"] || !found["api"] {
		t.Fatalf("expected both the defaultBackend and path backends, got %+v", in.TargetServices)
	}
}
