package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// evalRule runs one rule against one resource and returns its verdict.
func evalRule(t *testing.T, rule, kind string, spec map[string]any, ann map[string]string) PolicyResult {
	t.Helper()
	res := EvaluatePolicies(kind, spec, ann, []Policy{{ID: "p", Name: rule, RuleType: rule, Action: "Deny", Enabled: true}})
	if len(res) != 1 {
		t.Fatalf("expected 1 result for %s, got %d", rule, len(res))
	}
	return res[0]
}

// The image supply-chain rules fire on the absence of an attestation annotation. A
// Service, a ConfigMap or a ClusterRole never carries one and never pulls an image,
// so an unscoped rule denies every one of them. On the deploy path a single Service
// in the stack then blocks the whole apply with "이미지 서명 attestation 없음".
func TestImageRulesDoNotFireOnResourcesWithoutImages(t *testing.T) {
	imageRules := []string{"disallow_unsigned_image", "require_sbom", "require_vuln_scan_attestation"}
	policies := []Policy{}
	for i, rule := range imageRules {
		policies = append(policies, Policy{ID: string(rune('a' + i)), Name: rule, RuleType: rule, Action: "Deny", Enabled: true})
	}

	svc := map[string]any{"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": "web"},
		"spec":     map[string]any{"selector": map[string]any{"app": "web"}, "ports": []any{map[string]any{"port": float64(80)}}}}
	plan := AnalyzeStackManifest([]map[string]any{svc}, policies)
	if len(plan.PolicyViolations) != 0 {
		t.Errorf("a Service pulls no image; image rules must not fire: %+v", plan.PolicyViolations)
	}
	if plan.Denied {
		t.Error("a stack must not be denied because its Service carries no image signature")
	}

	// Same rules over the compliance path: a ClusterRole is evaluable (the RBAC rule
	// reads it) but references no image.
	role := store.K8sInventoryItem{Kind: "ClusterRole", Name: "reader",
		Spec: map[string]any{"rules": []any{map[string]any{"verbs": []any{"get"}, "resources": []any{"pods"}}}}}
	if v := CheckPolicyCompliance([]store.K8sInventoryItem{role}, policies); len(v) != 0 {
		t.Errorf("a ClusterRole must not be reported for image attestations: %+v", v)
	}

	// A workload with no attestation must still be caught — the scope narrows the
	// rules, it does not disarm them.
	pod := store.K8sInventoryItem{Kind: "Pod", Name: "app",
		Spec: map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:1.0"}}}}
	if v := CheckPolicyCompliance([]store.K8sInventoryItem{pod}, policies); len(v) != len(imageRules) {
		t.Errorf("an unattested Pod must still violate all %d image rules, got %+v", len(imageRules), v)
	}
}

// `registry.corp.local:5000/app` carries no tag, so the kubelet pulls `:latest` — the
// exact thing this rule exists to stop. Reading any `:` as "has a tag" let it through,
// and registries with an explicit port are the norm in a closed network.
func TestMutableTagRuleReadsTheReferenceNotTheColon(t *testing.T) {
	cases := []struct {
		image   string
		violate bool
		why     string
	}{
		{"registry.corp.local:5000/app", true, "untagged behind a registry port still resolves to :latest"},
		{"app", true, "untagged"},
		{"app:latest", true, "explicit latest"},
		{"registry.corp.local:5000/app:1.4.2", false, "pinned tag behind a registry port"},
		{"app:1.4.2", false, "pinned tag"},
		{"registry.corp.local:5000/app@sha256:abc", false, "digest pinned, no tag needed"},
		{"app:latest@sha256:abc", false, "digest wins over the tag"},
	}
	for _, tc := range cases {
		spec := map[string]any{"containers": []any{map[string]any{"name": "c", "image": tc.image}}}
		got := evalRule(t, "disallow_latest_tag", "Pod", spec, nil)
		if got.Violated != tc.violate {
			t.Errorf("%s: violated=%v, want %v (%s)", tc.image, got.Violated, tc.violate, tc.why)
		}
	}
}

// The Kubernetes API rejects `resources` on an ephemeral container, so requiring
// limits from one can never be satisfied: every pod with a debug session attached
// reports a limits violation for as long as the session lasts.
func TestResourceLimitsSkipsEphemeralContainers(t *testing.T) {
	limited := map[string]any{"limits": map[string]any{"cpu": "1", "memory": "256Mi"}}
	spec := map[string]any{
		"containers":          []any{map[string]any{"name": "app", "image": "app:1.0", "resources": limited}},
		"initContainers":      []any{map[string]any{"name": "init", "image": "init:1.0", "resources": limited}},
		"ephemeralContainers": []any{map[string]any{"name": "debugger", "image": "busybox:1.36"}},
	}
	if got := evalRule(t, "require_resource_limits", "Pod", spec, nil); got.Violated {
		t.Errorf("a debug container cannot declare resources; the pod is compliant: %s", got.Detail)
	}

	// An init container that really is missing limits must still be caught.
	spec["initContainers"] = []any{map[string]any{"name": "init", "image": "init:1.0"}}
	got := evalRule(t, "require_resource_limits", "Pod", spec, nil)
	if !got.Violated || !strings.Contains(got.Detail, "init") {
		t.Errorf("an init container without limits must violate, got %+v", got)
	}
}

// A container's securityContext overrides the pod's, so runAsNonRoot=false on a
// container defeats runAsNonRoot=true on the pod — that container runs as root while
// a pod-level-only reading calls the workload compliant.
func TestRunAsNonRootHonoursTheContainerOverride(t *testing.T) {
	spec := map[string]any{
		"securityContext": map[string]any{"runAsNonRoot": true},
		"containers": []any{
			map[string]any{"name": "app", "image": "app:1.0"},
			map[string]any{"name": "sidecar", "image": "side:1.0",
				"securityContext": map[string]any{"runAsNonRoot": false}},
		},
	}
	got := evalRule(t, "require_run_as_non_root", "Pod", spec, nil)
	if !got.Violated || !strings.Contains(got.Detail, "sidecar") {
		t.Errorf("runAsNonRoot=false on a container must violate despite the pod setting, got %+v", got)
	}

	// The pod-level setting still covers containers that say nothing.
	spec["containers"] = []any{map[string]any{"name": "app", "image": "app:1.0"}}
	if got := evalRule(t, "require_run_as_non_root", "Pod", spec, nil); got.Violated {
		t.Errorf("pod-level runAsNonRoot=true covers a silent container: %s", got.Detail)
	}
}
