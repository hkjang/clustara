package analyzer

import (
	"testing"

	"clustara/internal/store"
)

// violatingPodFor builds a Pod that violates exactly the named rule, as both a
// manifest document and the pod spec an inventory item would store.
func violatingPodFor(rule string) (doc map[string]any, spec map[string]any, annotations map[string]string) {
	ann := map[string]any{}
	podSpec := map[string]any{
		"containers": []any{map[string]any{
			"name": "app", "image": "app@sha256:0123456789abcdef",
			"securityContext": map[string]any{"runAsNonRoot": true},
			"resources":       map[string]any{"limits": map[string]any{"cpu": "1"}},
		}},
	}
	c := podSpec["containers"].([]any)[0].(map[string]any)
	sc := c["securityContext"].(map[string]any)
	switch rule {
	case "disallow_privileged", "deny_privileged_runtime", "enforce_pss_restricted":
		sc["privileged"] = true
	case "disallow_host_network":
		podSpec["hostNetwork"] = true
	case "disallow_host_path":
		podSpec["volumes"] = []any{map[string]any{"name": "h", "hostPath": map[string]any{"path": "/"}}}
	case "disallow_latest_tag":
		c["image"] = "app:latest"
	case "require_image_digest":
		c["image"] = "app:1.0"
	case "require_resource_limits":
		delete(c, "resources")
	case "require_run_as_non_root":
		delete(sc, "runAsNonRoot")
	case "disallow_unsigned_image", "require_sbom", "require_vuln_scan_attestation":
		// violated by the absence of an attestation annotation
	case "deny_critical_vulnerability":
		ann["clustara.io/critical-vulnerabilities"] = "12"
	case "warn_high_vulnerability":
		ann["clustara.io/high-vulnerabilities"] = "7"
	case "deny_unfixed_exception_expired":
		ann["clustara.io/exception-expired"] = "true"
	}
	meta := map[string]any{"name": "victim"}
	annotations = map[string]string{}
	if len(ann) > 0 {
		meta["annotations"] = ann
		for k, v := range ann {
			annotations[k] = v.(string)
		}
	}
	doc = map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": podSpec}
	return doc, podSpec, annotations
}

// Every rule must reach the same verdict whether it runs on the deploy path
// (AnalyzeStackManifest over a manifest document) or the compliance path
// (CheckPolicyCompliance over a live inventory item). A rule that fires on only one
// of them means an operator's guardrail is enforced after the fact but not at
// deploy time, or vice versa.
func TestEveryPolicyRuleFiresOnBothPaths(t *testing.T) {
	for _, rule := range PolicyRuleTypes {
		if rule == "disallow_wildcard_rbac" {
			continue // RBAC-only; covered by TestWildcardRBACIsDeniedOnTheManifestPath
		}
		t.Run(rule, func(t *testing.T) {
			pol := []Policy{{ID: "p", Name: rule, RuleType: rule, Action: "Deny", Enabled: true}}
			doc, spec, ann := violatingPodFor(rule)

			plan := AnalyzeStackManifest([]map[string]any{doc}, pol)
			if len(plan.PolicyViolations) == 0 {
				t.Errorf("manifest path did not fire; warnings=%v", plan.Warnings)
			}
			item := store.K8sInventoryItem{Kind: "Pod", Name: "victim", Spec: spec, Annotations: ann}
			if scan := CheckPolicyCompliance([]store.K8sInventoryItem{item}, pol); len(scan) == 0 {
				t.Error("inventory path did not fire")
			}
		})
	}
}

// The attestation rules read the resource's own annotations, which live beside spec
// in a document and in a separate field on an inventory item — not inside spec.
// Because they fire only on a bad value being present, an unreachable annotation
// silenced them entirely rather than making them noisy.
func TestResourceAnnotationsReachTheAttestationRules(t *testing.T) {
	pol := []Policy{{ID: "p", Name: "crit", RuleType: "deny_critical_vulnerability", Action: "Deny", Enabled: true}}
	podSpec := map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:1.0"}}}
	ann := map[string]any{"clustara.io/critical-vulnerabilities": "12"}

	doc := map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "p", "annotations": ann}, "spec": podSpec}
	if plan := AnalyzeStackManifest([]map[string]any{doc}, pol); len(plan.PolicyViolations) == 0 {
		t.Error("a Pod annotated with 12 critical vulnerabilities was not denied on the manifest path")
	}
	item := store.K8sInventoryItem{Kind: "Pod", Name: "p", Spec: podSpec,
		Annotations: map[string]string{"clustara.io/critical-vulnerabilities": "12"}}
	if scan := CheckPolicyCompliance([]store.K8sInventoryItem{item}, pol); len(scan) == 0 {
		t.Error("the same Pod was not flagged by the compliance scan")
	}
}

// Pod template annotations must keep working, and a clean count must not fire.
func TestTemplateAnnotationsStillReadAndZeroCountPasses(t *testing.T) {
	pol := []Policy{{ID: "p", Name: "crit", RuleType: "deny_critical_vulnerability", Action: "Deny", Enabled: true}}
	podSpec := map[string]any{"containers": []any{map[string]any{"name": "app", "image": "app:1.0"}}}

	bad := map[string]any{"template": map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{"clustara.io/critical-vulnerabilities": "3"}},
		"spec":     podSpec}}
	if r := EvaluatePolicies("Deployment", bad, nil, pol); !r[0].Violated {
		t.Error("template annotation with 3 critical vulnerabilities did not fire")
	}
	clean := map[string]any{"template": map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{"clustara.io/critical-vulnerabilities": "0"}},
		"spec":     podSpec}}
	if r := EvaluatePolicies("Deployment", clean, nil, pol); r[0].Violated {
		t.Error("a zero critical-vulnerability count must not fire")
	}
}
