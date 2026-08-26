package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

func privilegedEphemeralPodSpec() map[string]any {
	return map[string]any{
		"containers": []any{map[string]any{
			"name": "app", "image": "app:1.0",
			"securityContext": map[string]any{"runAsNonRoot": true, "privileged": false},
		}},
		"ephemeralContainers": []any{map[string]any{
			"name": "debugger", "image": "busybox:latest",
			"securityContext": map[string]any{"privileged": true},
		}},
	}
}

// Ephemeral containers are how a debug session attaches to a running pod, and they
// accept securityContext.privileged and their own image. The policy engine walked
// only containers+initContainers, so a pod carrying a privileged debug container
// evaluated as fully compliant — the same settings on a regular container were
// denied.
func TestPolicyRulesSeePrivilegedEphemeralContainers(t *testing.T) {
	policies := []Policy{
		{ID: "p1", Name: "no privileged", RuleType: "disallow_privileged", Action: "Deny", Enabled: true},
		{ID: "p2", Name: "no latest", RuleType: "disallow_latest_tag", Action: "Deny", Enabled: true},
		{ID: "p3", Name: "non root", RuleType: "require_run_as_non_root", Action: "Deny", Enabled: true},
	}
	violated := map[string]string{}
	for _, res := range EvaluatePolicies("Pod", privilegedEphemeralPodSpec(), nil, policies) {
		if res.Violated {
			violated[res.RuleType] = res.Detail
		}
	}
	for _, rule := range []string{"disallow_privileged", "disallow_latest_tag", "require_run_as_non_root"} {
		if _, ok := violated[rule]; !ok {
			t.Errorf("%s did not fire on a privileged ephemeral container; violations=%v", rule, violated)
		}
	}
	if detail := violated["disallow_privileged"]; !strings.Contains(detail, "debugger") {
		t.Errorf("violation should name the ephemeral container, got %q", detail)
	}
}

// Image policy rules run off ExtractImages, so a debug container's image must be in
// the list or every image-based rule silently skips it.
func TestExtractImagesIncludesEphemeralContainers(t *testing.T) {
	imgs := ExtractImages(privilegedEphemeralPodSpec())
	found := false
	for _, img := range imgs {
		if img == "busybox:latest" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ephemeral container image missing from %v", imgs)
	}
}

// Pod security posture classification must count an ephemeral container's
// privileged flag the same way it counts a regular container's.
func TestPodSecurityClassificationSeesEphemeralContainers(t *testing.T) {
	item := store.K8sInventoryItem{Kind: "Pod", Namespace: "prod", Name: "api", Spec: privilegedEphemeralPodSpec()}
	res := classifyPodSecurity(item, podSpecOf(item))
	joined := strings.Join(res.Violations, " | ")
	if !strings.Contains(joined, "debugger") || !strings.Contains(joined, "privileged") {
		t.Fatalf("privileged ephemeral container not reported: level=%s violations=%v", res.Level, res.Violations)
	}
}

// Workload templates never carry ephemeralContainers, so the change must not alter
// how a Deployment is analysed.
func TestWorkloadTemplateAnalysisUnchanged(t *testing.T) {
	spec := map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "app", "image": "app:1.0"}},
	}}}
	imgs := ExtractImages(spec)
	if len(imgs) != 1 || imgs[0] != "app:1.0" {
		t.Fatalf("deployment image extraction changed: %v", imgs)
	}
}
