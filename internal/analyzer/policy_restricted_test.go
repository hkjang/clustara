package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// hardenedContainer is a container that satisfies every Restricted control this
// package checks, plus both resource limits. It is the "nothing should fire" baseline
// the tests below mutate one field at a time.
func hardenedContainer() map[string]any {
	return map[string]any{
		"name": "app", "image": "app@sha256:abc",
		"securityContext": map[string]any{
			"runAsNonRoot": true, "allowPrivilegeEscalation": false,
			"capabilities": map[string]any{"drop": []any{"ALL"}},
		},
		"resources": map[string]any{"limits": map[string]any{"cpu": "1", "memory": "256Mi"}},
	}
}

func podSpecWith(c map[string]any) map[string]any {
	return map[string]any{"containers": []any{c}}
}

// A container with a CPU limit but no memory limit has no memory ceiling: it can grow
// until the kubelet evicts *other* pods off the node. That is the failure this rule
// exists to prevent, and `len(limits) == 0` never saw it — the exported Kyverno pattern
// (memory: "?*", cpu: "?*") and the rule description have always required both.
func TestResourceLimitsRequireBothCPUAndMemory(t *testing.T) {
	cases := []struct {
		limits  map[string]any
		violate bool
		want    string
		why     string
	}{
		{map[string]any{"cpu": "1", "memory": "256Mi"}, false, "", "both set"},
		{map[string]any{"cpu": "1"}, true, "memory", "cpu only — unbounded memory"},
		{map[string]any{"memory": "256Mi"}, true, "cpu", "memory only"},
		{map[string]any{"cpu": "1", "memory": ""}, true, "memory", "a blank value is not a limit"},
		{map[string]any{"cpu": "1", "memory": nil}, true, "memory", "a null value is not a limit"},
		{map[string]any{}, true, "cpu/memory", "empty limits map"},
		{nil, true, "cpu/memory", "no limits at all"},
	}
	for _, tc := range cases {
		c := hardenedContainer()
		if tc.limits == nil {
			delete(c, "resources")
		} else {
			c["resources"] = map[string]any{"limits": tc.limits}
		}
		got := evalRule(t, "require_resource_limits", "Pod", podSpecWith(c), nil)
		if got.Violated != tc.violate {
			t.Errorf("%s: violated=%v, want %v (detail %q)", tc.why, got.Violated, tc.violate, got.Detail)
			continue
		}
		if tc.violate && !strings.Contains(got.Detail, tc.want) {
			t.Errorf("%s: detail %q should name the missing key %q", tc.why, got.Detail, tc.want)
		}
	}
}

// A quantity written as a YAML number (`cpu: 1`) is still a quantity.
func TestResourceLimitsAcceptNumericQuantities(t *testing.T) {
	c := hardenedContainer()
	c["resources"] = map[string]any{"limits": map[string]any{"cpu": float64(1), "memory": float64(268435456)}}
	if got := evalRule(t, "require_resource_limits", "Pod", podSpecWith(c), nil); got.Violated {
		t.Errorf("numeric quantities are limits: %s", got.Detail)
	}
}

// enforce_pss_restricted shared a case with deny_privileged_runtime, so it checked
// nothing the Restricted profile actually requires: a pod with no securityContext at
// all — running as root, with the default capability set and privilege escalation
// allowed — passed a Deny gate named "Pod Security Restricted 강제".
func TestPSSRestrictedRuleChecksTheRestrictedControls(t *testing.T) {
	bare := podSpecWith(map[string]any{"name": "app", "image": "app:1.0"})

	if got := evalRule(t, "deny_privileged_runtime", "Pod", bare, nil); got.Violated {
		t.Errorf("a bare pod uses no privileged runtime setting: %s", got.Detail)
	}
	got := evalRule(t, "enforce_pss_restricted", "Pod", bare, nil)
	if !got.Violated {
		t.Fatal("a root pod with the default capability set does not meet Pod Security Restricted")
	}
	for _, want := range []string{"runAsNonRoot", "allowPrivilegeEscalation", "capabilities"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail %q should cite the failing control %q", got.Detail, want)
		}
	}

	// The hardened pod must still pass, and a resource with no pod spec must not fire.
	if got := evalRule(t, "enforce_pss_restricted", "Pod", podSpecWith(hardenedContainer()), nil); got.Violated {
		t.Errorf("a hardened pod meets Restricted: %s", got.Detail)
	}
	svc := map[string]any{"selector": map[string]any{"app": "web"}}
	if got := evalRule(t, "enforce_pss_restricted", "Service", svc, nil); got.Violated {
		t.Errorf("a Service runs no container: %s", got.Detail)
	}
}

// Pod Security levels are cumulative. Ranking on privileged/baseline violations alone
// labelled every unhardened pod "restricted" — the strictest tier — because running as
// root with the default capabilities breaks nothing at the baseline level. The label is
// what consumers key on: the Pod Security table and the warehouse export both drop
// restricted rows, so the least hardened workloads were the ones nobody could see.
func TestUnhardenedPodIsNotClassifiedRestricted(t *testing.T) {
	rep := AnalyzeSecurity([]store.K8sInventoryItem{
		deployWithPodSpec("default", "bare", podSpecWith(map[string]any{"name": "app", "image": "x:1"})),
		deployWithPodSpec("default", "hardened", podSpecWith(hardenedContainer())),
	})

	byName := map[string]PodSecurityResult{}
	for _, p := range rep.PodSecurity {
		byName[p.Name] = p
	}
	bare := byName["bare"]
	if bare.Level != "baseline" {
		t.Errorf("a root pod with default capabilities is at most baseline, got %q (violations %v)", bare.Level, bare.Violations)
	}
	if len(bare.Violations) == 0 {
		t.Error("its Restricted-level violations must be reported")
	}
	if hardened := byName["hardened"]; hardened.Level != "restricted" {
		t.Errorf("the hardened pod must stay restricted, got %q (%v)", hardened.Level, hardened.Violations)
	}
	if rep.Summary.Restricted != 1 || rep.Summary.Baseline != 1 {
		t.Errorf("summary should count 1 restricted + 1 baseline, got %+v", rep.Summary)
	}
}

// A container's securityContext overrides the pod's, so runAsNonRoot=false on the
// container means that container runs as root however the pod is configured. The
// posture report read the two with `&&`, which let the pod's true hide the container's
// false — the same defect already fixed on the require_run_as_non_root rule.
func TestRestrictedProfileHonoursTheContainerRunAsNonRootOverride(t *testing.T) {
	root := hardenedContainer()
	asAnyMap(root["securityContext"])["runAsNonRoot"] = false
	ps := map[string]any{
		"securityContext": map[string]any{"runAsNonRoot": true},
		"containers":      []any{root},
	}
	got := evalRule(t, "enforce_pss_restricted", "Pod", ps, nil)
	if !got.Violated || !strings.Contains(got.Detail, "runAsNonRoot=false") {
		t.Errorf("a container opting out of runAsNonRoot runs as root, got %+v", got)
	}
}
