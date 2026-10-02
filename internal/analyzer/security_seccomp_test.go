package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// seccompPodSpec builds a pod spec whose only deviation from the fully hardened
// baseline is the seccompProfile.type at the pod level and on its single container.
// An empty string means the level declares no seccompProfile at all.
func seccompPodSpec(podType, containerType string) map[string]any {
	c := hardenedContainer()
	sc := asAnyMap(c["securityContext"])
	if containerType == "" {
		delete(sc, "seccompProfile")
	} else {
		sc["seccompProfile"] = map[string]any{"type": containerType}
	}
	ps := map[string]any{"containers": []any{c}}
	if podType != "" {
		ps["securityContext"] = map[string]any{"seccompProfile": map[string]any{"type": podType}}
	}
	return ps
}

// Pod Security Restricted requires seccompProfile.type to be RuntimeDefault or
// Localhost, and the posture report never looked at it. A workload with no seccomp
// profile at all was reported at the strictest tier — and `level === 'restricted'` is
// the value the Pod Security table and the warehouse export use to *drop* a row, so
// the workloads still running the unconfined default were the ones nobody could see.
//
// The posture level is a separate judgement from "fails Restricted", so each case
// states it rather than deriving it from `violates`. Deriving it asserted that every
// seccomp failure lands on "baseline", which is wrong in one direction that matters:
// Baseline's own control is "must not be explicitly set to Unconfined", so an
// explicitly Unconfined pod is admitted by the Privileged policy alone. Leaving the
// profile undefined is the Restricted-only half.
func TestRestrictedProfileChecksSeccompProfile(t *testing.T) {
	cases := []struct {
		why           string
		podType       string
		containerType string
		violates      bool
		detail        string
		wantLevel     string
	}{
		{"neither pod nor container declares a profile", "", "", true, "seccompProfile 미설정", "baseline"},
		{"pod RuntimeDefault is inherited by a silent container", "RuntimeDefault", "", false, "", "restricted"},
		{"pod Localhost is inherited too", "Localhost", "", false, "", "restricted"},
		{"pod Unconfined is inherited by a silent container", "Unconfined", "", true, "seccompProfile=Unconfined", "privileged"},
		{"container Unconfined overrides a compliant pod", "RuntimeDefault", "Unconfined", true, "seccompProfile=Unconfined", "privileged"},
		{"container RuntimeDefault overrides an Unconfined pod", "Unconfined", "RuntimeDefault", false, "", "restricted"},
		{"container Localhost with no pod setting", "", "Localhost", false, "", "restricted"},
		{"container Unconfined with no pod setting", "", "Unconfined", true, "seccompProfile=Unconfined", "privileged"},
	}
	for _, tc := range cases {
		ps := seccompPodSpec(tc.podType, tc.containerType)

		got := evalRule(t, "enforce_pss_restricted", "Pod", ps, nil)
		if got.Violated != tc.violates {
			t.Errorf("%s: enforce_pss_restricted violated=%v, want %v (detail %q)", tc.why, got.Violated, tc.violates, got.Detail)
		} else if tc.violates && !strings.Contains(got.Detail, tc.detail) {
			t.Errorf("%s: detail %q should cite %q", tc.why, got.Detail, tc.detail)
		}

		rep := AnalyzeSecurity([]store.K8sInventoryItem{deployWithPodSpec("default", "w", ps)})
		if len(rep.PodSecurity) != 1 {
			t.Fatalf("%s: expected one pod security row, got %d", tc.why, len(rep.PodSecurity))
		}
		p := rep.PodSecurity[0]
		if p.Level != tc.wantLevel {
			t.Errorf("%s: level %q, want %q (violations %v)", tc.why, p.Level, tc.wantLevel, p.Violations)
		}
		if tc.violates && !strings.Contains(strings.Join(p.Violations, ", "), tc.detail) {
			t.Errorf("%s: posture violations %v should cite %q", tc.why, p.Violations, tc.detail)
		}
	}
}

// The precedence is per container, so a sidecar that opts out must not drag the
// container next to it into the report — and an init or ephemeral container counts,
// exactly like it does for the three controls this helper already checked.
func TestSeccompViolationNamesOnlyTheOffendingContainer(t *testing.T) {
	compliant := hardenedContainer()
	compliant["name"] = "app"
	unconfined := hardenedContainer()
	unconfined["name"] = "sidecar"
	asAnyMap(unconfined["securityContext"])["seccompProfile"] = map[string]any{"type": "Unconfined"}
	bareInit := hardenedContainer()
	bareInit["name"] = "init"
	delete(asAnyMap(bareInit["securityContext"]), "seccompProfile")

	ps := map[string]any{
		"securityContext": map[string]any{"seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers":      []any{compliant, unconfined},
		"initContainers":  []any{bareInit},
	}
	got := evalRule(t, "enforce_pss_restricted", "Pod", ps, nil)
	if !got.Violated {
		t.Fatal("the sidecar opting out of seccomp fails Restricted")
	}
	if !strings.Contains(got.Detail, "sidecar: seccompProfile=Unconfined") {
		t.Errorf("detail %q must name the sidecar", got.Detail)
	}
	if strings.Contains(got.Detail, "app: seccompProfile") {
		t.Errorf("detail %q must not blame the compliant container", got.Detail)
	}
	// The init container declares nothing, so it inherits the pod's RuntimeDefault.
	if strings.Contains(got.Detail, "init: seccompProfile") {
		t.Errorf("detail %q must not blame a container that inherits a compliant pod profile", got.Detail)
	}
}
