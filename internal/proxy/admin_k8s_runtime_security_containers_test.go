package proxy

import (
	"strings"
	"testing"

	"clustara/internal/analyzer"
)

// The runtime-security screen (CLU-OCP-03) and the workspace risk tally both read a
// pod spec themselves. Walking only `containers` scored a pod carrying a privileged
// init container — or a privileged debug container attached to it right now — as
// having no risky setting, while the SEC-01 posture flagged the very same pod.
func TestPodSecurityInputSeesInitAndEphemeralContainers(t *testing.T) {
	spec := map[string]any{
		"containers": []any{map[string]any{"name": "app", "securityContext": map[string]any{"runAsUser": float64(1000)}}},
		"initContainers": []any{map[string]any{"name": "setup", "securityContext": map[string]any{
			"capabilities": map[string]any{"add": []any{"SYS_ADMIN"}}}}},
		"ephemeralContainers": []any{map[string]any{"name": "debugger", "securityContext": map[string]any{"privileged": true}}},
	}
	in := podSecurityInput(spec)
	if !in.Privileged {
		t.Errorf("privileged ephemeral (debug) container not detected: %+v", in)
	}
	if len(in.AddedCaps) == 0 || !strings.EqualFold(in.AddedCaps[0], "SYS_ADMIN") {
		t.Errorf("init container capability not detected: %+v", in)
	}
	f := analyzer.ScorePodSecurity(in)
	if f.Profile != "privileged" || f.RiskLevel != "high" {
		t.Errorf("pod with a privileged debug container should score high/privileged, got %s/%s", f.RiskLevel, f.Profile)
	}
}

// runAsUser is inherited from the pod unless the container overrides it — in both
// directions.
func TestPodSecurityInputResolvesRootAgainstPodDefault(t *testing.T) {
	inherited := podSecurityInput(map[string]any{
		"securityContext": map[string]any{"runAsUser": float64(0)},
		"containers":      []any{map[string]any{"name": "app"}},
	})
	if !inherited.RunAsRoot {
		t.Errorf("container inheriting the pod's UID 0 should be root: %+v", inherited)
	}
	overridden := podSecurityInput(map[string]any{
		"securityContext": map[string]any{"runAsUser": float64(0)},
		"containers":      []any{map[string]any{"name": "app", "securityContext": map[string]any{"runAsUser": float64(1000)}}},
	})
	if overridden.RunAsRoot {
		t.Errorf("container overriding the pod UID must not be reported as root: %+v", overridden)
	}
}

// The workspace health tally answers the same question about the same pod and must
// not disagree with the runtime-security screen.
func TestWorkspaceRuntimeRiskMatchesRuntimeSecurity(t *testing.T) {
	cases := []struct {
		name string
		spec map[string]any
		want bool
	}{
		{"pod-level root", map[string]any{
			"securityContext": map[string]any{"runAsUser": float64(0)},
			"containers":      []any{map[string]any{"name": "app"}},
		}, true},
		{"privileged debug container", map[string]any{
			"containers":          []any{map[string]any{"name": "app"}},
			"ephemeralContainers": []any{map[string]any{"name": "debugger", "securityContext": map[string]any{"privileged": true}}},
		}, true},
		{"container overrides pod root", map[string]any{
			"securityContext": map[string]any{"runAsUser": float64(0)},
			"containers":      []any{map[string]any{"name": "app", "securityContext": map[string]any{"runAsUser": float64(1000)}}},
		}, false},
		{"plain workload", map[string]any{
			"containers": []any{map[string]any{"name": "app"}},
		}, false},
	}
	for _, tc := range cases {
		if got := podHasRuntimeSecurityRisk(tc.spec); got != tc.want {
			t.Errorf("%s: podHasRuntimeSecurityRisk=%v want %v", tc.name, got, tc.want)
		}
	}
}
