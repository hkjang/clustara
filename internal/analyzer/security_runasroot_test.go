package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

func rootTestPod(spec map[string]any) store.K8sInventoryItem {
	return store.K8sInventoryItem{Kind: "Pod", Namespace: "prod", Name: "api", Spec: spec}
}

func violationsOf(spec map[string]any) string {
	item := rootTestPod(spec)
	return strings.Join(classifyPodSecurity(item, podSpecOf(item)).Violations, " | ")
}

// The pod-level securityContext is the default for every container that does not set
// its own, and `spec.securityContext.runAsUser: 0` with containers that declare
// nothing is the most common way a workload runs as root. Reading only the container
// securityContext left that workload with no runAsUser violation at all.
func TestPodLevelRunAsUserRootIsAViolation(t *testing.T) {
	joined := violationsOf(map[string]any{
		"securityContext": map[string]any{"runAsUser": float64(0)},
		"containers":      []any{map[string]any{"name": "app", "image": "app:1.0"}},
	})
	if !strings.Contains(joined, "app: runAsUser=0") {
		t.Fatalf("pod-level runAsUser=0 not reported: %s", joined)
	}
	if !strings.Contains(joined, "Pod securityContext 상속") {
		t.Errorf("violation should say the root UID came from the pod: %s", joined)
	}
}

// A container's own runAsUser overrides the pod's, so a pod-level 0 that every
// container replaces with a real UID must not be reported as root.
func TestContainerRunAsUserOverridesPodRoot(t *testing.T) {
	joined := violationsOf(map[string]any{
		"securityContext": map[string]any{"runAsUser": float64(0)},
		"containers": []any{map[string]any{"name": "app", "image": "app:1.0",
			"securityContext": map[string]any{"runAsUser": float64(1000)}}},
	})
	if strings.Contains(joined, "runAsUser=0") {
		t.Fatalf("container overriding the pod UID should not be reported as root: %s", joined)
	}
}

// The reverse precedence: a container that asks for UID 0 runs as root however
// harmless the pod default is, and the violation names the container, not the pod.
func TestContainerRootOverridesNonRootPod(t *testing.T) {
	joined := violationsOf(map[string]any{
		"securityContext": map[string]any{"runAsUser": float64(1000)},
		"containers": []any{
			map[string]any{"name": "app", "image": "app:1.0"},
			map[string]any{"name": "sidecar", "image": "s:1.0",
				"securityContext": map[string]any{"runAsUser": float64(0)}},
		},
	})
	if !strings.Contains(joined, "sidecar: runAsUser=0") {
		t.Fatalf("container-level root not reported: %s", joined)
	}
	if strings.Contains(joined, "app: runAsUser=0") {
		t.Errorf("container inheriting a non-root pod UID should be clean: %s", joined)
	}
	if strings.Contains(joined, "sidecar: runAsUser=0 (Pod") {
		t.Errorf("an explicit container UID must not be attributed to the pod: %s", joined)
	}
}

// An explicit null is how a serialized spec spells "unset"; it must not read as UID 0.
func TestNullRunAsUserIsUnset(t *testing.T) {
	joined := violationsOf(map[string]any{
		"securityContext": map[string]any{"runAsUser": nil},
		"containers":      []any{map[string]any{"name": "app", "image": "app:1.0", "securityContext": map[string]any{"runAsUser": nil}}},
	})
	if strings.Contains(joined, "runAsUser=0") {
		t.Fatalf("runAsUser: null must not count as root: %s", joined)
	}
}

// PodRunsAsRoot is shared with the runtime-security and workspace handlers, so the
// same pod cannot be root on one screen and not root on another.
func TestPodRunsAsRoot(t *testing.T) {
	cases := []struct {
		name string
		spec map[string]any
		want bool
	}{
		{"pod-level root inherited", map[string]any{
			"securityContext": map[string]any{"runAsUser": float64(0)},
			"containers":      []any{map[string]any{"name": "app"}},
		}, true},
		{"container overrides pod root", map[string]any{
			"securityContext": map[string]any{"runAsUser": float64(0)},
			"containers":      []any{map[string]any{"name": "app", "securityContext": map[string]any{"runAsUser": float64(1000)}}},
		}, false},
		{"init container inherits pod root", map[string]any{
			"securityContext": map[string]any{"runAsUser": float64(0)},
			"containers":      []any{map[string]any{"name": "app", "securityContext": map[string]any{"runAsUser": float64(1000)}}},
			"initContainers":  []any{map[string]any{"name": "setup"}},
		}, true},
		{"root debug container attached", map[string]any{
			"containers":          []any{map[string]any{"name": "app", "securityContext": map[string]any{"runAsUser": float64(1000)}}},
			"ephemeralContainers": []any{map[string]any{"name": "debugger", "securityContext": map[string]any{"runAsUser": float64(0)}}},
		}, true},
		{"nothing declared", map[string]any{
			"containers": []any{map[string]any{"name": "app"}},
		}, false},
	}
	for _, tc := range cases {
		if got := PodRunsAsRoot(tc.spec); got != tc.want {
			t.Errorf("%s: PodRunsAsRoot=%v want %v", tc.name, got, tc.want)
		}
	}
}
