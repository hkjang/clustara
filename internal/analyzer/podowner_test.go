package analyzer

import "testing"

func TestPodOwnerReferencePrefersTheControllerReference(t *testing.T) {
	spec := map[string]any{"ownerReferences": []any{
		map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "name": "cfg"}, // non-controller owner listed first
		map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9", "controller": true},
	}}
	kind, name := PodOwnerReference(spec)
	if kind != "ReplicaSet" || name != "api-7d9" {
		t.Fatalf("controller reference must win, got %s/%s", kind, name)
	}

	// Without a controller flag, the first reference that names a kind is the owner.
	kind, name = PodOwnerReference(map[string]any{"ownerReferences": []any{map[string]any{"kind": "Workflow", "name": "wf-1"}}})
	if kind != "Workflow" || name != "wf-1" {
		t.Fatalf("expected Workflow/wf-1, got %s/%s", kind, name)
	}
	if kind, name := PodOwnerReference(map[string]any{"containers": []any{}}); kind != "" || name != "" {
		t.Fatalf("a Pod without ownerReferences has no owner, got %s/%s", kind, name)
	}
}

// PodControllerKind: ownerReferences decide; the label guess only stands in for rows collected
// without them, and even then a StatefulSet Pod is not a DaemonSet Pod.
func TestPodControllerKindReadsOwnerReferencesBeforeLabels(t *testing.T) {
	cases := []struct {
		name   string
		spec   map[string]any
		labels map[string]string
		want   string
	}{
		{"operator CR owner, no controller labels", map[string]any{"ownerReferences": []any{map[string]any{"kind": "SparkApplication", "name": "etl", "controller": true}}}, map[string]string{"app": "etl"}, "SparkApplication"},
		{"bare ReplicaSet without pod-template-hash", map[string]any{"ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": "rs", "controller": true}}}, nil, "ReplicaSet"},
		{"static Pod mirrored to its Node", map[string]any{"ownerReferences": []any{map[string]any{"kind": "Node", "name": "cp-1", "controller": true}}}, nil, "Node"},
		{"ownerReferences win over a misleading label", map[string]any{"ownerReferences": []any{map[string]any{"kind": "StatefulSet", "name": "db", "controller": true}}}, map[string]string{"controller-revision-hash": "db-1"}, "StatefulSet"},
		{"label fallback: StatefulSet", nil, map[string]string{"controller-revision-hash": "db-1", "statefulset.kubernetes.io/pod-name": "db-0"}, "StatefulSet"},
		{"label fallback: DaemonSet", nil, map[string]string{"controller-revision-hash": "ds-1"}, "DaemonSet"},
		{"label fallback: Deployment's ReplicaSet", nil, map[string]string{"pod-template-hash": "7d9"}, "ReplicaSet"},
		{"label fallback: Job", nil, map[string]string{"batch.kubernetes.io/job-name": "backup"}, "Job"},
		{"standalone", nil, map[string]string{"app": "debug"}, ""},
	}
	for _, tc := range cases {
		if got := PodControllerKind(tc.spec, tc.labels); got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.name, tc.want, got)
		}
	}
}
