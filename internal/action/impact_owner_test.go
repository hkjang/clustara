package action

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

func ownedBy(kind, name string, extra map[string]any) map[string]any {
	spec := map[string]any{"ownerReferences": []any{map[string]any{"apiVersion": "v1", "kind": kind, "name": name, "controller": true}}}
	for k, v := range extra {
		spec[k] = v
	}
	return spec
}

// A Pod owned through ownerReferences alone — an operator's CR, a bare ReplicaSet, a static
// Pod — carries none of the labels the built-in controllers stamp. Judged by labels it read as
// "standalone, nothing recreates it", and that claim went into the approval record.
func TestAssessImpactDeletePodOwnedThroughOwnerReferences(t *testing.T) {
	cases := []store.K8sInventoryItem{
		{Kind: "Pod", Namespace: "spark", Name: "etl-driver", Labels: map[string]string{"app": "etl"}, Spec: ownedBy("SparkApplication", "etl", nil)},
		{Kind: "Pod", Namespace: "default", Name: "rs-abc", Spec: ownedBy("ReplicaSet", "rs", nil)},
		{Kind: "Pod", Namespace: "kube-system", Name: "kube-apiserver-cp-1", Spec: ownedBy("Node", "cp-1", nil)},
	}
	for _, pod := range cases {
		imp := AssessImpact("delete_pod", nil, pod, true, nil)
		if len(imp.Blockers) != 0 || imp.Details["controller_owned"] != true {
			t.Fatalf("%s/%s is controller-owned and must not be blocked as standalone, got %+v", pod.Namespace, pod.Name, imp)
		}
		if strings.Contains(imp.Summary, "standalone") {
			t.Fatalf("%s/%s summary must not call the pod standalone, got %q", pod.Namespace, pod.Name, imp.Summary)
		}
	}
	// A Pod with no owner at all is still the standalone case.
	imp := AssessImpact("delete_pod", nil, store.K8sInventoryItem{Kind: "Pod", Namespace: "default", Name: "debug", Spec: map[string]any{"containers": []any{}}}, true, nil)
	if len(imp.Blockers) == 0 || imp.Details["controller_owned"] != false {
		t.Fatalf("a pod without ownerReferences or controller labels is standalone, got %+v", imp)
	}
}

// Drain preview: StatefulSet Pods are evicted, DaemonSet Pods are not. Told apart by labels
// alone they look identical (controller-revision-hash, no pod-template-hash), so the database
// replicas were reported as DaemonSet Pods — and DaemonSet Pods, which are the ones mounting
// hostPath, raised the data-loss blocker on every node.
func TestAssessImpactDrainSeparatesDaemonSetFromStatefulSet(t *testing.T) {
	hostPath := map[string]any{"volumes": []any{map[string]any{"name": "logs", "hostPath": map[string]any{"path": "/var/log"}}}}
	all := []store.K8sInventoryItem{
		// StatefulSet replica, exactly the label shape a DaemonSet Pod has.
		{Kind: "Pod", Namespace: "db", Name: "pg-0", Labels: map[string]string{"controller-revision-hash": "pg-1", "statefulset.kubernetes.io/pod-name": "pg-0"},
			Spec: ownedBy("StatefulSet", "pg", map[string]any{"nodeName": "node-1"})},
		// DaemonSet log shipper with a hostPath volume.
		{Kind: "Pod", Namespace: "logging", Name: "fluent-bit-x1", Labels: map[string]string{"controller-revision-hash": "fb-1"},
			Spec: ownedBy("DaemonSet", "fluent-bit", map[string]any{"nodeName": "node-1", "volumes": hostPath["volumes"]})},
		// Deployment Pod, no local storage.
		{Kind: "Pod", Namespace: "web", Name: "api-7d9-1", Labels: map[string]string{"pod-template-hash": "7d9"},
			Spec: ownedBy("ReplicaSet", "api-7d9", map[string]any{"nodeName": "node-1"})},
	}
	imp := AssessImpact("drain", nil, store.K8sInventoryItem{Kind: "Node", Name: "node-1"}, true, all)
	if got := imp.Details["daemonset_pods"]; got != 1 {
		t.Fatalf("exactly one DaemonSet pod on node-1, got %v (summary %q)", got, imp.Summary)
	}
	if got := imp.Details["affected_pods"]; got != 2 {
		t.Fatalf("drain evicts the StatefulSet and Deployment pods, not the DaemonSet pod: want 2, got %v (summary %q)", got, imp.Summary)
	}
	if got := imp.Details["local_storage_pods"]; got != 0 {
		t.Fatalf("the DaemonSet's hostPath is not at risk from a drain, got local_storage_pods=%v", got)
	}
	for _, b := range imp.Blockers {
		if strings.Contains(b, "local storage") {
			t.Fatalf("data-loss blocker must not be raised for a DaemonSet's hostPath, got %+v", imp.Blockers)
		}
	}
	ns, _ := imp.Details["namespaces"].([]string)
	if strings.Join(ns, ",") != "db,web" {
		t.Fatalf("affected namespaces are those of the evicted pods, got %v", ns)
	}

	// The same StatefulSet Pod collected without ownerReferences is still not a DaemonSet Pod.
	legacy := []store.K8sInventoryItem{{Kind: "Pod", Namespace: "db", Name: "pg-0",
		Labels: map[string]string{"controller-revision-hash": "pg-1", "statefulset.kubernetes.io/pod-name": "pg-0"},
		Spec:   map[string]any{"nodeName": "node-1"}}}
	imp = AssessImpact("drain", nil, store.K8sInventoryItem{Kind: "Node", Name: "node-1"}, true, legacy)
	if imp.Details["daemonset_pods"] != 0 || imp.Details["affected_pods"] != 1 {
		t.Fatalf("label-only StatefulSet pod must count as evicted, got %+v", imp.Details)
	}
}
