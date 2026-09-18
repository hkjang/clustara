package analyzer

// Pod ownership, read the way the API server records it.
//
// The collector folds metadata.ownerReferences into the stored Spec (kube.inventoryFromObject),
// so every Pod row says which controller owns it. Several screens still guessed from the labels
// the built-in controllers happen to stamp (pod-template-hash, controller-revision-hash,
// job-name), and those guesses disagree with the ownerReferences in two ways that matter to an
// approval record: a Pod owned only through ownerReferences (a bare ReplicaSet, an operator's
// CR, a static Pod mirrored to its Node) has none of those labels and read as "standalone,
// nothing recreates it"; and a StatefulSet Pod carries controller-revision-hash without
// pod-template-hash exactly like a DaemonSet Pod does, so a drain preview counted the database
// replicas — the Pods a drain evicts — as the DaemonSet Pods a drain leaves alone.

// PodOwnerReference returns the kind and name of the Pod's owner from ownerReferences: the
// reference marked controller, or failing that the first one that names a kind. Both are ""
// when the Pod has no owner (or the row predates ownerReferences being stored).
func PodOwnerReference(spec map[string]any) (kind, name string) {
	refs := asAnySlice(spec["ownerReferences"])
	for _, raw := range refs {
		m := asAnyMap(raw)
		if asBool(m["controller"]) && str(m["kind"]) != "" {
			return str(m["kind"]), str(m["name"])
		}
	}
	for _, raw := range refs {
		m := asAnyMap(raw)
		if k := str(m["kind"]); k != "" {
			return k, str(m["name"])
		}
	}
	return "", ""
}

// PodControllerKind answers "what recreates this Pod" for callers that must not read a
// controller-owned Pod as standalone: ownerReferences first, then the labels the built-in
// controllers stamp, for rows collected without ownerReferences. "" means no controller.
//
// The label fallback tells StatefulSet from DaemonSet by statefulset.kubernetes.io/pod-name,
// which only StatefulSet Pods carry; both kinds carry controller-revision-hash.
func PodControllerKind(spec map[string]any, labels map[string]string) string {
	if kind, _ := PodOwnerReference(spec); kind != "" {
		return kind
	}
	if _, ok := labels["statefulset.kubernetes.io/pod-name"]; ok {
		return "StatefulSet"
	}
	if _, ok := labels["pod-template-hash"]; ok {
		return "ReplicaSet"
	}
	if _, ok := labels["controller-revision-hash"]; ok {
		return "DaemonSet"
	}
	for _, k := range []string{"job-name", "batch.kubernetes.io/job-name"} {
		if _, ok := labels[k]; ok {
			return "Job"
		}
	}
	return ""
}
