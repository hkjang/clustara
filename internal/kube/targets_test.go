package kube

import "testing"

func TestDefaultInventoryTargetsIncludeManifestEditableKinds(t *testing.T) {
	got := map[string]bool{}
	for _, target := range DefaultInventoryTargets() {
		got[target.Kind] = true
	}
	for _, kind := range []string{
		"ConfigMap",
		"Secret",
		"ServiceAccount",
		"Service",
		"Role",
		"RoleBinding",
		"PersistentVolumeClaim",
		"Ingress",
		"NetworkPolicy",
	} {
		if !got[kind] {
			t.Fatalf("DefaultInventoryTargets missing manifest-editable kind %s", kind)
		}
	}
}
