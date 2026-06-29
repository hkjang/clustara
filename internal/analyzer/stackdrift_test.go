package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestDetectStackDrift(t *testing.T) {
	resources := []StackResource{
		{Kind: "Deployment", Namespace: "prod", Name: "web"},
		{Kind: "Service", Namespace: "prod", Name: "web"},
		{Kind: "ConfigMap", Name: "cfg"}, // no namespace → default applied
	}
	inventory := []store.K8sInventoryItem{
		{Kind: "Deployment", Namespace: "prod", Name: "web"},
		{Kind: "ConfigMap", Namespace: "prod", Name: "cfg"},
		// Service web is missing
	}
	rep := DetectStackDrift(resources, "prod", inventory)
	if rep.Declared != 3 || rep.Present != 2 || rep.Missing != 1 {
		t.Fatalf("drift counts: %+v", rep)
	}
	if rep.Synced {
		t.Fatalf("should not be synced with a missing resource: %+v", rep)
	}
	// Missing resource sorts first.
	if rep.Entries[0].Status != "missing" || rep.Entries[0].Kind != "Service" {
		t.Fatalf("missing Service should sort first: %+v", rep.Entries)
	}
	// Default namespace applied to the namespaceless ConfigMap.
	for _, e := range rep.Entries {
		if e.Kind == "ConfigMap" && (e.Namespace != "prod" || e.Status != "present") {
			t.Fatalf("namespaceless ConfigMap should use default ns and be present: %+v", e)
		}
	}

	// All present → synced.
	full := DetectStackDrift([]StackResource{{Kind: "Deployment", Namespace: "prod", Name: "web"}}, "prod",
		[]store.K8sInventoryItem{{Kind: "Deployment", Namespace: "prod", Name: "web"}})
	if !full.Synced || full.Missing != 0 {
		t.Fatalf("all-present should be synced: %+v", full)
	}
}
