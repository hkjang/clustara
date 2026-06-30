package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestDetectStackFieldDrift(t *testing.T) {
	docs := []map[string]any{
		{
			"kind":       "Deployment",
			"apiVersion": "apps/v1",
			"metadata":   map[string]any{"name": "web", "namespace": "prod", "labels": map[string]any{"app": "web", "tier": "frontend"}},
			"spec": map[string]any{
				"replicas": 3,
				"template": map[string]any{"spec": map[string]any{"containers": []any{
					map[string]any{"name": "web", "image": "nginx:1.27", "env": []any{map[string]any{"name": "LOG", "value": "info"}}},
				}}},
			},
		},
		{ // declared but missing in cluster
			"kind": "Service", "apiVersion": "v1",
			"metadata": map[string]any{"name": "web-svc", "namespace": "prod"},
		},
	}
	inventory := []store.K8sInventoryItem{
		{
			Kind: "Deployment", Namespace: "prod", Name: "web",
			Labels: map[string]string{"app": "web", "tier": "backend"}, // tier drifted
			Spec: map[string]any{
				"replicas": float64(2), // drifted 3 → 2
				"template": map[string]any{"spec": map[string]any{"containers": []any{
					map[string]any{"name": "web", "image": "nginx:1.25", "env": []any{map[string]any{"name": "LOG", "value": "debug"}}}, // image + env drifted
				}}},
			},
		},
	}

	rep := DetectStackFieldDrift(docs, "default", inventory)
	if rep.Declared != 2 {
		t.Fatalf("declared = %d, want 2", rep.Declared)
	}
	if rep.Present != 1 || rep.Missing != 1 {
		t.Fatalf("present/missing = %d/%d, want 1/1", rep.Present, rep.Missing)
	}
	if rep.Drifted != 1 {
		t.Fatalf("drifted = %d, want 1", rep.Drifted)
	}
	if rep.Synced {
		t.Fatalf("should not be synced")
	}

	// Find the deployment entry and verify its field diffs.
	var dep *StackFieldDriftEntry
	for i := range rep.Entries {
		if rep.Entries[i].Name == "web" {
			dep = &rep.Entries[i]
		}
	}
	if dep == nil {
		t.Fatal("deployment entry missing")
	}
	paths := map[string]string{}
	for _, d := range dep.Diffs {
		paths[d.Path] = d.Declared + "→" + d.Live
	}
	if paths["spec.replicas"] != "3→2" {
		t.Fatalf("replicas diff wrong: %q", paths["spec.replicas"])
	}
	if paths["containers[web].image"] != "nginx:1.27→nginx:1.25" {
		t.Fatalf("image diff wrong: %q", paths["containers[web].image"])
	}
	if _, ok := paths["containers[web].env"]; !ok {
		t.Fatalf("expected env diff, got %+v", paths)
	}
	if _, ok := paths["labels[tier]"]; !ok {
		t.Fatalf("expected labels[tier] diff, got %+v", paths)
	}
	// app label matches → no diff
	if _, ok := paths["labels[app]"]; ok {
		t.Fatalf("labels[app] should not drift")
	}
}

func TestDetectStackFieldDriftSynced(t *testing.T) {
	docs := []map[string]any{{
		"kind": "Deployment", "apiVersion": "apps/v1",
		"metadata": map[string]any{"name": "api", "namespace": "prod"},
		"spec": map[string]any{"replicas": 2, "template": map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"name": "api", "image": "api:1.0"},
		}}}},
	}}
	inventory := []store.K8sInventoryItem{{
		Kind: "Deployment", Namespace: "prod", Name: "api",
		Spec: map[string]any{"replicas": float64(2), "template": map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"name": "api", "image": "api:1.0"},
		}}}},
	}}
	rep := DetectStackFieldDrift(docs, "default", inventory)
	if !rep.Synced || rep.Drifted != 0 {
		t.Fatalf("expected synced with no drift, got %+v", rep)
	}
}
