package analyzer

import (
	"strings"
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

// The field drift report is rendered straight into the admin UI. Every sibling diff view masks
// env values (maskRevisionDiff, the Manifest Viewer), so this one must not be the view that prints
// a password — while still reporting that the two sides differ.
func TestDetectStackFieldDriftMasksCredentialValues(t *testing.T) {
	docs := []map[string]any{{
		"kind": "Deployment", "apiVersion": "apps/v1",
		"metadata": map[string]any{"name": "api", "namespace": "prod", "annotations": map[string]any{
			"clustara.io/db-password": "declared-pw",
			"owner":                   "platform-team",
		}},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"name": "api", "env": []any{
				map[string]any{"name": "DB_PASSWORD", "value": "declared-pw"},
				map[string]any{"name": "DSN", "value": "postgres://app:declared-pw@db:5432/app"},
				map[string]any{"name": "LOG_LEVEL", "value": "info"},
			}},
		}}}},
	}}
	inventory := []store.K8sInventoryItem{{
		Kind: "Deployment", Namespace: "prod", Name: "api",
		Annotations: map[string]string{"clustara.io/db-password": "live-pw", "owner": "sre-team"},
		Spec: map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"name": "api", "env": []any{
				map[string]any{"name": "DB_PASSWORD", "value": "live-pw"},
				map[string]any{"name": "DSN", "value": "postgres://app:live-pw@db:5432/app"},
				map[string]any{"name": "LOG_LEVEL", "value": "debug"},
			}},
		}}}},
	}}

	rep := DetectStackFieldDrift(docs, "default", inventory)
	if rep.Drifted != 1 {
		t.Fatalf("drifted = %d, want 1 (masking must not hide the drift itself)", rep.Drifted)
	}
	diffs := map[string]StackFieldDiff{}
	for _, d := range rep.Entries[0].Diffs {
		diffs[d.Path] = d
	}
	env, ok := diffs["containers[api].env"]
	if !ok {
		t.Fatalf("env drift not reported: %+v", diffs)
	}
	for _, secret := range []string{"declared-pw", "live-pw"} {
		for _, rendered := range []string{env.Declared, env.Live, diffs["annotations[clustara.io/db-password]"].Declared, diffs["annotations[clustara.io/db-password]"].Live} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("drift report leaked %q in %q", secret, rendered)
			}
		}
	}
	if !strings.Contains(env.Declared, "LOG_LEVEL=info") || !strings.Contains(env.Live, "LOG_LEVEL=debug") {
		t.Fatalf("non-credential env values must stay readable: %q → %q", env.Declared, env.Live)
	}
	if !strings.Contains(env.Declared, "DB_PASSWORD=") {
		t.Fatalf("masked env should keep the variable name: %q", env.Declared)
	}
	if owner, ok := diffs["annotations[owner]"]; !ok || owner.Declared != "platform-team" || owner.Live != "sre-team" {
		t.Fatalf("harmless annotation drift should stay readable: %+v", owner)
	}
}
