package analyzer

import (
	"encoding/json"
	"testing"

	"clustara/internal/store"
)

func specFromJSON(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("bad spec json: %v", err)
	}
	return m
}

func TestDiffRevisionsHighlightsKeyFields(t *testing.T) {
	from := store.K8sResourceRevision{
		ID: "a", Kind: "Deployment", Namespace: "default", Name: "api",
		Spec: specFromJSON(t, `{
			"replicas": 2,
			"template": {"spec": {"containers": [
				{"name": "api", "image": "example/api:1.0",
				 "resources": {"limits": {"memory": "256Mi"}}}
			]}}
		}`),
	}
	to := store.K8sResourceRevision{
		ID: "b", Kind: "Deployment", Namespace: "default", Name: "api",
		Spec: specFromJSON(t, `{
			"replicas": 5,
			"template": {"spec": {"containers": [
				{"name": "api", "image": "example/api:2.0",
				 "resources": {"limits": {"memory": "512Mi"}}}
			]}}
		}`),
	}

	diff := DiffRevisions(from, to)

	want := map[string]bool{"replica": false, "image": false, "resources": false}
	for _, c := range diff.Changes {
		if _, ok := want[c.Highlight]; ok {
			want[c.Highlight] = true
		}
	}
	for h, seen := range want {
		if !seen {
			t.Errorf("expected a change highlighted as %q, got changes=%+v", h, diff.Changes)
		}
	}

	// replicas change must surface the actual old/new scalar values.
	var foundReplica bool
	for _, c := range diff.Changes {
		if c.Highlight == "replica" {
			foundReplica = true
			if c.Old != "2" || c.New != "5" {
				t.Errorf("replica diff = %s -> %s, want 2 -> 5", c.Old, c.New)
			}
		}
	}
	if !foundReplica {
		t.Fatal("no replica change recorded")
	}
}

func TestDiffRevisionsNoChange(t *testing.T) {
	spec := specFromJSON(t, `{"replicas": 3, "image": "a:1"}`)
	from := store.K8sResourceRevision{Spec: spec}
	to := store.K8sResourceRevision{Spec: specFromJSON(t, `{"replicas": 3, "image": "a:1"}`)}
	if diff := DiffRevisions(from, to); len(diff.Changes) != 0 {
		t.Errorf("expected no changes for identical specs, got %+v", diff.Changes)
	}
}

func TestExtractReplicaAndImages(t *testing.T) {
	spec := specFromJSON(t, `{
		"replicas": 4,
		"template": {"spec": {"containers": [
			{"name": "a", "image": "img/b:2"},
			{"name": "c", "image": "img/a:1"}
		]}}
	}`)
	if got := ExtractReplica(spec); got != 4 {
		t.Errorf("ExtractReplica = %d, want 4", got)
	}
	// sorted + comma joined
	if got := ImageSetString(spec); got != "img/a:1, img/b:2" {
		t.Errorf("ImageSetString = %q, want %q", got, "img/a:1, img/b:2")
	}
}

func TestHashStableForEqualSpecs(t *testing.T) {
	a := specFromJSON(t, `{"x": 1, "y": {"z": 2}}`)
	b := specFromJSON(t, `{"y": {"z": 2}, "x": 1}`)
	if store.HashK8sSpec(a) != store.HashK8sSpec(b) {
		t.Error("hash should be independent of key order")
	}
}
