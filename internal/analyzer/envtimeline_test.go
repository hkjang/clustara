package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestEnvReferencedSources(t *testing.T) {
	m := EnvSourceMap{Vars: []EnvVarSource{
		{Name: "A", SourceType: "configmap", SourceName: "cfg1"},
		{Name: "B", SourceType: "secret", SourceName: "sec1"},
		{Name: "(envFrom)", SourceType: "configmap_all", SourceName: "cfg2"},
		{Name: "(envFrom)", SourceType: "secret_all", SourceName: "sec1"}, // dup secret → deduped
		{Name: "C", SourceType: "literal"},
		{Name: "D", SourceType: "field"},
	}}
	cms, secs := EnvReferencedSources(m)
	if len(cms) != 2 || cms[0] != "cfg1" || cms[1] != "cfg2" {
		t.Fatalf("configmaps wrong: %+v", cms)
	}
	if len(secs) != 1 || secs[0] != "sec1" {
		t.Fatalf("secrets should dedupe to [sec1]: %+v", secs)
	}
}

func TestBuildEnvChangeTimeline(t *testing.T) {
	in := EnvTimelineInput{
		PodRevisions: []store.K8sResourceRevision{
			{Kind: "Pod", Name: "web-1", ChangeKind: "updated", ImageSet: "x:1.3", ObservedAt: "2026-06-30T10:00:00Z"},
		},
		SourceRevisions: []store.K8sResourceRevision{
			{Kind: "ConfigMap", Name: "cfg1", ChangeKind: "updated", ObservedAt: "2026-06-30T09:30:00Z"},
			{Kind: "Secret", Name: "sec1", ChangeKind: "updated", ObservedAt: "2026-06-30T11:00:00Z"},
		},
	}
	tl := BuildEnvChangeTimeline(in)
	if len(tl) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(tl))
	}
	// Newest first: secret 11:00 > pod 10:00 > configmap 09:30.
	if tl[0].Type != "secret_change" || tl[1].Type != "pod_change" || tl[2].Type != "configmap_change" {
		t.Fatalf("timeline not newest-first by type: %+v", tl)
	}
	if tl[1].Detail != "image: x:1.3" {
		t.Fatalf("pod entry should carry image detail: %+v", tl[1])
	}
}
