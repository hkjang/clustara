package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func podItem(ns, name, image, statusImage, imageID string) store.K8sInventoryItem {
	it := store.K8sInventoryItem{
		Kind: "Pod", Namespace: ns, Name: name,
		Spec: map[string]any{"containers": []any{map[string]any{"name": "c", "image": image}}},
	}
	if statusImage != "" {
		it.StatusObject = map[string]any{"containerStatuses": []any{map[string]any{"image": statusImage, "imageID": imageID}}}
	}
	return it
}

func TestBuildImageLedger(t *testing.T) {
	items := []store.K8sInventoryItem{
		// same repo:tag resolving to two different digests across pods → tag drift.
		podItem("prod", "web-1", "registry.io/app/web:1.2", "registry.io/app/web:1.2", "registry.io/app/web@sha256:aaa"),
		podItem("prod", "web-2", "registry.io/app/web:1.2", "registry.io/app/web:1.2", "registry.io/app/web@sha256:bbb"),
		// mutable latest tag.
		podItem("prod", "cache-1", "redis:latest", "", ""),
		// digest-pinned (immutable).
		podItem("prod", "db-1", "postgres@sha256:ccc", "", ""),
	}
	rep := BuildImageLedger(items)

	if rep.TotalImages != 3 { // web:1.2, redis:latest, postgres@sha256
		t.Fatalf("expected 3 distinct images: %+v", rep.Entries)
	}
	// tag drift on app/web:1.2 (aaa vs bbb).
	if rep.TagDriftCount != 1 {
		t.Fatalf("expected 1 tag drift: %+v", rep.TagDrifts)
	}
	if len(rep.TagDrifts) == 1 {
		d := rep.TagDrifts[0]
		if d.Tag != "1.2" || len(d.Digests) != 2 {
			t.Fatalf("drift should have 2 digests for tag 1.2: %+v", d)
		}
	}
	// mutable + pinned counts.
	byImg := map[string]ImageLedgerEntry{}
	for _, e := range rep.Entries {
		byImg[e.Image] = e
	}
	if !byImg["redis:latest"].Mutable {
		t.Fatalf("redis:latest should be mutable: %+v", byImg["redis:latest"])
	}
	if byImg["postgres@sha256:ccc"].Mutable || !byImg["postgres@sha256:ccc"].PinnedDigest {
		t.Fatalf("postgres digest-pinned should be immutable+pinned: %+v", byImg["postgres@sha256:ccc"])
	}
	if rep.MutableCount < 1 || rep.DigestPinnedCount < 1 {
		t.Fatalf("expected mutable+pinned counts: %+v", rep)
	}
}

func TestIsMutableTag(t *testing.T) {
	cases := map[string]bool{"latest": true, "": true, "main": true, "1.2.3": false, "v1.0": false}
	for tag, want := range cases {
		if got := isMutableTag(tag, "repo:"+tag); got != want {
			t.Fatalf("isMutableTag(%q)=%v want %v", tag, got, want)
		}
	}
	if isMutableTag("latest", "repo:latest@sha256:abc") {
		t.Fatal("digest-pinned ref must be immutable even with latest tag")
	}
}
