package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestParseImageRef(t *testing.T) {
	cases := []struct{ raw, reg, repo, tag, dig string }{
		{"nginx", "docker.io", "nginx", "latest", ""},
		{"nginx:1.25", "docker.io", "nginx", "1.25", ""},
		{"library/redis:7", "docker.io", "library/redis", "7", ""},
		{"harbor.corp.io/team/app:v2", "harbor.corp.io", "team/app", "v2", ""},
		{"registry:5000/app:1.0", "registry:5000", "app", "1.0", ""},
		{"ghcr.io/org/svc@sha256:abc123", "ghcr.io", "org/svc", "", "sha256:abc123"},
	}
	for _, c := range cases {
		reg, repo, tag, dig := ParseImageRef(c.raw)
		if reg != c.reg || repo != c.repo || tag != c.tag || dig != c.dig {
			t.Errorf("ParseImageRef(%q) = (%q,%q,%q,%q), want (%q,%q,%q,%q)", c.raw, reg, repo, tag, dig, c.reg, c.repo, c.tag, c.dig)
		}
	}
}

func TestAnalyzeImageUsage(t *testing.T) {
	pod := func(ns, name, img string) store.K8sInventoryItem {
		return store.K8sInventoryItem{Kind: "Pod", Namespace: ns, Name: name,
			Spec: map[string]any{"containers": []any{map[string]any{"name": "c", "image": img}}}}
	}
	items := []store.K8sInventoryItem{
		pod("a", "p1", "nginx:1.25"),
		pod("a", "p2", "nginx:1.25"), // same image, 2 workloads
		pod("b", "p3", "app:latest"), // mutable
		pod("b", "p4", "svc@sha256:deadbeef"), // pinned
	}
	usage := AnalyzeImageUsage(items)
	by := map[string]ImageUsage{}
	for _, u := range usage {
		by[u.Image] = u
	}
	if by["nginx:1.25"].Count != 2 || len(by["nginx:1.25"].Workloads) != 2 {
		t.Fatalf("nginx should be used by 2 workloads: %+v", by["nginx:1.25"])
	}
	if !by["app:latest"].Latest || by["app:latest"].Pinned {
		t.Fatalf("app:latest should be mutable, not pinned: %+v", by["app:latest"])
	}
	if !by["svc@sha256:deadbeef"].Pinned || by["svc@sha256:deadbeef"].Latest {
		t.Fatalf("digest image should be pinned, not mutable: %+v", by["svc@sha256:deadbeef"])
	}
	// Most-used image sorts first.
	if usage[0].Image != "nginx:1.25" {
		t.Fatalf("most-used image should sort first, got %s", usage[0].Image)
	}
}
