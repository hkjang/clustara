package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// One image reference is read by four places — the SEC-02 posture check, the SEC-10 policy
// gate, the Dockerfile build gate and the image ledger/usage inventory. These pin them to the
// same reading: a `:` is a tag only after the last `/`, so a registry port is not a tag.

func imgPod(ns, name string, spec map[string]any) store.K8sInventoryItem {
	return store.K8sInventoryItem{ClusterID: "c1", Kind: "Pod", Namespace: ns, Name: name, Spec: spec}
}

func TestImageFindingsUntaggedPortedRegistry(t *testing.T) {
	pod := func(name, img string) store.K8sInventoryItem {
		return imgPod("prod", name, map[string]any{"containers": []any{map[string]any{"name": "c", "image": img}}})
	}
	items := []store.K8sInventoryItem{
		pod("untagged", "registry.corp.local:5000/team/app"),
		pod("tagged", "registry.corp.local:5000/team/app:1.4.2"),
		pod("pinned", "registry.corp.local:5000/team/app@sha256:abc"),
	}
	rep := AnalyzeSecurity(items)
	flagged := map[string]bool{}
	for _, f := range rep.Images {
		flagged[f.ResourceName] = true
	}
	// Untagged behind a registry port is `:latest` at pull time — the SEC-10 gate already
	// says so, and the posture report must not disagree.
	if !flagged["untagged"] {
		t.Fatalf("untagged image behind a registry port should violate image-tag-policy: %+v", rep.Images)
	}
	// False-positive regression: a real tag / a digest behind the same port stay clean.
	if flagged["tagged"] || flagged["pinned"] {
		t.Fatalf("tagged and digest-pinned images must stay clean: %+v", rep.Images)
	}
	// The two readings of the same reference must agree.
	policy := Policy{RuleType: "disallow_latest_tag", Action: "audit", Enabled: true}
	for _, it := range items {
		violated := len(CheckPolicyCompliance([]store.K8sInventoryItem{it}, []Policy{policy})) > 0
		if violated != flagged[it.Name] {
			t.Fatalf("%s: policy gate says violated=%v but posture says %v", it.Name, violated, flagged[it.Name])
		}
	}
}

func TestAnalyzeDockerfileBaseImageReference(t *testing.T) {
	// Untagged image behind a registry port: no tag, so `:latest` at pull time.
	rep := AnalyzeDockerfile("FROM registry.corp.local:5000/base\nUSER 1000\n")
	if !rep.MutableBase {
		t.Fatalf("untagged base behind a registry port should be mutable: %+v", rep)
	}

	// `--platform` is a FROM flag, not the image reference, and `FROM build` refers to an
	// earlier stage in this same file — neither is an unpinned registry pull.
	multi := "FROM --platform=linux/amd64 registry.corp.local:5000/base:1.0 AS build\n" +
		"RUN make\n" +
		"FROM build\n" +
		"USER 1000\n"
	rep = AnalyzeDockerfile(multi)
	if rep.MutableBase {
		t.Fatalf("pinned base + stage reference should not be mutable: %+v", rep.Findings)
	}
	for _, f := range rep.Findings {
		if f.Rule == "mutable-base" && strings.Contains(f.Message, "--platform") {
			t.Fatalf("build flag reported as the base image: %+v", f)
		}
	}
}

func TestAnalyzeImageUsageIncludesEphemeralContainers(t *testing.T) {
	usage := AnalyzeImageUsage([]store.K8sInventoryItem{
		imgPod("prod", "web", map[string]any{
			"containers":          []any{map[string]any{"name": "app", "image": "registry:5000/app:1.0"}},
			"ephemeralContainers": []any{map[string]any{"name": "debug", "image": "netshoot:latest"}},
		}),
	})
	by := map[string]ImageUsage{}
	for _, u := range usage {
		by[u.Image] = u
	}
	if _, ok := by["netshoot:latest"]; !ok {
		t.Fatalf("a debug container's image belongs in the supply-chain inventory: %+v", usage)
	}
	if !by["netshoot:latest"].Latest {
		t.Fatalf("netshoot:latest should be flagged mutable: %+v", by["netshoot:latest"])
	}
	if by["registry:5000/app:1.0"].Latest {
		t.Fatalf("a tagged image behind a registry port is not mutable: %+v", by["registry:5000/app:1.0"])
	}
}

func TestBuildImageLedgerRegistryScopedDrift(t *testing.T) {
	items := []store.K8sInventoryItem{
		podItem("prod", "a", "harbor.corp/app/web:1.2", "harbor.corp/app/web:1.2", "harbor.corp/app/web@sha256:aaa"),
		podItem("prod", "b", "docker.io/app/web:1.2", "docker.io/app/web:1.2", "docker.io/app/web@sha256:bbb"),
	}
	rep := BuildImageLedger(items)
	// Two registries hosting the same repository path are two images, not a moved tag.
	if rep.TagDriftCount != 0 {
		t.Fatalf("same repo path on two registries is not tag drift: %+v", rep.TagDrifts)
	}

	// Init container images are pulled too — they belong in the ledger and its mutable count.
	initPod := store.K8sInventoryItem{Kind: "Pod", Namespace: "prod", Name: "job",
		Spec: map[string]any{
			"containers":     []any{map[string]any{"name": "app", "image": "harbor.corp/app:1.0"}},
			"initContainers": []any{map[string]any{"name": "wait", "image": "busybox:latest"}},
		}}
	rep = BuildImageLedger([]store.K8sInventoryItem{initPod})
	found := false
	for _, e := range rep.Entries {
		if e.Image == "busybox:latest" {
			found = e.Mutable
		}
	}
	if !found {
		t.Fatalf("init container image should be a mutable ledger entry: %+v", rep.Entries)
	}
}
