package analyzer

import (
	"sort"
	"strings"

	"clustara/internal/store"
)

// Image usage: from the current inventory, map every container image to the workloads that use it
// and flag supply-chain risks (mutable :latest tag, no pinned digest). Pure over the inventory —
// no registry credentials required. Foundation for "이 image를 어떤 workload가 쓰는가" (REG-REQ-04).

// ImageUsage is one distinct image and where it is used.
type ImageUsage struct {
	Image      string   `json:"image"`
	Registry   string   `json:"registry"`
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	Digest     string   `json:"digest,omitempty"`
	Workloads  []string `json:"workloads"`
	Count      int      `json:"count"`
	Latest     bool     `json:"latest"`  // :latest or untagged → mutable
	Pinned     bool     `json:"pinned"`  // pinned by @sha256 digest
}

// ParseImageRef splits an image reference into registry / repository / tag / digest.
func ParseImageRef(raw string) (registry, repository, tag, digest string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", "", ""
	}
	if at := strings.Index(s, "@"); at >= 0 {
		digest = s[at+1:]
		s = s[:at]
	}
	// Registry = first path segment if it looks like a host (contains "." or ":" or is localhost).
	registry = "docker.io"
	slash := strings.Index(s, "/")
	if slash >= 0 {
		head := s[:slash]
		if strings.ContainsAny(head, ".:") || head == "localhost" {
			registry = head
			s = s[slash+1:]
		}
	}
	// Tag = after the LAST ":" in the remaining repository path (registry port already stripped).
	if colon := strings.LastIndex(s, ":"); colon >= 0 {
		tag = s[colon+1:]
		repository = s[:colon]
	} else {
		repository = s
		if digest == "" {
			tag = "latest" // untagged → implicit :latest (mutable)
		}
	}
	return registry, repository, tag, digest
}

// AnalyzeImageUsage builds the image→workloads map across the inventory, worst-first (most used,
// then mutable tags before pinned).
func AnalyzeImageUsage(items []store.K8sInventoryItem) []ImageUsage {
	type acc struct {
		u    ImageUsage
		seen map[string]bool
	}
	byImage := map[string]*acc{}
	for _, it := range items {
		ps := podSpecOf(it)
		if ps == nil {
			continue
		}
		workload := it.Namespace + "/" + it.Kind + "/" + it.Name
		for _, raw := range append(asAnySlice(ps["initContainers"]), asAnySlice(ps["containers"])...) {
			c := asAnyMap(raw)
			img := strings.TrimSpace(str(c["image"]))
			if img == "" {
				continue
			}
			a := byImage[img]
			if a == nil {
				reg, repo, tag, dig := ParseImageRef(img)
				a = &acc{u: ImageUsage{
					Image: img, Registry: reg, Repository: repo, Tag: tag, Digest: dig,
					Latest: dig == "" && (tag == "latest" || tag == ""),
					Pinned: dig != "",
				}, seen: map[string]bool{}}
				byImage[img] = a
			}
			if !a.seen[workload] {
				a.seen[workload] = true
				a.u.Workloads = append(a.u.Workloads, workload)
				a.u.Count++
			}
		}
	}
	out := make([]ImageUsage, 0, len(byImage))
	for _, a := range byImage {
		sort.Strings(a.u.Workloads)
		out = append(out, a.u)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Latest != out[j].Latest {
			return out[i].Latest // mutable first
		}
		return out[i].Image < out[j].Image
	})
	return out
}
