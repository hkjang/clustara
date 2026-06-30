package analyzer

import (
	"sort"
	"strings"

	"clustara/internal/store"
)

// Image Stream Ledger (CLU-OCP-04).
//
// Absorbs OpenShift's ImageStream UX as a generic notion: a digest ledger over running workloads.
// Tracks which image (registry/repo/tag/digest) each workload runs, flags mutable tags (latest /
// not digest-pinned), and detects tag drift — the same repo:tag resolved to different digests
// across the cluster (a moved tag, the classic "works on one pod, not another" trap). Pure over
// Pod inventory: spec images give the declared ref, status containerStatuses give the resolved digest.

// ImageLedgerEntry is one distinct image reference in use.
type ImageLedgerEntry struct {
	Registry     string   `json:"registry"`
	Repository   string   `json:"repository"`
	Tag          string   `json:"tag"`
	Digest       string   `json:"digest,omitempty"` // resolved digest (from status imageID) if known
	Image        string   `json:"image"`            // declared spec ref
	Workloads    []string `json:"workloads"`        // ns/name using it (sample)
	Mutable      bool     `json:"mutable"`          // latest / not digest-pinned in spec
	PinnedDigest bool     `json:"pinned_digest"`    // spec ref pins @sha256:
}

// TagDrift is a repo:tag that currently resolves to more than one digest in the cluster.
type TagDrift struct {
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	Digests    []string `json:"digests"`
	Workloads  []string `json:"workloads"`
}

// ImageLedgerReport is the full ledger + risk rollup.
type ImageLedgerReport struct {
	Entries           []ImageLedgerEntry `json:"entries"`
	TagDrifts         []TagDrift         `json:"tag_drifts"`
	TotalImages       int                `json:"total_images"`
	MutableCount      int                `json:"mutable_count"`
	DigestPinnedCount int                `json:"digest_pinned_count"`
	TagDriftCount     int                `json:"tag_drift_count"`
}

// BuildImageLedger builds the image digest ledger + tag-drift detection from Pod inventory.
func BuildImageLedger(items []store.K8sInventoryItem) ImageLedgerReport {
	type entryAcc struct {
		e         ImageLedgerEntry
		workloads map[string]bool
	}
	entries := map[string]*entryAcc{} // key: declared image ref
	order := []string{}
	// repo:tag → set of resolved digests + workloads (for drift).
	driftDigests := map[string]map[string]bool{}
	driftWorkloads := map[string]map[string]bool{}

	for _, it := range items {
		if it.Kind != "Pod" {
			continue
		}
		wl := it.Namespace + "/" + it.Name
		// Resolved digests by container image, from status.containerStatuses.
		resolved := map[string]string{} // image → digest
		for _, cs := range asAnySliceLedger(it.StatusObject["containerStatuses"]) {
			csm := asAnyMapLedger(cs)
			img := strLedger(csm["image"])
			_, _, _, dig := ParseImageRef(strLedger(csm["imageID"]))
			if img != "" && dig != "" {
				resolved[img] = dig
			}
		}
		for _, c := range specContainersLedger(it.Spec) {
			cm := asAnyMapLedger(c)
			img := strLedger(cm["image"])
			if img == "" {
				continue
			}
			reg, repo, tag, dig := ParseImageRef(img)
			if dig == "" {
				dig = resolved[img] // fall back to the resolved digest from status
			}
			acc := entries[img]
			if acc == nil {
				acc = &entryAcc{e: ImageLedgerEntry{
					Registry: reg, Repository: repo, Tag: tag, Digest: dig, Image: img,
					Mutable: isMutableTag(tag, img), PinnedDigest: strings.Contains(img, "@sha256:"),
				}, workloads: map[string]bool{}}
				entries[img] = acc
				order = append(order, img)
			}
			if acc.e.Digest == "" && dig != "" {
				acc.e.Digest = dig
			}
			acc.workloads[wl] = true

			if repo != "" && tag != "" && dig != "" {
				rt := repo + ":" + tag
				if driftDigests[rt] == nil {
					driftDigests[rt] = map[string]bool{}
					driftWorkloads[rt] = map[string]bool{}
				}
				driftDigests[rt][dig] = true
				driftWorkloads[rt][wl] = true
			}
		}
	}

	rep := ImageLedgerReport{Entries: []ImageLedgerEntry{}, TagDrifts: []TagDrift{}}
	for _, k := range order {
		acc := entries[k]
		acc.e.Workloads = sortedKeysLedger(acc.workloads, 10)
		rep.Entries = append(rep.Entries, acc.e)
		if acc.e.Mutable {
			rep.MutableCount++
		}
		if acc.e.PinnedDigest {
			rep.DigestPinnedCount++
		}
	}
	rep.TotalImages = len(rep.Entries)
	for rt, digs := range driftDigests {
		if len(digs) <= 1 {
			continue
		}
		i := strings.LastIndex(rt, ":")
		drift := TagDrift{Repository: rt[:i], Tag: rt[i+1:], Digests: sortedSetLedger(digs), Workloads: sortedKeysLedger(driftWorkloads[rt], 10)}
		rep.TagDrifts = append(rep.TagDrifts, drift)
	}
	rep.TagDriftCount = len(rep.TagDrifts)
	sort.SliceStable(rep.Entries, func(i, j int) bool {
		if rep.Entries[i].Mutable != rep.Entries[j].Mutable {
			return rep.Entries[i].Mutable // mutable first (riskier)
		}
		return rep.Entries[i].Image < rep.Entries[j].Image
	})
	sort.SliceStable(rep.TagDrifts, func(i, j int) bool {
		return rep.TagDrifts[i].Repository+rep.TagDrifts[i].Tag < rep.TagDrifts[j].Repository+rep.TagDrifts[j].Tag
	})
	return rep
}

func isMutableTag(tag, img string) bool {
	if strings.Contains(img, "@sha256:") {
		return false // digest-pinned
	}
	t := strings.ToLower(tag)
	return t == "" || t == "latest" || t == "main" || t == "master" || t == "stable" || t == "dev" || t == "edge"
}

// --- tiny local any-helpers (analyzer must not import proxy) ---

func asAnyMapLedger(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asAnySliceLedger(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func strLedger(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func specContainersLedger(spec map[string]any) []any {
	ps := spec
	if tmpl := asAnyMapLedger(spec["template"]); len(tmpl) > 0 {
		if inner := asAnyMapLedger(tmpl["spec"]); len(inner) > 0 {
			ps = inner
		}
	}
	return asAnySliceLedger(ps["containers"])
}

func sortedKeysLedger(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func sortedSetLedger(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
