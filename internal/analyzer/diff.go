package analyzer

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"clustara/internal/store"
)

// FieldChange is one differing field between two resource revisions.
type FieldChange struct {
	Path      string `json:"path"`
	Old       string `json:"old"`
	New       string `json:"new"`
	Kind      string `json:"kind"`      // added | removed | changed
	Highlight string `json:"highlight"` // replica | image | env | resources | ingress_host | ""
}

// RevisionDiff is the structured difference between two revisions of one resource.
type RevisionDiff struct {
	ClusterID  string        `json:"cluster_id"`
	Kind       string        `json:"kind"`
	Namespace  string        `json:"namespace"`
	Name       string        `json:"name"`
	FromID     string        `json:"from_id"`
	ToID       string        `json:"to_id"`
	FromAt     string        `json:"from_observed_at"`
	ToAt       string        `json:"to_observed_at"`
	Changes    []FieldChange `json:"changes"`
	Highlights []string      `json:"highlights"` // distinct highlight categories present
}

// DiffRevisions compares two revisions and returns the field-level changes, tagging the
// changes that map to the acceptance-criteria fields (replica, image, env, resource limits,
// ingress host).
func DiffRevisions(from, to store.K8sResourceRevision) RevisionDiff {
	changes := []FieldChange{}
	diffValue("", from.Spec, to.Spec, &changes)
	kind := to.Kind
	if kind == "" {
		kind = from.Kind
	}
	seen := map[string]bool{}
	highlights := []string{}
	for i := range changes {
		changes[i].Highlight = classifyHighlight(kind, changes[i].Path)
		if h := changes[i].Highlight; h != "" && !seen[h] {
			seen[h] = true
			highlights = append(highlights, h)
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return RevisionDiff{
		ClusterID:  to.ClusterID,
		Kind:       kind,
		Namespace:  to.Namespace,
		Name:       to.Name,
		FromID:     from.ID,
		ToID:       to.ID,
		FromAt:     from.ObservedAt,
		ToAt:       to.ObservedAt,
		Changes:    changes,
		Highlights: highlights,
	}
}

func diffValue(path string, a, b any, out *[]FieldChange) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		for _, k := range ordered {
			diffValue(joinPath(path, k), am[k], bm[k], out)
		}
		return
	}
	as, aok := a.([]any)
	bs, bok := b.([]any)
	if aok && bok {
		n := len(as)
		if len(bs) > n {
			n = len(bs)
		}
		for i := 0; i < n; i++ {
			var av, bv any
			if i < len(as) {
				av = as[i]
			}
			if i < len(bs) {
				bv = bs[i]
			}
			diffValue(fmt.Sprintf("%s[%d]", path, i), av, bv, out)
		}
		return
	}
	if reflect.DeepEqual(a, b) {
		return
	}
	kind := "changed"
	if a == nil {
		kind = "added"
	} else if b == nil {
		kind = "removed"
	}
	*out = append(*out, FieldChange{Path: path, Old: formatValue(a), New: formatValue(b), Kind: kind})
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func formatValue(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// JSON numbers decode to float64; render integers without a trailing ".0".
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		return fmt.Sprintf("%t", t)
	case map[string]any, []any:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// classifyHighlight tags a JSON path with the acceptance-criteria category it belongs to.
func classifyHighlight(kind, path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "replicas"):
		return "replica"
	case strings.HasSuffix(p, ".image") || p == "image":
		return "image"
	case strings.Contains(p, ".env[") || strings.HasSuffix(p, ".env") || strings.Contains(p, "envfrom"):
		return "env"
	case strings.Contains(p, "resources.limits") || strings.Contains(p, "resources.requests"):
		return "resources"
	case strings.EqualFold(kind, "Ingress") && strings.Contains(p, "host"):
		return "ingress_host"
	}
	return ""
}

// ExtractReplica reads spec.replicas from a workload spec (0 when absent).
func ExtractReplica(spec map[string]any) int {
	switch v := spec["replicas"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return 0
}

// ExtractImages returns the container images referenced by a spec, covering both Pod-style
// (spec.containers) and workload-style (spec.template.spec.containers) shapes.
func ExtractImages(spec map[string]any) []string {
	imgs := []string{}
	add := func(containers any) {
		arr, ok := containers.([]any)
		if !ok {
			return
		}
		for _, c := range arr {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if img, ok := cm["image"].(string); ok && strings.TrimSpace(img) != "" {
				imgs = append(imgs, img)
			}
		}
	}
	add(spec["containers"])
	add(spec["initContainers"])
	if tmpl, ok := spec["template"].(map[string]any); ok {
		if ps, ok := tmpl["spec"].(map[string]any); ok {
			add(ps["containers"])
			add(ps["initContainers"])
		}
	}
	return imgs
}

// ImageSetString returns a stable, comma-separated, de-duplicated image list for quick
// display in revision lists.
func ImageSetString(spec map[string]any) string {
	imgs := ExtractImages(spec)
	if len(imgs) == 0 {
		return ""
	}
	seen := map[string]bool{}
	uniq := []string{}
	for _, img := range imgs {
		if !seen[img] {
			seen[img] = true
			uniq = append(uniq, img)
		}
	}
	sort.Strings(uniq)
	return strings.Join(uniq, ", ")
}
