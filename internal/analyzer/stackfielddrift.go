package analyzer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"clustara/internal/store"
)

// Field-level Stack drift (CLU-REQ-07): beyond existence (present/missing), compare the declared
// manifest spec against the live cluster object field-by-field — image, replicas, env, resources,
// probes, labels, annotations — so GitOps drift shows WHAT changed, not just whether the resource
// exists. Pure over decoded manifest docs + the stored live inventory.

// StackFieldDiff is one declared-vs-live field difference.
type StackFieldDiff struct {
	Path     string `json:"path"`     // e.g. "spec.replicas", "containers[web].image"
	Declared string `json:"declared"` // declared (desired) value
	Live     string `json:"live"`     // live (actual) value
	Type     string `json:"type"`     // modified | missing_in_live | extra_in_live
}

// StackFieldDriftEntry is one declared resource with its field-level diffs.
type StackFieldDriftEntry struct {
	Kind      string           `json:"kind"`
	Namespace string           `json:"namespace"`
	Name      string           `json:"name"`
	Status    string           `json:"status"` // present | missing
	Diffs     []StackFieldDiff `json:"diffs"`
}

// StackFieldDriftReport summarizes field-level drift across a stack.
type StackFieldDriftReport struct {
	Entries  []StackFieldDriftEntry `json:"entries"`
	Declared int                    `json:"declared"`
	Present  int                    `json:"present"`
	Missing  int                    `json:"missing"`
	Drifted  int                    `json:"drifted"` // present resources with ≥1 field diff
	Synced   bool                   `json:"synced"`  // all present and zero field diffs
}

// DetectStackFieldDrift compares each declared manifest document against the matching live inventory
// item and reports field-level differences. Resources absent from the cluster are status=missing
// (no field diff). Pure.
func DetectStackFieldDrift(docs []map[string]any, defaultNamespace string, inventory []store.K8sInventoryItem) StackFieldDriftReport {
	live := map[string]store.K8sInventoryItem{}
	for _, it := range inventory {
		live[invKey(it.Kind, it.Namespace, it.Name)] = it
	}
	rep := StackFieldDriftReport{Entries: []StackFieldDriftEntry{}}
	for _, doc := range docs {
		kind := strings.TrimSpace(str(doc["kind"]))
		meta := asAnyMap(doc["metadata"])
		name := strings.TrimSpace(str(meta["name"]))
		if kind == "" || name == "" {
			continue
		}
		ns := strings.TrimSpace(str(meta["namespace"]))
		if ns == "" {
			ns = defaultNamespace
		}
		entry := StackFieldDriftEntry{Kind: kind, Namespace: ns, Name: name, Diffs: []StackFieldDiff{}}
		item, ok := live[invKey(kind, ns, name)]
		if !ok {
			entry.Status = "missing"
			rep.Missing++
			rep.Entries = append(rep.Entries, entry)
			continue
		}
		entry.Status = "present"
		rep.Present++
		entry.Diffs = diffResource(doc, item)
		if len(entry.Diffs) > 0 {
			rep.Drifted++
		}
		rep.Entries = append(rep.Entries, entry)
	}
	rep.Declared = len(rep.Entries)
	rep.Synced = rep.Missing == 0 && rep.Drifted == 0 && rep.Declared > 0
	sort.SliceStable(rep.Entries, func(i, j int) bool {
		ri, rj := rep.Entries[i], rep.Entries[j]
		// missing first, then drifted, then synced.
		rank := func(e StackFieldDriftEntry) int {
			if e.Status == "missing" {
				return 0
			}
			if len(e.Diffs) > 0 {
				return 1
			}
			return 2
		}
		if rank(ri) != rank(rj) {
			return rank(ri) < rank(rj)
		}
		return ri.Kind+ri.Name < rj.Kind+rj.Name
	})
	return rep
}

// diffResource computes field-level diffs for one declared doc vs its live inventory item.
func diffResource(doc map[string]any, item store.K8sInventoryItem) []StackFieldDiff {
	diffs := []StackFieldDiff{}
	declSpec := asAnyMap(doc["spec"])
	liveSpec := item.Spec

	// replicas (workloads)
	if dv, ok := intField(declSpec, "replicas"); ok {
		lv, _ := intField(liveSpec, "replicas")
		if dv != lv {
			diffs = append(diffs, StackFieldDiff{Path: "spec.replicas", Declared: fmt.Sprintf("%d", dv), Live: fmt.Sprintf("%d", lv), Type: "modified"})
		}
	}

	// containers (by name): image, env, resources, probes
	declC := containersByName(declSpec)
	liveC := containersByName(liveSpec)
	names := sortedContainerKeys(declC)
	for _, cn := range names {
		dc := declC[cn]
		lc, present := liveC[cn]
		if !present {
			diffs = append(diffs, StackFieldDiff{Path: "containers[" + cn + "]", Declared: "declared", Live: "", Type: "missing_in_live"})
			continue
		}
		if di, li := str(dc["image"]), str(lc["image"]); di != li {
			diffs = append(diffs, StackFieldDiff{Path: "containers[" + cn + "].image", Declared: di, Live: li, Type: "modified"})
		}
		if de, le := canonicalEnv(dc["env"]), canonicalEnv(lc["env"]); de != le {
			diffs = append(diffs, StackFieldDiff{Path: "containers[" + cn + "].env", Declared: de, Live: le, Type: "modified"})
		}
		if dr, lr := canonicalJSON(dc["resources"]), canonicalJSON(lc["resources"]); dr != lr {
			diffs = append(diffs, StackFieldDiff{Path: "containers[" + cn + "].resources", Declared: dr, Live: lr, Type: "modified"})
		}
		for _, probe := range []string{"readinessProbe", "livenessProbe", "startupProbe"} {
			if dp, lp := canonicalJSON(dc[probe]), canonicalJSON(lc[probe]); dp != lp {
				diffs = append(diffs, StackFieldDiff{Path: "containers[" + cn + "]." + probe, Declared: dp, Live: lp, Type: "modified"})
			}
		}
	}

	// labels + annotations (only declared keys; cluster adds many controller-managed ones)
	diffs = append(diffs, diffStringMap("labels", declaredStringMap(doc, "labels"), item.Labels)...)
	diffs = append(diffs, diffStringMap("annotations", declaredStringMap(doc, "annotations"), item.Annotations)...)
	return diffs
}

func diffStringMap(prefix string, declared, live map[string]string) []StackFieldDiff {
	out := []StackFieldDiff{}
	for _, k := range sortedStringKeys(declared) {
		dv := declared[k]
		lv, ok := live[k]
		if !ok {
			out = append(out, StackFieldDiff{Path: prefix + "[" + k + "]", Declared: dv, Live: "", Type: "missing_in_live"})
		} else if dv != lv {
			out = append(out, StackFieldDiff{Path: prefix + "[" + k + "]", Declared: dv, Live: lv, Type: "modified"})
		}
	}
	return out
}

// containersByName returns spec.template.spec.containers (workloads) or spec.containers (bare Pod)
// keyed by container name.
func containersByName(spec map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	var list []any
	if tmpl := asAnyMap(spec["template"]); len(tmpl) > 0 {
		if podSpec := asAnyMap(tmpl["spec"]); len(podSpec) > 0 {
			list = asAnySlice(podSpec["containers"])
		}
	}
	if list == nil {
		list = asAnySlice(spec["containers"])
	}
	for _, c := range list {
		cm := asAnyMap(c)
		name := strings.TrimSpace(str(cm["name"]))
		if name != "" {
			out[name] = cm
		}
	}
	return out
}

// canonicalEnv renders an env list as a stable sorted "NAME=VALUE" string for comparison.
func canonicalEnv(v any) string {
	list := asAnySlice(v)
	if len(list) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(list))
	for _, e := range list {
		em := asAnyMap(e)
		name := str(em["name"])
		val := str(em["value"])
		if _, ok := em["valueFrom"]; ok && val == "" {
			val = canonicalJSON(em["valueFrom"])
		}
		pairs = append(pairs, name+"="+val)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ";")
}

func canonicalJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	if string(b) == "null" || string(b) == "{}" {
		return ""
	}
	return string(b)
}

func declaredStringMap(doc map[string]any, key string) map[string]string {
	meta := asAnyMap(doc["metadata"])
	raw := asAnyMap(meta[key])
	out := map[string]string{}
	for k, v := range raw {
		out[k] = str(v)
	}
	return out
}

func intField(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

func sortedContainerKeys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
