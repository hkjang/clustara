package analyzer

import (
	"sort"
	"strings"

	"clustara/internal/store"
)

// Config impact: before changing a ConfigMap/Secret, find which workloads consume it (env, envFrom,
// or volume mount) and whether a restart is needed to pick up the change — the blast radius of a
// config/secret edit (CFG-REQ-04). Pure over the inventory.
//
// Restart semantics: env/envFrom values are injected at start, so a change needs a Pod restart;
// volume-mounted ConfigMaps/Secrets update in place (subPath aside), so they may not require one.

// ConfigImpactEntry is one workload that references the config/secret.
type ConfigImpactEntry struct {
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Via       []string `json:"via"` // env | envFrom | volume
}

// ConfigImpactReport summarizes the blast radius of a config/secret change.
type ConfigImpactReport struct {
	SourceKind       string              `json:"source_kind"`
	SourceName       string              `json:"source_name"`
	Workloads        []ConfigImpactEntry `json:"workloads"`
	Count            int                 `json:"count"`
	RestartNeeded    int                 `json:"restart_needed"`   // workloads consuming via env/envFrom
	RestartRecommend bool                `json:"restart_recommend"`
}

// AnalyzeConfigImpact finds the workloads referencing the given ConfigMap/Secret. sourceKind is
// "ConfigMap" or "Secret". Pure.
func AnalyzeConfigImpact(items []store.K8sInventoryItem, sourceKind, sourceName string) ConfigImpactReport {
	rep := ConfigImpactReport{SourceKind: sourceKind, SourceName: sourceName, Workloads: []ConfigImpactEntry{}}
	isSecret := strings.EqualFold(sourceKind, "Secret")
	for _, it := range items {
		ps := podSpecOf(it)
		if ps == nil {
			continue
		}
		viaSet := map[string]bool{}
		// Containers: env (valueFrom) + envFrom.
		for _, raw := range append(asAnySlice(ps["initContainers"]), asAnySlice(ps["containers"])...) {
			c := asAnyMap(raw)
			for _, ev := range asAnySlice(c["env"]) {
				vf := asAnyMap(asAnyMap(ev)["valueFrom"])
				ref := asAnyMap(vf["configMapKeyRef"])
				if isSecret {
					ref = asAnyMap(vf["secretKeyRef"])
				}
				if str(ref["name"]) == sourceName {
					viaSet["env"] = true
				}
			}
			for _, ef := range asAnySlice(c["envFrom"]) {
				f := asAnyMap(ef)
				ref := asAnyMap(f["configMapRef"])
				if isSecret {
					ref = asAnyMap(f["secretRef"])
				}
				if str(ref["name"]) == sourceName {
					viaSet["envFrom"] = true
				}
			}
		}
		// Volumes.
		for _, vol := range asAnySlice(ps["volumes"]) {
			v := asAnyMap(vol)
			if isSecret {
				if str(asAnyMap(v["secret"])["secretName"]) == sourceName {
					viaSet["volume"] = true
				}
			} else {
				if str(asAnyMap(v["configMap"])["name"]) == sourceName {
					viaSet["volume"] = true
				}
			}
		}
		if len(viaSet) == 0 {
			continue
		}
		via := make([]string, 0, len(viaSet))
		for k := range viaSet {
			via = append(via, k)
		}
		sort.Strings(via)
		rep.Workloads = append(rep.Workloads, ConfigImpactEntry{Namespace: it.Namespace, Kind: it.Kind, Name: it.Name, Via: via})
		if viaSet["env"] || viaSet["envFrom"] {
			rep.RestartNeeded++
		}
	}
	rep.Count = len(rep.Workloads)
	rep.RestartRecommend = rep.RestartNeeded > 0
	sort.SliceStable(rep.Workloads, func(i, j int) bool {
		return rep.Workloads[i].Namespace+rep.Workloads[i].Kind+rep.Workloads[i].Name < rep.Workloads[j].Namespace+rep.Workloads[j].Kind+rep.Workloads[j].Name
	})
	return rep
}
