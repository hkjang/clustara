package analyzer

import "sort"

// API Compatibility Radar (CLU-DISC-12).
//
// Two capabilities over the discovered API catalog: (1) flag deprecated/removed API group-versions
// present in a cluster (upgrade-readiness — "what breaks when you upgrade"), using a built-in table
// of well-known Kubernetes removals; (2) diff two catalogs (two clusters, or before/after) into
// added / removed / changed resources. Pure.

// deprecatedGV maps a deprecated/removed API group-version to the Kubernetes release that removed it
// and the recommended replacement. Keyed by "group/version" ("" group is core, never deprecated).
var deprecatedGV = map[string]struct {
	removedIn   string
	replacement string
}{
	"extensions/v1beta1":                  {"1.16", "apps/v1, networking.k8s.io/v1, policy/v1"},
	"apps/v1beta1":                        {"1.16", "apps/v1"},
	"apps/v1beta2":                        {"1.16", "apps/v1"},
	"networking.k8s.io/v1beta1":           {"1.22", "networking.k8s.io/v1"},
	"rbac.authorization.k8s.io/v1beta1":   {"1.22", "rbac.authorization.k8s.io/v1"},
	"apiextensions.k8s.io/v1beta1":        {"1.22", "apiextensions.k8s.io/v1"},
	"admissionregistration.k8s.io/v1beta1": {"1.22", "admissionregistration.k8s.io/v1"},
	"certificates.k8s.io/v1beta1":         {"1.22", "certificates.k8s.io/v1"},
	"coordination.k8s.io/v1beta1":         {"1.22", "coordination.k8s.io/v1"},
	"policy/v1beta1":                      {"1.25", "policy/v1 (PodSecurityPolicy removed)"},
	"batch/v1beta1":                       {"1.25", "batch/v1"},
	"discovery.k8s.io/v1beta1":            {"1.25", "discovery.k8s.io/v1"},
	"events.k8s.io/v1beta1":               {"1.25", "events.k8s.io/v1"},
	"autoscaling/v2beta1":                 {"1.25", "autoscaling/v2"},
	"autoscaling/v2beta2":                 {"1.26", "autoscaling/v2"},
	"flowcontrol.apiserver.k8s.io/v1beta1": {"1.29", "flowcontrol.apiserver.k8s.io/v1"},
	"flowcontrol.apiserver.k8s.io/v1beta2": {"1.29", "flowcontrol.apiserver.k8s.io/v1"},
	"flowcontrol.apiserver.k8s.io/v1beta3": {"1.32", "flowcontrol.apiserver.k8s.io/v1"},
}

// DeprecatedAPI is one deprecated/removed group-version present in the cluster.
type DeprecatedAPI struct {
	GroupVersion string   `json:"group_version"`
	RemovedIn    string   `json:"removed_in"`
	Replacement  string   `json:"replacement"`
	Resources    []string `json:"resources"` // resources served under this GV
	Severity     string   `json:"severity"`  // warning (deprecated, still served)
}

// DetectDeprecatedAPIs flags catalog group-versions that match the built-in removal table.
func DetectDeprecatedAPIs(resources []APIResourceInfo) []DeprecatedAPI {
	byGV := map[string][]string{}
	order := []string{}
	for _, r := range resources {
		gv := r.GroupVersion()
		if _, ok := deprecatedGV[gv]; !ok {
			continue
		}
		if _, seen := byGV[gv]; !seen {
			order = append(order, gv)
		}
		byGV[gv] = append(byGV[gv], r.Resource)
	}
	out := []DeprecatedAPI{}
	for _, gv := range order {
		info := deprecatedGV[gv]
		res := byGV[gv]
		sort.Strings(res)
		out = append(out, DeprecatedAPI{
			GroupVersion: gv, RemovedIn: info.removedIn, Replacement: info.replacement,
			Resources: res, Severity: "warning",
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GroupVersion < out[j].GroupVersion })
	return out
}

// APICatalogDiff is the difference between two API catalogs.
type APICatalogDiff struct {
	AddedResources   []string `json:"added_resources"`   // "gv/resource" present in `to` not `from`
	RemovedResources []string `json:"removed_resources"` // present in `from` not `to`
	ChangedResources []string `json:"changed_resources"` // verb set changed
	AddedCount       int      `json:"added_count"`
	RemovedCount     int      `json:"removed_count"`
	ChangedCount     int      `json:"changed_count"`
}

// DiffAPICatalogs compares two resource catalogs (e.g. two clusters or pre/post upgrade).
func DiffAPICatalogs(from, to []APIResourceInfo) APICatalogDiff {
	key := func(r APIResourceInfo) string { return r.GroupVersion() + "/" + r.Resource }
	fromMap := map[string]string{} // key → sorted verbs
	toMap := map[string]string{}
	for _, r := range from {
		fromMap[key(r)] = joinSortedVerbs(r.Verbs)
	}
	for _, r := range to {
		toMap[key(r)] = joinSortedVerbs(r.Verbs)
	}
	d := APICatalogDiff{AddedResources: []string{}, RemovedResources: []string{}, ChangedResources: []string{}}
	for k, toVerbs := range toMap {
		if fromVerbs, ok := fromMap[k]; !ok {
			d.AddedResources = append(d.AddedResources, k)
		} else if fromVerbs != toVerbs {
			d.ChangedResources = append(d.ChangedResources, k)
		}
	}
	for k := range fromMap {
		if _, ok := toMap[k]; !ok {
			d.RemovedResources = append(d.RemovedResources, k)
		}
	}
	sort.Strings(d.AddedResources)
	sort.Strings(d.RemovedResources)
	sort.Strings(d.ChangedResources)
	d.AddedCount, d.RemovedCount, d.ChangedCount = len(d.AddedResources), len(d.RemovedResources), len(d.ChangedResources)
	return d
}

func joinSortedVerbs(verbs []string) string {
	v := append([]string(nil), verbs...)
	sort.Strings(v)
	out := ""
	for i, x := range v {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}
