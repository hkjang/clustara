package analyzer

import (
	"sort"
	"strings"

	"clustara/internal/store"
)

// Stack drift: compare a saved Application Stack's declared resources (desired state) against the
// live inventory (actual state) to surface what the manifest declares but the cluster is missing —
// the existence-level GitOps drift signal (GIT-REQ-05). Pure; deeper field-diff is future work.

// StackDriftEntry is one declared resource's presence in the cluster.
type StackDriftEntry struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Status    string `json:"status"` // present | missing
}

// StackDriftReport summarizes drift between declared and live state.
type StackDriftReport struct {
	Entries  []StackDriftEntry `json:"entries"`
	Declared int               `json:"declared"`
	Present  int               `json:"present"`
	Missing  int               `json:"missing"`
	Synced   bool              `json:"synced"`
}

// DetectStackDrift checks each declared resource against the inventory by (kind, namespace, name).
// When a declared resource omits a namespace, the stack's default namespace is used. Pure.
func DetectStackDrift(resources []StackResource, defaultNamespace string, inventory []store.K8sInventoryItem) StackDriftReport {
	live := map[string]bool{}
	for _, it := range inventory {
		live[invKey(it.Kind, it.Namespace, it.Name)] = true
	}
	rep := StackDriftReport{Entries: []StackDriftEntry{}}
	for _, r := range resources {
		ns := r.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		status := "missing"
		if live[invKey(r.Kind, ns, r.Name)] {
			status = "present"
			rep.Present++
		} else {
			rep.Missing++
		}
		rep.Entries = append(rep.Entries, StackDriftEntry{Kind: r.Kind, Namespace: ns, Name: r.Name, Status: status})
	}
	rep.Declared = len(rep.Entries)
	rep.Synced = rep.Missing == 0 && rep.Declared > 0
	sort.SliceStable(rep.Entries, func(i, j int) bool {
		if (rep.Entries[i].Status == "missing") != (rep.Entries[j].Status == "missing") {
			return rep.Entries[i].Status == "missing" // missing first
		}
		return rep.Entries[i].Kind+rep.Entries[i].Name < rep.Entries[j].Kind+rep.Entries[j].Name
	})
	return rep
}

func invKey(kind, namespace, name string) string {
	return strings.ToLower(kind) + "|" + namespace + "|" + name
}
