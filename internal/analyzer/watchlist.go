package analyzer

import "strings"

// Watch List evaluation: match an operator's standing watches against the current workload health
// roll-up so important services surface their risk without scanning the full pod list. Pure.

// WatchTarget is one watch's matching criteria (owner empty = whole namespace).
type WatchTarget struct {
	ID        string
	ClusterID string
	Namespace string
	OwnerKind string
	OwnerName string
	Note      string
}

// WatchStatus is the current health of a watched target, derived from matching workload groups.
type WatchStatus struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	Namespace     string `json:"namespace"`
	OwnerKind     string `json:"owner_kind"`
	OwnerName     string `json:"owner_name"`
	Note          string `json:"note"`
	Matched       int    `json:"matched_workloads"`
	PodCount      int    `json:"pod_count"`
	CriticalPods  int    `json:"critical_pods"`
	WarningPods   int    `json:"warning_pods"`
	TotalRestarts int    `json:"total_restarts"`
	MinHealth     int    `json:"min_health"`
	WorstSymptom  string `json:"worst_symptom"`
	Band          string `json:"band"` // critical | warning | healthy | unknown (no match)
}

// EvaluateWatchTargets rolls each watch up against the current workload groups. A watch matches a
// group when the namespace matches and (owner unset, or owner kind+name match). Worst band wins.
func EvaluateWatchTargets(watches []WatchTarget, workloads []WorkloadGroup) []WatchStatus {
	out := make([]WatchStatus, 0, len(watches))
	bandRank := map[string]int{"critical": 0, "warning": 1, "healthy": 2}
	for _, wtch := range watches {
		st := WatchStatus{
			ID: wtch.ID, ClusterID: wtch.ClusterID, Namespace: wtch.Namespace, OwnerKind: wtch.OwnerKind, OwnerName: wtch.OwnerName,
			Note: wtch.Note, Band: "unknown", MinHealth: 100,
		}
		worstBandRank := 3
		worstSymRank := len(podSymptomRules) + 1
		minHealthInit := false
		for _, g := range workloads {
			if g.Namespace != wtch.Namespace {
				continue
			}
			if wtch.OwnerName != "" && !(strings.EqualFold(g.OwnerKind, wtch.OwnerKind) && g.OwnerName == wtch.OwnerName) {
				continue
			}
			st.Matched++
			st.PodCount += g.PodCount
			st.CriticalPods += g.CriticalPods
			st.WarningPods += g.WarningPods
			st.TotalRestarts += g.TotalRestarts
			if !minHealthInit || g.MinHealth < st.MinHealth {
				st.MinHealth = g.MinHealth
				minHealthInit = true
			}
			if r := bandRank[g.Band]; r < worstBandRank {
				worstBandRank = r
				st.Band = g.Band
			}
			if g.WorstSymptom != "" {
				if r := symptomPriority(g.WorstSymptom); r < worstSymRank {
					worstSymRank = r
					st.WorstSymptom = g.WorstSymptom
				}
			}
		}
		if st.Matched == 0 {
			st.MinHealth = 0
		}
		out = append(out, st)
	}
	return out
}
