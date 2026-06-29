package analyzer

import "sort"

// Workload grouping: roll Pod-level health up to the owning workload (ReplicaSet/StatefulSet/
// DaemonSet/Job) so a cluster with many pods stays readable — the operator scans workloads, not
// hundreds of pods. Pure over its input.

// WorkloadPod is one Pod's roll-up signal, mapped from the caller's Pod view.
type WorkloadPod struct {
	Namespace      string
	OwnerKind      string
	OwnerName      string
	Name           string
	HealthScore    int
	HealthBand     string // healthy | warning | critical
	PrimarySymptom string
	RestartCount   int
	Ready          bool
}

// WorkloadGroup is the aggregated health of one owning workload.
type WorkloadGroup struct {
	Namespace     string `json:"namespace"`
	OwnerKind     string `json:"owner_kind"`
	OwnerName     string `json:"owner_name"`
	PodCount      int    `json:"pod_count"`
	ReadyPods     int    `json:"ready_pods"`
	HealthyPods   int    `json:"healthy_pods"`
	WarningPods   int    `json:"warning_pods"`
	CriticalPods  int    `json:"critical_pods"`
	TotalRestarts int    `json:"total_restarts"`
	MinHealth     int    `json:"min_health"` // worst pod's score
	AvgHealth     int    `json:"avg_health"`
	WorstSymptom  string `json:"worst_symptom"`
	Band          string `json:"band"` // worst band among member pods
}

// symptomPriority returns a rank for a primary symptom (lower = more severe); -1 for none/healthy.
func symptomPriority(tag string) int {
	for i, r := range podSymptomRules {
		if r.tag == tag {
			return i
		}
	}
	return len(podSymptomRules) // unknown/degraded ranks after known symptoms but before "none"
}

// BuildWorkloadGroups aggregates pods by owning workload, worst-first (critical → warning →
// healthy, then by lowest member health). Pods without an owner are grouped per-pod.
func BuildWorkloadGroups(pods []WorkloadPod) []WorkloadGroup {
	type agg struct {
		g          WorkloadGroup
		sumHealth  int
		worstRank  int
		worstSympt string
		minInit    bool
	}
	groups := map[string]*agg{}
	order := []string{}
	for _, p := range pods {
		kind, owner := p.OwnerKind, p.OwnerName
		if owner == "" {
			kind, owner = "Pod", p.Name
		}
		key := p.Namespace + "|" + kind + "|" + owner
		a := groups[key]
		if a == nil {
			a = &agg{g: WorkloadGroup{Namespace: p.Namespace, OwnerKind: kind, OwnerName: owner}, worstRank: len(podSymptomRules) + 1, minInit: false}
			groups[key] = a
			order = append(order, key)
		}
		a.g.PodCount++
		a.g.TotalRestarts += p.RestartCount
		a.sumHealth += p.HealthScore
		if !a.minInit || p.HealthScore < a.g.MinHealth {
			a.g.MinHealth = p.HealthScore
			a.minInit = true
		}
		if p.Ready {
			a.g.ReadyPods++
		}
		switch p.HealthBand {
		case "critical":
			a.g.CriticalPods++
		case "warning":
			a.g.WarningPods++
		default:
			a.g.HealthyPods++
		}
		if rank := symptomPriority(p.PrimarySymptom); p.PrimarySymptom != "" && p.PrimarySymptom != "Healthy" && rank < a.worstRank {
			a.worstRank = rank
			a.worstSympt = p.PrimarySymptom
		}
	}

	out := make([]WorkloadGroup, 0, len(groups))
	for _, key := range order {
		a := groups[key]
		if a.g.PodCount > 0 {
			a.g.AvgHealth = a.sumHealth / a.g.PodCount
		}
		a.g.WorstSymptom = a.worstSympt
		switch {
		case a.g.CriticalPods > 0:
			a.g.Band = "critical"
		case a.g.WarningPods > 0:
			a.g.Band = "warning"
		default:
			a.g.Band = "healthy"
		}
		out = append(out, a.g)
	}

	bandRank := map[string]int{"critical": 0, "warning": 1, "healthy": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if bandRank[out[i].Band] != bandRank[out[j].Band] {
			return bandRank[out[i].Band] < bandRank[out[j].Band]
		}
		return out[i].MinHealth < out[j].MinHealth
	})
	return out
}
