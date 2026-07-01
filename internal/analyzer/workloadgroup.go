package analyzer

import "sort"

// Workload grouping: roll Pod-level health up to the owning workload (ReplicaSet/StatefulSet/
// DaemonSet/Job) so a cluster with many pods stays readable — the operator scans workloads, not
// hundreds of pods. Pure over its input.

// WorkloadPod is one Pod's roll-up signal, mapped from the caller's Pod view.
type WorkloadPod struct {
	Namespace          string
	OwnerKind          string
	OwnerName          string
	Name               string
	HealthScore        int
	HealthBand         string // healthy | warning | critical
	PrimarySymptom     string
	RestartCount       int
	RecentRestartCount int
	Ready              bool
	Resources          ResourceTags // container CPU/mem requests+limits (replicas share the template)
}

// WorkloadGroup is the aggregated health of one owning workload.
type WorkloadGroup struct {
	Namespace      string       `json:"namespace"`
	OwnerKind      string       `json:"owner_kind"`
	OwnerName      string       `json:"owner_name"`
	PodCount       int          `json:"pod_count"`
	ReadyPods      int          `json:"ready_pods"`
	HealthyPods    int          `json:"healthy_pods"`
	WarningPods    int          `json:"warning_pods"`
	CriticalPods   int          `json:"critical_pods"`
	TotalRestarts  int          `json:"total_restarts"`
	RecentRestarts int          `json:"recent_restarts"`
	MinHealth      int          `json:"min_health"` // worst pod's score
	AvgHealth      int          `json:"avg_health"`
	WorstSymptom   string       `json:"worst_symptom"`
	Band           string       `json:"band"`        // worst band among member pods
	Resources      ResourceTags `json:"resources"`   // representative container requests+limits
	SamplePods     []string     `json:"sample_pods"` // member pod names (worst-health first), for deep-links
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
	type sampleMember struct {
		name   string
		health int
	}
	type agg struct {
		g          WorkloadGroup
		sumHealth  int
		worstRank  int
		worstSympt string
		minInit    bool
		resSet     bool
		members    []sampleMember
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
		a.g.RecentRestarts += p.RecentRestartCount
		a.sumHealth += p.HealthScore
		a.members = append(a.members, sampleMember{name: p.Name, health: p.HealthScore})
		// Replicas share a pod template, so any member's resources represent the workload; prefer
		// the first member that actually declares resources.
		if !a.resSet || (!a.g.Resources.HasReq && !a.g.Resources.HasLim) {
			if p.Resources.HasReq || p.Resources.HasLim || !a.resSet {
				a.g.Resources = p.Resources
				a.resSet = true
			}
		}
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
		// Sample pod names, worst-health first, for Pod-detail deep-links (cap 5).
		sort.SliceStable(a.members, func(i, j int) bool { return a.members[i].health < a.members[j].health })
		a.g.SamplePods = []string{}
		for i, m := range a.members {
			if i >= 5 {
				break
			}
			a.g.SamplePods = append(a.g.SamplePods, m.name)
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
