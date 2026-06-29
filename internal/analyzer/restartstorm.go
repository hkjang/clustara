package analyzer

import (
	"sort"
	"strconv"
	"strings"
)

// Restart Storm detection (POD-RULE-06): when several Pods of the SAME workload are restarting or
// unhealthy at once, it is a service-level problem, not a single-Pod blip. Grouping by owner lets
// the operator (and incident scanner) treat it as one workload incident. Pure over its input.

// RestartStormPod is one Pod's restart signal, mapped from the caller's Pod view.
type RestartStormPod struct {
	Namespace    string
	Name         string
	OwnerKind    string
	OwnerName    string
	RestartCount int
	Unhealthy    bool // crashloop/oom/not-ready/critical band
}

// RestartStorm is a workload where multiple Pods are restarting/unhealthy together.
type RestartStorm struct {
	Namespace     string   `json:"namespace"`
	OwnerKind     string   `json:"owner_kind"`
	OwnerName     string   `json:"owner_name"`
	PodCount      int      `json:"pod_count"`
	AffectedPods  int      `json:"affected_pods"`
	AffectedPct   int      `json:"affected_pct"`
	TotalRestarts int      `json:"total_restarts"`
	Severity      string   `json:"severity"` // high | critical
	Reason        string   `json:"reason"`
	SamplePods    []string `json:"sample_pods"`
}

// RestartStormOptions tunes thresholds. Zero values fall back to sensible defaults.
type RestartStormOptions struct {
	RestartThreshold int // a pod counts as affected at/above this restart count (default 3)
	MinAffected      int // minimum affected pods in a workload to be a storm (default 2)
	CriticalPct      int // affected ratio at/above which the storm is critical (default 50)
}

func (o RestartStormOptions) withDefaults() RestartStormOptions {
	if o.RestartThreshold <= 0 {
		o.RestartThreshold = 3
	}
	if o.MinAffected <= 0 {
		o.MinAffected = 2
	}
	if o.CriticalPct <= 0 {
		o.CriticalPct = 50
	}
	return o
}

// DetectRestartStorms groups pods by owner workload and flags those with multiple
// restarting/unhealthy pods. Pods without an owner are grouped per-pod (so a single bare pod never
// raises a storm). Returned worst-first (critical before high, then by affected ratio).
func DetectRestartStorms(pods []RestartStormPod, opts RestartStormOptions) []RestartStorm {
	opts = opts.withDefaults()

	type agg struct {
		ns, kind, owner       string
		total, affected, rest int
		samples               []string
	}
	groups := map[string]*agg{}
	for _, p := range pods {
		kind, owner := p.OwnerKind, p.OwnerName
		if strings.TrimSpace(owner) == "" {
			// No controller → treat each bare pod as its own group (cannot be a storm alone).
			kind, owner = "Pod", p.Name
		}
		key := p.Namespace + "|" + kind + "|" + owner
		a := groups[key]
		if a == nil {
			a = &agg{ns: p.Namespace, kind: kind, owner: owner}
			groups[key] = a
		}
		a.total++
		a.rest += p.RestartCount
		if p.Unhealthy || p.RestartCount >= opts.RestartThreshold {
			a.affected++
			if len(a.samples) < 5 {
				a.samples = append(a.samples, p.Name)
			}
		}
	}

	out := []RestartStorm{}
	for _, a := range groups {
		if a.affected < opts.MinAffected {
			continue
		}
		pct := 0
		if a.total > 0 {
			pct = a.affected * 100 / a.total
		}
		severity := "high"
		if pct >= opts.CriticalPct {
			severity = "critical"
		}
		out = append(out, RestartStorm{
			Namespace: a.ns, OwnerKind: a.kind, OwnerName: a.owner,
			PodCount: a.total, AffectedPods: a.affected, AffectedPct: pct, TotalRestarts: a.rest,
			Severity: severity, SamplePods: a.samples,
			Reason: a.kind + "/" + a.owner + " 워크로드에서 " + strconv.Itoa(a.affected) + "/" + strconv.Itoa(a.total) +
				" Pod가 재시작/비정상 (" + strconv.Itoa(pct) + "%) — 단일 Pod가 아닌 서비스 장애로 판단",
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Severity == "critical") != (out[j].Severity == "critical") {
			return out[i].Severity == "critical"
		}
		if out[i].AffectedPct != out[j].AffectedPct {
			return out[i].AffectedPct > out[j].AffectedPct
		}
		return out[i].AffectedPods > out[j].AffectedPods
	})
	return out
}

// BuildRestartStormIncidents turns critical restart storms into workload-level incident drafts so a
// service-wide restart wave opens one incident on the owner (not N pod incidents). High storms stay
// as list warnings. Deduplicated per workload. Pure builder.
func BuildRestartStormIncidents(storms []RestartStorm, clusterID string) []IncidentDraft {
	out := []IncidentDraft{}
	for _, s := range storms {
		if s.Severity != "critical" {
			continue
		}
		key := clusterID + "|" + s.Namespace + "|" + s.OwnerKind + "|" + s.OwnerName + "|RestartStorm"
		ev := []string{s.Reason}
		if len(s.SamplePods) > 0 {
			ev = append(ev, "영향 Pod: "+strings.Join(s.SamplePods, ", "))
		}
		ev = append(ev, "총 재시작 "+strconv.Itoa(s.TotalRestarts)+"회")
		out = append(out, IncidentDraft{
			Key: key, ClusterID: clusterID, Namespace: s.Namespace, Kind: s.OwnerKind, Name: s.OwnerName,
			Condition: "RestartStorm", Severity: "critical",
			Title:    "RestartStorm — " + nsName(s.Namespace) + s.OwnerKind + "/" + s.OwnerName,
			Evidence: ev,
		})
	}
	return out
}
