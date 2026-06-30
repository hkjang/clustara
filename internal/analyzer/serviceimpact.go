package analyzer

import "sort"

// Service Impact Home (CLU-REQ-07).
//
// Lifts the Pod-centric list up to a service-centric one: each card is a workload with its pod
// health rolled up plus the things that determine its blast radius — the Services routing to it,
// Ingresses exposing it, the HPA scaling it, recent config/spec changes, and open incidents. The
// handler does the Kubernetes-spec matching (selector→pod labels, ingress→service, hpa→workload)
// and passes the enrichment in by workload key; this assembles + ranks. Pure.

// HPASummary is the autoscaler attached to a workload.
type HPASummary struct {
	Name        string `json:"name"`
	MinReplicas int    `json:"min_replicas"`
	MaxReplicas int    `json:"max_replicas"`
	Current     int    `json:"current_replicas"`
	AtMax       bool   `json:"at_max"`
}

// ServiceEnrichment is the per-workload context the handler resolves from inventory.
type ServiceEnrichment struct {
	Services      []string    `json:"services"`
	Ingresses     []string    `json:"ingresses"`
	HPA           *HPASummary `json:"hpa,omitempty"`
	OpenIncidents int         `json:"open_incidents"`
	RecentChanges int         `json:"recent_changes"`
}

// ServiceCard is one service-centric row.
type ServiceCard struct {
	Namespace     string      `json:"namespace"`
	Workload      string      `json:"workload"`
	Kind          string      `json:"kind"`
	Band          string      `json:"band"`     // pod health band: healthy|warning|critical
	Severity      string      `json:"severity"` // overall: critical|warning|ok (health + incidents + changes)
	PodCount      int         `json:"pod_count"`
	ReadyPods     int         `json:"ready_pods"`
	CriticalPods  int         `json:"critical_pods"`
	WarningPods   int         `json:"warning_pods"`
	TotalRestarts int         `json:"total_restarts"`
	WorstSymptom  string      `json:"worst_symptom"`
	Services      []string    `json:"services"`
	Ingresses     []string    `json:"ingresses"`
	HPA           *HPASummary `json:"hpa,omitempty"`
	OpenIncidents int         `json:"open_incidents"`
	RecentChanges int         `json:"recent_changes"`
	Exposed       bool        `json:"exposed"` // has an Ingress (internet-facing blast radius)
	SamplePods    []string    `json:"sample_pods"`
}

// WorkloadImpactKey is the stable key joining a WorkloadGroup to its enrichment.
func WorkloadImpactKey(namespace, kind, workload string) string {
	return namespace + "|" + kind + "|" + workload
}

// AssembleServiceCards joins workload health with per-workload enrichment into ranked service cards.
func AssembleServiceCards(groups []WorkloadGroup, enrich map[string]ServiceEnrichment) []ServiceCard {
	out := make([]ServiceCard, 0, len(groups))
	for _, g := range groups {
		e := enrich[WorkloadImpactKey(g.Namespace, g.OwnerKind, g.OwnerName)]
		card := ServiceCard{
			Namespace: g.Namespace, Workload: g.OwnerName, Kind: g.OwnerKind, Band: g.Band,
			PodCount: g.PodCount, ReadyPods: g.ReadyPods, CriticalPods: g.CriticalPods,
			WarningPods: g.WarningPods, TotalRestarts: g.TotalRestarts, WorstSymptom: g.WorstSymptom,
			Services: nonNil(e.Services), Ingresses: nonNil(e.Ingresses), HPA: e.HPA,
			OpenIncidents: e.OpenIncidents, RecentChanges: e.RecentChanges,
			Exposed: len(e.Ingresses) > 0, SamplePods: g.SamplePods,
		}
		card.Severity = serviceSeverity(card)
		out = append(out, card)
	}
	rank := map[string]int{"critical": 0, "warning": 1, "ok": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		// Within a band, exposed services and those with more open incidents sort first.
		if out[i].Exposed != out[j].Exposed {
			return out[i].Exposed
		}
		if out[i].OpenIncidents != out[j].OpenIncidents {
			return out[i].OpenIncidents > out[j].OpenIncidents
		}
		return out[i].Namespace+out[i].Workload < out[j].Namespace+out[j].Workload
	})
	return out
}

// serviceSeverity combines pod health, open incidents, HPA-at-max, and recent changes.
func serviceSeverity(c ServiceCard) string {
	if c.Band == "critical" || c.OpenIncidents > 0 || (c.HPA != nil && c.HPA.AtMax) {
		return "critical"
	}
	if c.Band == "warning" || c.TotalRestarts > 0 || c.RecentChanges > 0 {
		return "warning"
	}
	return "ok"
}

// ServiceImpactSummary is the fleet rollup for the home header.
type ServiceImpactSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	OK       int `json:"ok"`
	Exposed  int `json:"exposed"`
}

// SummarizeServiceImpact tallies cards by severity for the home KPIs.
func SummarizeServiceImpact(cards []ServiceCard) ServiceImpactSummary {
	s := ServiceImpactSummary{Total: len(cards)}
	for _, c := range cards {
		switch c.Severity {
		case "critical":
			s.Critical++
		case "warning":
			s.Warning++
		default:
			s.OK++
		}
		if c.Exposed {
			s.Exposed++
		}
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
