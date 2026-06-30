package analyzer

import "testing"

func TestAssembleServiceCards(t *testing.T) {
	groups := []WorkloadGroup{
		{Namespace: "prod", OwnerKind: "Deployment", OwnerName: "web", Band: "healthy", PodCount: 3, ReadyPods: 3, SamplePods: []string{"web-1"}},
		{Namespace: "prod", OwnerKind: "Deployment", OwnerName: "api", Band: "critical", PodCount: 2, CriticalPods: 2, TotalRestarts: 8, WorstSymptom: "OOMKilled"},
		{Namespace: "prod", OwnerKind: "Deployment", OwnerName: "worker", Band: "healthy", PodCount: 1, ReadyPods: 1, TotalRestarts: 2},
	}
	enrich := map[string]ServiceEnrichment{
		WorkloadImpactKey("prod", "Deployment", "web"):    {Services: []string{"web-svc"}, Ingresses: []string{"web-ing"}},
		WorkloadImpactKey("prod", "Deployment", "api"):    {Services: []string{"api-svc"}, OpenIncidents: 1},
		WorkloadImpactKey("prod", "Deployment", "worker"): {RecentChanges: 1},
	}
	cards := AssembleServiceCards(groups, enrich)
	if len(cards) != 3 {
		t.Fatalf("expected 3 cards: %d", len(cards))
	}
	// api is critical (critical pods + open incident) → first.
	if cards[0].Workload != "api" || cards[0].Severity != "critical" {
		t.Fatalf("api should rank first as critical: %+v", cards[0])
	}
	// web is healthy but exposed (ingress) → ranks above worker among non-critical... but web is "ok"
	// (no restarts/changes) and worker is "warning" (recent change). warning ranks before ok.
	if cards[1].Workload != "worker" || cards[1].Severity != "warning" {
		t.Fatalf("worker should be warning (recent change), ranked 2nd: %+v", cards[1])
	}
	if cards[2].Workload != "web" || cards[2].Severity != "ok" {
		t.Fatalf("web should be ok, last: %+v", cards[2])
	}
	if !cards[2].Exposed {
		t.Fatalf("web should be exposed (ingress): %+v", cards[2])
	}

	sum := SummarizeServiceImpact(cards)
	if sum.Total != 3 || sum.Critical != 1 || sum.Warning != 1 || sum.OK != 1 || sum.Exposed != 1 {
		t.Fatalf("summary wrong: %+v", sum)
	}
}

func TestServiceSeverityHPAAtMax(t *testing.T) {
	groups := []WorkloadGroup{{Namespace: "prod", OwnerKind: "Deployment", OwnerName: "x", Band: "healthy", PodCount: 1}}
	enrich := map[string]ServiceEnrichment{
		WorkloadImpactKey("prod", "Deployment", "x"): {HPA: &HPASummary{Name: "x-hpa", MaxReplicas: 5, Current: 5, AtMax: true}},
	}
	cards := AssembleServiceCards(groups, enrich)
	if cards[0].Severity != "critical" {
		t.Fatalf("HPA at max should be critical: %+v", cards[0])
	}
}
