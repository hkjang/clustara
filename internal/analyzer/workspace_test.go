package analyzer

import "testing"

func TestScoreWorkspaceHealth(t *testing.T) {
	// Clean workspace → healthy, 100.
	clean := ScoreWorkspaceHealth(WorkspaceInput{Namespace: "ok", PodTotal: 10, QuotaUsedPct: -1})
	if clean.Band != "healthy" || clean.Score != 100 {
		t.Fatalf("clean workspace should be 100/healthy: %+v", clean)
	}

	// Incident + critical pods → critical.
	bad := ScoreWorkspaceHealth(WorkspaceInput{
		Namespace: "prod", PodTotal: 8, PodCritical: 3, OpenIncidents: 2, Exposed: true, SecurityFindings: 1, QuotaUsedPct: 97,
	})
	if bad.Band != "critical" {
		t.Fatalf("workspace with incidents+critical pods should be critical: %+v", bad)
	}
	if bad.Score >= clean.Score {
		t.Fatalf("bad must score below clean")
	}
	// exposure+risk reason present
	found := false
	for _, r := range bad.Reasons {
		if r == "외부 노출 + 위험 신호" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected exposure+risk reason: %+v", bad.Reasons)
	}

	// Warning-only pods → warning band.
	warn := ScoreWorkspaceHealth(WorkspaceInput{Namespace: "stage", PodTotal: 6, PodWarning: 5, QuotaUsedPct: 85})
	if warn.Band != "warning" {
		t.Fatalf("warning pods + quota 85%% should be warning: %+v", warn)
	}

	// Exposure alone (no risks) is NOT penalized.
	exp := ScoreWorkspaceHealth(WorkspaceInput{Namespace: "web", PodTotal: 3, Exposed: true, QuotaUsedPct: -1})
	if exp.Score != 100 {
		t.Fatalf("exposure without risk should not lower score: %+v", exp)
	}
}

func TestSummarizeAndSortWorkspaces(t *testing.T) {
	ws := []WorkspaceHealth{
		{Namespace: "a", Score: 95, Band: "healthy"},
		{Namespace: "b", Score: 30, Band: "critical", OpenIncidents: 2, Exposed: true},
		{Namespace: "c", Score: 65, Band: "warning"},
	}
	s := SummarizeWorkspaces(ws)
	if s.Total != 3 || s.Healthy != 1 || s.Warning != 1 || s.Critical != 1 || s.Exposed != 1 || s.Incidents != 2 {
		t.Fatalf("summary wrong: %+v", s)
	}
	SortWorkspaces(ws)
	if ws[0].Namespace != "b" || ws[2].Namespace != "a" {
		t.Fatalf("should sort worst-first: %+v", ws)
	}
}
