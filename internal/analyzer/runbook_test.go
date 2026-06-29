package analyzer

import "testing"

func TestBuildRunbookPlan(t *testing.T) {
	// CrashLoopBackOff with owner + recent change → full plan incl. rollback.
	plan := BuildRunbookPlan("CrashLoopBackOff", RunbookContext{HasOwner: true, RecentChange: true, Replicas: 3})
	if plan.Symptom != "CrashLoopBackOff" || plan.RollbackCandidate == "" {
		t.Fatalf("crashloop plan: %+v", plan)
	}
	// Phases must appear in canonical order with at least one remediate (approval) step.
	wantOrder := []string{PhasePrecheck, PhaseDiagnose, PhaseRemediate, PhasePostcheck, PhaseRollback}
	seen := map[string]int{}
	lastRank := -1
	rankOf := map[string]int{PhasePrecheck: 0, PhaseDiagnose: 1, PhaseRemediate: 2, PhasePostcheck: 3, PhaseRollback: 4}
	remediateApproval := false
	for i, s := range plan.Steps {
		if s.Order != i+1 {
			t.Fatalf("steps must be sequentially ordered: %+v", plan.Steps)
		}
		seen[s.Phase]++
		if r := rankOf[s.Phase]; r < lastRank {
			t.Fatalf("phases out of order at %q: %+v", s.Phase, plan.Steps)
		} else {
			lastRank = r
		}
		if s.Phase == PhaseRemediate && s.RequiresApproval {
			remediateApproval = true
		}
	}
	for _, p := range wantOrder {
		if seen[p] == 0 {
			t.Fatalf("missing phase %q: %+v", p, plan.Steps)
		}
	}
	if !remediateApproval {
		t.Fatalf("remediate step must require approval: %+v", plan.Steps)
	}

	// No recent change → no rollback phase.
	plan2 := BuildRunbookPlan("ImagePullBackOff", RunbookContext{HasOwner: true})
	for _, s := range plan2.Steps {
		if s.Phase == PhaseRollback {
			t.Fatalf("no recent change should mean no rollback step: %+v", plan2.Steps)
		}
	}
	if plan2.RollbackCandidate != "" {
		t.Fatalf("no rollback candidate expected: %+v", plan2)
	}

	// Bare pod (no owner) → extra warning step.
	plan3 := BuildRunbookPlan("CrashLoopBackOff", RunbookContext{HasOwner: false})
	warned := false
	for _, s := range plan3.Steps {
		if s.Action == "warn_bare_pod" {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("bare pod should get a no-controller warning: %+v", plan3.Steps)
	}

	// Unknown symptom → still a valid plan with generic remediate.
	plan4 := BuildRunbookPlan("", RunbookContext{HasOwner: true})
	if len(plan4.Steps) == 0 {
		t.Fatalf("unknown symptom should still yield a plan")
	}
}
