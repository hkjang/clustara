package analyzer

import "testing"

func TestSummarizeActionOutcomes(t *testing.T) {
	samples := []ActionOutcomeSample{
		{Status: "proposed", Action: "scale", Risk: "low"},
		{Status: "pending_approval", Action: "scale", Risk: "low"},
		{Status: "dismissed", Action: "scale", Risk: "low"},
		{Status: "rejected", Action: "delete_pod", Risk: "high"},
		{Status: "executed", Action: "rollout_restart", Risk: "medium"},
		{Status: "executed", Action: "rollout_restart", Risk: "medium"},
		{Status: "failed", Action: "rollout_restart", Risk: "medium"},
		{Status: "rolled_back", Action: "scale", Risk: "low"},
		{Status: "recurred", Action: "scale", Risk: "low"},
	}
	s := SummarizeActionOutcomes(samples)

	if s.Total != 9 {
		t.Fatalf("total: %+v", s)
	}
	if s.Proposed != 1 || s.Pending != 1 || s.Dismissed != 1 || s.Rejected != 1 {
		t.Fatalf("status counts: %+v", s)
	}
	// adopted = approved/executed/failed/rolled_back/recurred = 2 exec + 1 failed + 1 rolled_back + 1 recurred = 5
	if s.Adopted != 5 {
		t.Fatalf("adopted should be 5: %+v", s)
	}
	// executed-ever = executed(2) + rolled_back(1) + recurred(1) = 4
	if s.Executed != 4 {
		t.Fatalf("executed-ever should be 4: %+v", s)
	}
	if s.Failed != 1 || s.RolledBack != 1 || s.Recurred != 1 {
		t.Fatalf("terminal counts: %+v", s)
	}
	// decided = adopted(5) + rejected(1) + dismissed(1) = 7 ; adoption = 5/7 = 71.43
	if s.AdoptionRate < 71.0 || s.AdoptionRate > 71.5 {
		t.Fatalf("adoption rate ~71.43, got %v", s.AdoptionRate)
	}
	// success = executed-ever(4) / ran(executed-ever 4 + failed 1 = 5) = 80
	if s.SuccessRate != 80 {
		t.Fatalf("success rate should be 80, got %v", s.SuccessRate)
	}
	// rollback = 1/4 = 25 ; recurrence = 1/4 = 25
	if s.RollbackRate != 25 || s.RecurrenceRate != 25 {
		t.Fatalf("rollback/recurrence should be 25: %+v", s)
	}

	// Grouping: scale is the most-used action (5 cards) → first.
	if len(s.ByAction) == 0 || s.ByAction[0].Key != "scale" || s.ByAction[0].Total != 5 {
		t.Fatalf("by_action[0] should be scale x5: %+v", s.ByAction)
	}
}

func TestSummarizeActionOutcomesEmpty(t *testing.T) {
	s := SummarizeActionOutcomes(nil)
	if s.Total != 0 || s.AdoptionRate != 0 || s.SuccessRate != 0 {
		t.Fatalf("empty should be zeroed: %+v", s)
	}
}
