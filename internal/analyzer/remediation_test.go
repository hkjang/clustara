package analyzer

import "testing"

func TestAdviseRemediation(t *testing.T) {
	findings := []RCAFinding{
		{Condition: "ReadinessProbeFailed", Severity: "medium", ResourceName: "a"},
		{Condition: "CrashLoopBackOff", Severity: "high", ResourceName: "b"},
		{Condition: "PostDeploymentLatency", Severity: "high", ResourceName: "c"},
		{Condition: "MysteryCondition", Severity: "critical", ResourceName: "d"},
	}
	adv := AdviseRemediation(findings)
	if len(adv) != 4 {
		t.Fatalf("expected 4 advices, got %d", len(adv))
	}
	// Sorted by priority: critical(d) first.
	if adv[0].Name != "d" || adv[0].Priority != 0 {
		t.Fatalf("critical should sort first, got %+v", adv[0])
	}
	byName := map[string]RemediationAdvice{}
	for _, a := range adv {
		byName[a.Name] = a
	}
	if byName["b"].RecommendedAction != "rollout_restart" || !byName["b"].Actionable || !byName["b"].RollbackPossible {
		t.Fatalf("CrashLoop should advise actionable rollout_restart w/ rollback: %+v", byName["b"])
	}
	if byName["c"].RecommendedAction != "rollback" || byName["c"].Actionable {
		t.Fatalf("PostDeploymentLatency should advise (non-executor) rollback: %+v", byName["c"])
	}
	if byName["a"].RecommendedAction != "investigate" {
		t.Fatalf("ReadinessProbeFailed should advise investigate: %+v", byName["a"])
	}
	// Unknown condition falls back to investigate.
	if byName["d"].RecommendedAction != "investigate" || byName["d"].Actionable {
		t.Fatalf("unknown condition should fall back to investigate: %+v", byName["d"])
	}
}
