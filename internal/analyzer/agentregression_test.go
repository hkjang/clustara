package analyzer

import "testing"

func TestRunAgentRegressionDefaultAllPass(t *testing.T) {
	rep := RunAgentRegression(DefaultAgentRegressionCases())
	if rep.Total != len(DefaultAgentRegressionCases()) {
		t.Fatalf("total mismatch: %+v", rep)
	}
	// The curated baseline must pass 100% against current code — a failure here means the agent's
	// deterministic intent/tool behavior changed and a case (or the code) needs review.
	if rep.PassRate != 100 {
		t.Fatalf("default suite should pass 100%%, got %.2f%%; failures=%+v", rep.PassRate, rep.Failures)
	}
	if rep.IntentAccuracy != 100 || rep.AvgToolCoverage != 100 {
		t.Fatalf("intent accuracy + tool coverage should be 100: %+v", rep)
	}
	if len(rep.Failures) != 0 {
		t.Fatalf("no failures expected: %+v", rep.Failures)
	}
}

func TestRunAgentRegressionDetectsRegression(t *testing.T) {
	// A case whose expectation no longer matches the code is flagged as a failure.
	cases := []RegressionCase{
		{ID: "bad-intent", Question: "비용 알려줘", Context: AgentPageContext{Route: "#/k8s-cost"},
			ExpectIntent: IntentSLO /* wrong on purpose */, ExpectTools: []string{"cost"}},
		{ID: "missing-tool", Question: "위험한 pod 있어?", Context: AgentPageContext{Route: "#/k8s-pods"},
			ExpectIntent: IntentPod, ExpectTools: []string{"pods", "nonexistent_tool"}},
	}
	rep := RunAgentRegression(cases)
	if rep.Passed != 0 || rep.PassRate != 0 {
		t.Fatalf("both cases should fail: %+v", rep)
	}
	if len(rep.Failures) != 2 {
		t.Fatalf("expected 2 failures: %+v", rep.Failures)
	}
	// The missing-tool case should report the missing tool and partial coverage.
	for _, f := range rep.Failures {
		if f.ID == "missing-tool" {
			if len(f.MissingTools) != 1 || f.MissingTools[0] != "nonexistent_tool" {
				t.Fatalf("missing tool not reported: %+v", f)
			}
			if f.ToolCoverage != 50 {
				t.Fatalf("coverage should be 50 (1 of 2), got %v", f.ToolCoverage)
			}
		}
	}
}

func TestRunAgentRegressionEmpty(t *testing.T) {
	rep := RunAgentRegression(nil)
	if rep.Total != 0 || rep.PassRate != 0 {
		t.Fatalf("empty: %+v", rep)
	}
}
