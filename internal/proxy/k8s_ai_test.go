package proxy

import (
	"strings"
	"testing"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func TestComposeK8sAIPromptGrounding(t *testing.T) {
	p := composeK8sAIPrompt("왜 죽었어?", []string{"RCA[high] Pod/api: OOM", "Event[Warning] BackOff: ..."})
	// Must instruct grounding + include question + numbered evidence.
	for _, want := range []string{"근거", "왜 죽었어?", "1. RCA[high] Pod/api: OOM", "2. Event[Warning]"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q\n%s", want, p)
		}
	}
	// Empty evidence → explicit "없음".
	if !strings.Contains(composeK8sAIPrompt("q", nil), "근거 없음") {
		t.Error("empty-evidence prompt should note no evidence")
	}
}

func TestGatherK8sEvidenceFiltersToTarget(t *testing.T) {
	rca := []analyzer.RCAFinding{
		{Namespace: "default", ResourceKind: "Pod", ResourceName: "api", Severity: "high", Cause: "OOM", Evidence: []string{"limit exceeded"}},
		{Namespace: "default", ResourceKind: "Pod", ResourceName: "other", Severity: "high", Cause: "Crash"},
	}
	events := []store.K8sEvent{
		{Namespace: "default", InvolvedName: "api", Type: "Warning", Reason: "BackOff", Message: "restarting"},
		{Namespace: "default", InvolvedName: "other", Type: "Warning", Reason: "X", Message: "noise"},
		{Namespace: "default", InvolvedName: "api", Type: "Normal", Reason: "Started", Message: "ok"},
	}
	diff := &analyzer.RevisionDiff{
		Highlights: []string{"image"},
		Changes:    []analyzer.FieldChange{{Path: "spec.x.image", Kind: "changed", Old: "a:1", New: "a:2"}},
	}
	ev := gatherK8sEvidence("default", "api", rca, events, diff)
	joined := strings.Join(ev, "\n")

	if !strings.Contains(joined, "OOM") || !strings.Contains(joined, "limit exceeded") {
		t.Errorf("should include target RCA + its evidence: %v", ev)
	}
	if strings.Contains(joined, "other") || strings.Contains(joined, "Crash") || strings.Contains(joined, "noise") {
		t.Errorf("should NOT include other resources: %v", ev)
	}
	if strings.Contains(joined, "Started") {
		t.Errorf("Normal events must be excluded: %v", ev)
	}
	if !strings.Contains(joined, "image") || !strings.Contains(joined, "a:1 → a:2") {
		t.Errorf("should include diff highlight + change: %v", ev)
	}
}
