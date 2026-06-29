package analyzer

import (
	"strings"
	"testing"
)

func TestBuildPodBriefing(t *testing.T) {
	// Healthy pod → no-symptom verdict.
	b := BuildPodBriefing(PodBriefingInput{Health: PodHealth{Score: 100, Band: "healthy", PrimarySymptom: "Healthy"}})
	if !strings.Contains(b.Verdict, "정상") || b.Severity != "healthy" {
		t.Fatalf("healthy briefing: %+v", b)
	}

	// CrashLoop + recent change → cause + change surfaced first.
	b = BuildPodBriefing(PodBriefingInput{
		Health:        PodHealth{Score: 20, Band: "critical", PrimarySymptom: "CrashLoopBackOff", Symptoms: []string{"CrashLoopBackOff"}},
		RestartCount:  9,
		RecentChange:  true,
		ChangeSummary: "x:1.2 → x:1.3",
		WarningEvents: 2,
	})
	if b.Severity != "critical" || !strings.Contains(b.Verdict, "CrashLoopBackOff") {
		t.Fatalf("crashloop verdict: %+v", b)
	}
	if !strings.Contains(b.LikelyCause, "반복 종료") {
		t.Fatalf("crashloop cause missing: %+v", b)
	}
	if len(b.FirstChecks) == 0 || !strings.Contains(b.FirstChecks[0], "변경") {
		t.Fatalf("recent change should be the first check: %+v", b.FirstChecks)
	}
	// change summary embedded
	if !strings.Contains(strings.Join(b.FirstChecks, " "), "x:1.2") {
		t.Fatalf("change summary should appear: %+v", b.FirstChecks)
	}

	// OOMKilled maps to memory-focused checks.
	b = BuildPodBriefing(PodBriefingInput{Health: PodHealth{Score: 25, Band: "critical", PrimarySymptom: "OOMKilled"}})
	if !strings.Contains(strings.Join(b.FirstChecks, " "), "메모리") {
		t.Fatalf("OOM checks should mention memory: %+v", b.FirstChecks)
	}

	// Unknown/degraded symptom → generic guidance, no crash.
	b = BuildPodBriefing(PodBriefingInput{Health: PodHealth{Score: 55, Band: "warning", PrimarySymptom: "Degraded"}})
	if b.Severity != "warning" || len(b.FirstChecks) == 0 {
		t.Fatalf("degraded briefing should have generic checks: %+v", b)
	}
}
