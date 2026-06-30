package analyzer

import "testing"

func TestScoreGroundingWellGrounded(t *testing.T) {
	evidence := []string{
		"pod nginx-7d9 in namespace prod restarted 5 times (CrashLoopBackOff)",
		"event: Liveness probe failed for nginx-7d9",
		"config revision changed image to nginx:1.27",
		"memory limit 256Mi exceeded on nginx-7d9",
	}
	answer := "nginx-7d9 파드가 CrashLoopBackOff 상태이며 image nginx:1.27 변경 이후 memory 256Mi 초과로 재시작되고 있습니다."
	plan := []AgentToolCall{{Tool: "pod_detail", API: "/admin/k8s/pods/x"}, {Tool: "pod_logs", API: "/admin/k8s/logs"}}

	gs := ScoreGrounding(answer, evidence, plan, false)
	if gs.EvidenceTotal != 4 {
		t.Fatalf("evidence total = %d, want 4", gs.EvidenceTotal)
	}
	if gs.EvidenceUsed < 2 {
		t.Fatalf("expected at least 2 evidence lines reflected, got %d", gs.EvidenceUsed)
	}
	if gs.Grade != "A" && gs.Grade != "B" {
		t.Fatalf("well-grounded answer should grade A/B, got %s (score %v)", gs.Grade, gs.Score)
	}
}

func TestScoreGroundingFallbackPenalized(t *testing.T) {
	evidence := []string{"pod nginx-7d9 restarted 5 times", "memory limit exceeded"}
	answer := "nginx-7d9 restarted due to memory limit"
	plan := []AgentToolCall{{Tool: "pod_detail", API: "/x"}}

	full := ScoreGrounding(answer, evidence, plan, false)
	fallback := ScoreGrounding(answer, evidence, plan, true)
	if fallback.Score >= full.Score {
		t.Fatalf("fallback (%v) should score below non-fallback (%v)", fallback.Score, full.Score)
	}
	if !fallback.Fallback {
		t.Fatalf("fallback flag not set")
	}
}

func TestScoreGroundingNoEvidence(t *testing.T) {
	gs := ScoreGrounding("일반적인 설명입니다.", nil, nil, false)
	if gs.EvidenceTotal != 0 || gs.EvidenceUsed != 0 {
		t.Fatalf("no-evidence counts wrong: %+v", gs)
	}
	if gs.Grade != "D" {
		t.Fatalf("ungrounded answer should grade D, got %s (%v)", gs.Grade, gs.Score)
	}
	if len(gs.Notes) == 0 {
		t.Fatalf("expected explanatory notes for ungrounded answer")
	}
}

func TestScoreGroundingEvidenceNotCited(t *testing.T) {
	evidence := []string{"pod nginx-7d9 restarted 5 times", "liveness probe failed"}
	// Answer shares no salient tokens with the evidence.
	answer := "전반적으로 정상이며 특이사항 없습니다."
	gs := ScoreGrounding(answer, evidence, nil, false)
	if gs.EvidenceUsed != 0 {
		t.Fatalf("expected 0 citations, got %d", gs.EvidenceUsed)
	}
	if gs.CitationRate != 0 {
		t.Fatalf("citation rate = %v, want 0", gs.CitationRate)
	}
}
