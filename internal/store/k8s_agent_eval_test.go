package store

import (
	"context"
	"testing"
)

func TestK8sAgentEvaluations(t *testing.T) {
	ctx := context.Background()
	db := openAgentSessionTestStore(t)

	// Insert a spread of evaluations across intents/feedback.
	evals := []K8sAgentEvaluation{
		{ID: "e1", SessionID: "s1", MessageID: "m1", Intent: "pod", EvidenceCount: 5, ResponseMS: 800, LLMAvailable: true, GroundingScore: 90, Feedback: "up"},
		{ID: "e2", SessionID: "s1", MessageID: "m2", Intent: "pod", EvidenceCount: 0, ResponseMS: 400, Fallback: true, GroundingScore: 20, Feedback: "down"},
		{ID: "e3", SessionID: "s2", MessageID: "m3", Intent: "incident", EvidenceCount: 3, ResponseMS: 1200, LLMAvailable: true, GroundingScore: 70, ActionCardID: "card1"},
	}
	for _, e := range evals {
		if err := db.InsertK8sAgentEvaluation(ctx, e); err != nil {
			t.Fatalf("insert %s: %v", e.ID, err)
		}
	}

	// Filter by session.
	s1, err := db.ListK8sAgentEvaluations(ctx, K8sAgentEvalFilter{SessionID: "s1"})
	if err != nil || len(s1) != 2 {
		t.Fatalf("session s1 should have 2 evals, got %d (%v)", len(s1), err)
	}
	// Filter by intent.
	inc, _ := db.ListK8sAgentEvaluations(ctx, K8sAgentEvalFilter{Intent: "incident"})
	if len(inc) != 1 || inc[0].ID != "e3" {
		t.Fatalf("intent filter wrong: %+v", inc)
	}

	// Feedback round-trips.
	if err := db.SetK8sAgentEvaluationFeedback(ctx, "e3", "up", "정확함"); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetK8sAgentEvaluation(ctx, "e3")
	if got.Feedback != "up" || got.FeedbackNote != "정확함" {
		t.Fatalf("feedback not stored: %+v", got)
	}
	if err := db.SetK8sAgentEvaluationFeedback(ctx, "missing", "up", ""); err != ErrNotFound {
		t.Fatalf("feedback on missing should be ErrNotFound, got %v", err)
	}

	// Aggregate stats.
	stats, byIntent, err := db.K8sAgentEvalStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 3 {
		t.Fatalf("total = %d, want 3", stats.Total)
	}
	if stats.LLMAnswers != 2 || stats.Fallbacks != 1 {
		t.Fatalf("llm/fallback counts wrong: %+v", stats)
	}
	if stats.ThumbsUp != 2 || stats.ThumbsDown != 1 {
		t.Fatalf("feedback counts wrong: %+v", stats)
	}
	if stats.ActionsProposed != 1 {
		t.Fatalf("actions proposed = %d, want 1", stats.ActionsProposed)
	}
	// avg grounding = (90+20+70)/3 = 60
	if stats.AvgGrounding != 60 {
		t.Fatalf("avg grounding = %v, want 60", stats.AvgGrounding)
	}
	if len(byIntent) != 2 {
		t.Fatalf("expected 2 intent groups, got %d", len(byIntent))
	}
}
