package store

import (
	"context"
	"testing"
)

func TestK8sAgentActionCardLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openAgentSessionTestStore(t)

	card := K8sAgentActionCard{
		ID: "c1", SessionID: "s1", Action: "rollout_restart", Kind: "Deployment",
		Namespace: "prod", Name: "web", Title: "롤아웃 재시작", Risk: "medium",
		RequiresApproval: true, Executable: true, CreatedBy: "admin_x",
	}
	if err := db.InsertK8sAgentActionCard(ctx, card); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetK8sAgentActionCard(ctx, "c1")
	if err != nil || got.Status != "proposed" || !got.Executable {
		t.Fatalf("get card: %+v %v", got, err)
	}

	// Valid lifecycle path: proposed → pending_approval → approved → executed → rolled_back.
	steps := []struct {
		to    string
		valid bool
	}{
		{"pending_approval", true},
		{"approved", true},
		{"executed", true},
		{"rolled_back", true},
	}
	for _, st := range steps {
		err := db.UpdateK8sAgentActionCardStatus(ctx, "c1", st.to, "", "")
		if (err == nil) != st.valid {
			t.Fatalf("transition to %s: got err=%v want valid=%v", st.to, err, st.valid)
		}
	}
	final, _ := db.GetK8sAgentActionCard(ctx, "c1")
	if final.Status != "rolled_back" {
		t.Fatalf("final status = %s, want rolled_back", final.Status)
	}

	// Invalid transition is rejected.
	card2 := card
	card2.ID = "c2"
	_ = db.InsertK8sAgentActionCard(ctx, card2)
	if err := db.UpdateK8sAgentActionCardStatus(ctx, "c2", "executed", "", ""); err != ErrInvalidTransition {
		t.Fatalf("proposed→executed should be ErrInvalidTransition, got %v", err)
	}

	// Link to an Action Center request is recorded.
	_ = db.UpdateK8sAgentActionCardStatus(ctx, "c2", "pending_approval", "k8saction_99", "")
	c2, _ := db.GetK8sAgentActionCard(ctx, "c2")
	if c2.ActionRequestID != "k8saction_99" {
		t.Fatalf("action request id not linked: %+v", c2)
	}

	// Recurrence flag on an executed card.
	card3 := card
	card3.ID = "c3"
	_ = db.InsertK8sAgentActionCard(ctx, card3)
	_ = db.UpdateK8sAgentActionCardStatus(ctx, "c3", "pending_approval", "", "")
	_ = db.UpdateK8sAgentActionCardStatus(ctx, "c3", "approved", "", "")
	_ = db.UpdateK8sAgentActionCardStatus(ctx, "c3", "executed", "", "")
	if err := db.UpdateK8sAgentActionCardStatus(ctx, "c3", "recurred", "", ""); err != nil {
		t.Fatalf("recurred flag: %v", err)
	}
	c3, _ := db.GetK8sAgentActionCard(ctx, "c3")
	if !c3.Recurred || c3.Status != "executed" {
		t.Fatalf("recurrence should flag but keep executed status: %+v", c3)
	}

	// List filters.
	all, _ := db.ListK8sAgentActionCards(ctx, K8sAgentActionCardFilter{SessionID: "s1"})
	if len(all) != 3 {
		t.Fatalf("expected 3 cards for s1, got %d", len(all))
	}
	executed, _ := db.ListK8sAgentActionCards(ctx, K8sAgentActionCardFilter{Status: "executed"})
	if len(executed) != 1 || executed[0].ID != "c3" {
		t.Fatalf("status filter wrong: %+v", executed)
	}

	if _, err := db.GetK8sAgentActionCard(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("missing card should be ErrNotFound, got %v", err)
	}
}
