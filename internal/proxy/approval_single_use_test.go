package proxy

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"clustara/internal/store"
)

func approvalTestServer(t *testing.T) (*store.SQLStore, *Server) {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return db, server
}

func approvedApproval(t *testing.T, db *store.SQLStore, id string, a store.Approval) {
	t.Helper()
	a.ID = id
	a.Status = "approved"
	if a.ExpiresAt.IsZero() {
		a.ExpiresAt = time.Now().UTC().Add(time.Hour)
	}
	a.CreatedAt = time.Now().UTC()
	if err := db.InsertApproval(context.Background(), a); err != nil {
		t.Fatal(err)
	}
}

// An approval authorizes ONE request. It was left in state "approved" after use, so the
// same X-Governance-Approval-ID header replayed on every later request for the whole
// 24-hour expiry window: one human decision became unlimited authorization, and the header
// is chosen by the caller.
func TestApprovalCannotBeReplayedOnAnotherRequest(t *testing.T) {
	db, server := approvalTestServer(t)
	approvedApproval(t, db, "appr_1", store.Approval{APIKeyID: "ak_1", SubjectType: "openai_request"})

	first := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	first.Header.Set("X-Governance-Approval-ID", "appr_1")
	gctx := governanceContext{RequestID: "req_1", APIKeyID: "ak_1", SubjectType: "openai_request"}
	if allowed, _, reason := server.governanceApprovalGate(first, gctx, "needs approval"); !allowed {
		t.Fatalf("the approved approval must let its own request through: %s", reason)
	}

	// A different request presenting the same header must not pass.
	second := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	second.Header.Set("X-Governance-Approval-ID", "appr_1")
	next := governanceContext{RequestID: "req_2", APIKeyID: "ak_1", SubjectType: "openai_request"}
	allowed, _, reason := server.governanceApprovalGate(second, next, "needs approval")
	if allowed {
		t.Fatal("a spent approval authorized a second, different request; one approval became " +
			"unlimited authorization for as long as it had not expired")
	}
	if reason == "" {
		t.Fatal("the refusal must say why")
	}
}

// A single request may cross more than one governance phase (request and cost), and both
// evaluate policies. Spending the approval must not lock the request out of its own second
// phase.
func TestApprovalSurvivesASecondPhaseOfTheSameRequest(t *testing.T) {
	db, server := approvalTestServer(t)
	approvedApproval(t, db, "appr_2", store.Approval{APIKeyID: "ak_1", SubjectType: "openai_request"})

	gctx := governanceContext{RequestID: "req_1", APIKeyID: "ak_1", SubjectType: "openai_request"}
	for phase := 1; phase <= 2; phase++ {
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.Header.Set("X-Governance-Approval-ID", "appr_2")
		if allowed, _, reason := server.governanceApprovalGate(r, gctx, "needs approval"); !allowed {
			t.Fatalf("phase %d of the same request was refused its own approval: %s", phase, reason)
		}
	}
}

// An approval bound to an identity is usable only by that identity. The checks carried
// "&& g.X != \"\"", so a request carrying no identity at all matched every bound approval —
// the caller least entitled to it passed most easily.
func TestBoundApprovalRejectsAnUnidentifiedCaller(t *testing.T) {
	db, server := approvalTestServer(t)
	approvedApproval(t, db, "appr_key", store.Approval{APIKeyID: "ak_owner", SubjectType: "openai_request"})
	approvedApproval(t, db, "appr_user", store.Approval{UserID: "u_owner", SubjectType: "openai_request"})
	approvedApproval(t, db, "appr_team", store.Approval{TeamID: "t_owner", SubjectType: "openai_request"})

	cases := []struct {
		name       string
		approvalID string
		gctx       governanceContext
	}{
		{"no api key", "appr_key", governanceContext{RequestID: "r1", SubjectType: "openai_request"}},
		{"no user", "appr_user", governanceContext{RequestID: "r2", SubjectType: "openai_request"}},
		{"no team", "appr_team", governanceContext{RequestID: "r3", SubjectType: "openai_request"}},
		{"other api key", "appr_key", governanceContext{RequestID: "r4", APIKeyID: "ak_other", SubjectType: "openai_request"}},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.Header.Set("X-Governance-Approval-ID", tc.approvalID)
		if allowed, _, _ := server.governanceApprovalGate(r, tc.gctx, "needs approval"); allowed {
			t.Errorf("%s: a request that is not the bound identity used the approval anyway", tc.name)
		}
	}
}

// The consume is one conditional UPDATE so concurrent replays cannot both win.
func TestApprovalConsumeIsAtomic(t *testing.T) {
	db, _ := approvalTestServer(t)
	approvedApproval(t, db, "appr_race", store.Approval{SubjectType: "openai_request"})
	ctx := context.Background()

	first, err := db.ConsumeApproval(ctx, "appr_race", "req_a")
	if err != nil || !first {
		t.Fatalf("first consume = %v (%v), want true", first, err)
	}
	second, err := db.ConsumeApproval(ctx, "appr_race", "req_b")
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("a second request consumed an approval that was already spent")
	}
	// The request that spent it may re-consume (its own second governance phase).
	again, err := db.ConsumeApproval(ctx, "appr_race", "req_a")
	if err != nil || !again {
		t.Fatalf("the spending request could not re-consume its own approval: %v (%v)", again, err)
	}
}
