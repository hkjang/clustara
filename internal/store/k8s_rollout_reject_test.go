package store

import (
	"context"
	"errors"
	"testing"
)

func rejectFixture(t *testing.T) (*SQLStore, K8sActionRequest, K8sRolloutAction) {
	t.Helper()
	ctx := context.Background()
	db := openStoreForTest(t)
	action := K8sActionRequest{
		ID: "act-1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", Action: "rollout_restart", Status: "approval_required", TargetUID: "uid-api",
	}
	rollout := K8sRolloutAction{
		ID: "roll-1", ActionRequestID: action.ID, ClusterID: "c1", Namespace: "prod",
		ResourceKind: "Deployment", ResourceName: "api", ResourceUID: "uid-api",
		Status: "approval_required", TimeoutSeconds: 600,
	}
	if err := db.InsertK8sRolloutRequest(ctx, action, rollout, K8sRolloutEvent{ID: "ev-1"}); err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetK8sRolloutAction(ctx, rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	return db, action, stored
}

func TestRejectK8sRolloutWithActionMovesBothLedgers(t *testing.T) {
	ctx := context.Background()
	db, action, rollout := rejectFixture(t)

	if err := db.RejectK8sRolloutWithAction(ctx, rollout.ID, action.ID, "admin-1", "rollout rejected",
		rollout.Status, rollout.RollbackStatus, rollout.UpdatedAt); err != nil {
		t.Fatal(err)
	}

	savedAction, err := db.GetK8sActionRequest(ctx, action.ID)
	if err != nil {
		t.Fatal(err)
	}
	savedRollout, err := db.GetK8sRolloutAction(ctx, rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	if savedAction.Status != "rejected" {
		t.Fatalf("action status = %q, want rejected", savedAction.Status)
	}
	if savedRollout.Status != "rejected" {
		t.Fatalf("rollout status = %q, want rejected", savedRollout.Status)
	}
	if savedRollout.CompletedAt == "" {
		t.Fatal("a rejected rollout must be stamped complete")
	}
}

// The two writes have to be atomic. If the rollout half cannot apply, the
// action must not be left as rejected on its own.
func TestRejectK8sRolloutLeavesBothUnchangedOnStaleRollout(t *testing.T) {
	ctx := context.Background()
	db, action, rollout := rejectFixture(t)

	err := db.RejectK8sRolloutWithAction(ctx, rollout.ID, action.ID, "admin-1", "rollout rejected",
		rollout.Status, rollout.RollbackStatus, "1999-01-01T00:00:00Z")
	if err == nil {
		t.Fatal("rejecting against a stale rollout snapshot should fail")
	}
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition", err)
	}

	savedAction, err := db.GetK8sActionRequest(ctx, action.ID)
	if err != nil {
		t.Fatal(err)
	}
	if savedAction.Status == "rejected" {
		t.Fatal("the action was rejected even though the rollout half did not apply")
	}
	savedRollout, err := db.GetK8sRolloutAction(ctx, rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	if savedRollout.Status != "approval_required" {
		t.Fatalf("rollout status = %q, want it untouched", savedRollout.Status)
	}
}

func TestRejectK8sRolloutRejectsAnAlreadyDecidedAction(t *testing.T) {
	ctx := context.Background()
	db, action, rollout := rejectFixture(t)
	if err := db.UpdateK8sActionStatus(ctx, action.ID, "approved", "admin-1", "approved"); err != nil {
		t.Fatal(err)
	}

	err := db.RejectK8sRolloutWithAction(ctx, rollout.ID, action.ID, "admin-1", "rollout rejected",
		rollout.Status, rollout.RollbackStatus, rollout.UpdatedAt)
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition for an approved action", err)
	}
	savedRollout, err := db.GetK8sRolloutAction(ctx, rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	if savedRollout.Status != "approval_required" {
		t.Fatalf("rollout status = %q, want it untouched", savedRollout.Status)
	}
}

func TestRejectK8sRolloutReportsMissingRecords(t *testing.T) {
	ctx := context.Background()
	db, _, rollout := rejectFixture(t)
	if err := db.RejectK8sRolloutWithAction(ctx, rollout.ID, "act-missing", "admin-1", "x",
		rollout.Status, rollout.RollbackStatus, rollout.UpdatedAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound for a missing action", err)
	}
}
