package proxy

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// reconcilerActsOn mirrors the branches in K8sRolloutReconciler.reconcileOne.
// It exists so the invariant below stays honest if those branches move.
func reconcilerActsOn(roll store.K8sRolloutAction, actionStatus string) string {
	if roll.StartedAt == "" && (roll.Status == "approved" || roll.Status == "approval_required") &&
		roll.ActionRequestID != "" && actionStatus == "approved" {
		return "approved-execution handoff"
	}
	if rolloutNeedsReconcile(roll) {
		return "reconcileRolloutContext"
	}
	if rolloutTerminal(roll.Status) {
		return "syncRolloutActionRequest"
	}
	return ""
}

// ListK8sRolloutActionsDue is the worker's queue. Every state it selects must
// map to a branch that can actually change that state — otherwise the row is
// fetched, leased and dropped on every tick forever, making no progress and
// never tripping the failure backoff. Terminal rows sort first in the queue, so
// a stuck one also starves live rollout work.
//
// This invariant is what the auto-rollback-on-terminal-rollout bug violated.
func TestEveryDueRolloutStateHasAReconcilerBranch(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "due-invariant.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	started := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	type state struct {
		name           string
		status         string
		rollbackStatus string
		startedAt      string
		autoRollback   bool
		actionStatus   string
	}
	states := []state{}
	for _, status := range []string{
		"requested", "pending", "approval_required", "approved", "running",
		"monitoring", "rollback_running", "succeeded", "failed", "timed_out", "rejected", "cancelled",
	} {
		for _, rollback := range []string{"", "requested", "monitoring", "running", "succeeded", "failed"} {
			for _, auto := range []bool{false, true} {
				for _, actionStatus := range []string{"approved", "running", "executed"} {
					for _, startedAt := range []string{"", started} {
						states = append(states, state{
							name: fmt.Sprintf("%s/rollback=%s/auto=%v/action=%s/started=%v",
								status, rollback, auto, actionStatus, startedAt != ""),
							status: status, rollbackStatus: rollback, startedAt: startedAt,
							autoRollback: auto, actionStatus: actionStatus,
						})
					}
				}
			}
		}
	}

	checked, dueCount := 0, 0
	for i, st := range states {
		id := fmt.Sprintf("roll-%04d", i)
		actionID := fmt.Sprintf("act-%04d", i)
		action := store.K8sActionRequest{
			ID: actionID, ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
			ResourceName: "api", Action: "rollout_restart", Status: "approved", TargetUID: "uid-api",
		}
		rollout := store.K8sRolloutAction{
			ID: id, ActionRequestID: actionID, ClusterID: "c1", Namespace: "prod",
			ResourceKind: "Deployment", ResourceName: "api", ResourceUID: id,
			Status: "monitoring", TimeoutSeconds: 600,
		}
		if err := db.InsertK8sRolloutRequest(ctx, action, rollout, store.K8sRolloutEvent{ID: "ev-" + id}); err != nil {
			t.Fatalf("%s: insert: %v", st.name, err)
		}
		// The action state machine only allows approved -> running -> executed,
		// so walk the chain. A rejected step just leaves the action where it is;
		// the assertion below reads the real stored status either way.
		for _, step := range actionTransitionChain(st.actionStatus) {
			_ = db.UpdateK8sActionStatus(ctx, actionID, step, "test", "fixture")
		}
		current, err := db.GetK8sRolloutAction(ctx, id)
		if err != nil {
			t.Fatalf("%s: get: %v", st.name, err)
		}
		current.Status = st.status
		current.RollbackStatus = st.rollbackStatus
		current.StartedAt = st.startedAt
		current.AutoRollback = st.autoRollback
		if err := db.UpdateK8sRolloutProgress(ctx, current); err != nil {
			t.Fatalf("%s: progress: %v", st.name, err)
		}
		checked++
	}

	due, err := db.ListK8sRolloutActionsDue(ctx, len(states)+10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) == 0 {
		t.Fatal("the due query selected nothing; the fixture is not exercising it")
	}

	orphans := []string{}
	for _, roll := range due {
		dueCount++
		action, err := db.GetK8sActionRequest(ctx, roll.ActionRequestID)
		if err != nil {
			t.Fatalf("%s: action lookup: %v", roll.ID, err)
		}
		if reconcilerActsOn(roll, action.Status) == "" {
			orphans = append(orphans, fmt.Sprintf("status=%q rollback=%q auto=%v started=%v action=%q",
				roll.Status, roll.RollbackStatus, roll.AutoRollback, roll.StartedAt != "", action.Status))
		}
	}
	if len(orphans) > 0 {
		t.Fatalf("%d/%d due rollouts have no reconciler branch and would spin forever:\n  %s",
			len(orphans), dueCount, joinLines(orphans))
	}
	t.Logf("checked %d states, %d selected as due, all reachable", checked, dueCount)
}

// actionTransitionChain returns the steps needed to reach target from
// "approved" through the action state machine.
func actionTransitionChain(target string) []string {
	switch target {
	case "approved":
		return nil
	case "running":
		return []string{"running"}
	default:
		return []string{"running", target}
	}
}

func joinLines(items []string) string {
	out := ""
	for i, item := range items {
		if i > 0 {
			out += "\n  "
		}
		out += item
	}
	return out
}
