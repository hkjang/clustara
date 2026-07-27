package store

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func TestK8sRolloutLedgerRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a := K8sRolloutAction{ID: "r1", ActionRequestID: "a1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-1", RequestedBy: "user", Reason: "refresh", Status: "monitoring", DesiredReplicas: 3,
		UpdatedReplicas: 1, ReadyReplicas: 1, Precheck: map[string]any{"healthy": true},
		PreviousTemplate: map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "api"}}}}}
	if err := db.InsertK8sRolloutAction(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetK8sRolloutAction(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ResourceUID != "uid-1" || got.DesiredReplicas != 3 || got.Precheck["healthy"] != true || len(got.PreviousTemplate) == 0 {
		t.Fatalf("bad rollout: %+v", got)
	}
	got.Status = "succeeded"
	got.UpdatedReplicas = 3
	got.ReadyReplicas = 3
	got.AvailableReplicas = 3
	if err := db.UpdateK8sRolloutProgress(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sRolloutPodTransition(ctx, K8sRolloutPodTransition{ID: "p1", ActionID: "r1", PodUID: "pod-1", PodName: "api-new", ReadyAt: "2026-07-27T00:01:00Z"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendK8sRolloutEvent(ctx, K8sRolloutEvent{ID: "e1", ActionID: "r1", Status: "monitoring", Stage: "pod_replacement", Evidence: map[string]any{"ready": 1}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendK8sRolloutEvent(ctx, K8sRolloutEvent{ID: "e2", ActionID: "r1", Status: "succeeded", Stage: "completed"}); err != nil {
		t.Fatal(err)
	}
	events, err := db.ListK8sRolloutEvents(ctx, "r1")
	if err != nil || len(events) != 2 || events[1].SequenceNo != 2 {
		t.Fatalf("bad events=%+v err=%v", events, err)
	}
	pods, err := db.ListK8sRolloutPodTransitions(ctx, "r1")
	if err != nil || len(pods) != 1 || pods[0].ReadyAt == "" {
		t.Fatalf("bad pods=%+v err=%v", pods, err)
	}
	list, err := db.ListK8sRolloutActions(ctx, "c1", "uid-1", 10)
	if err != nil || len(list) != 1 || list[0].Status != "succeeded" {
		t.Fatalf("bad list=%+v err=%v", list, err)
	}
}

func TestK8sRolloutRejectsConcurrentActiveTarget(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "rollout-race.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	base := K8sRolloutAction{ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api",
		ResourceUID: "uid-1", RequestedBy: "user", Reason: "refresh", Status: "monitoring"}
	base.ID = "r1"
	if err := db.InsertK8sRolloutAction(ctx, base); err != nil {
		t.Fatal(err)
	}
	base.ID = "r2"
	if err := db.InsertK8sRolloutAction(ctx, base); err == nil {
		t.Fatal("expected active rollout uniqueness violation")
	}
}
