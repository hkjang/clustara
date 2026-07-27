package store

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func TestPodLifecycleLedgerSurvivesDeletion(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "lifecycle.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	item := K8sInventoryItem{
		ClusterID: "c1", Kind: "Pod", Namespace: "apps", Name: "api-0", UID: "pod-uid-1",
		CreationTimestamp: "2026-07-27T00:31:12.128Z", ObservedAt: "2026-07-27T00:31:22.105Z",
		Spec: map[string]any{"nodeName": "node-a", "ownerReferences": []any{map[string]any{
			"kind": "StatefulSet", "name": "api", "uid": "owner-1", "controller": true,
		}}},
		StatusObject: map[string]any{
			"phase": "Running",
			"conditions": []any{
				map[string]any{"type": "PodScheduled", "status": "True", "lastTransitionTime": "2026-07-27T00:31:12.533Z"},
				map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": "2026-07-27T00:31:22.105Z"},
			},
			"containerStatuses": []any{map[string]any{
				"name": "app", "ready": true, "started": true, "restartCount": float64(0),
				"containerID": "containerd://one", "state": map[string]any{"running": map[string]any{"startedAt": "2026-07-27T00:31:18.441Z"}},
			}},
		},
	}
	if err := db.ObservePodLifecycle(ctx, item); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkPodDeleted(ctx, "c1", item.UID, "2026-07-27T02:00:04.218Z", "missing_detection"); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetK8sPodLifecycleByName(ctx, "c1", "apps", "api-0", item.UID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentState != "DELETED" || got.DeletedObservedAt == "" || got.TotalLifetimeMS == 0 {
		t.Fatalf("unexpected lifecycle: %+v", got)
	}
	transitions, err := db.ListK8sPodTransitions(ctx, "c1", item.UID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(transitions) != 3 || transitions[0].CurrentState != "CREATED" || transitions[2].CurrentState != "DELETED" {
		t.Fatalf("unexpected transitions: %+v", transitions)
	}
	containers, err := db.ListK8sContainerLifecycles(ctx, "c1", item.UID)
	if err != nil || len(containers) != 1 || containers[0].StartedAt == "" {
		t.Fatalf("unexpected containers: %+v err=%v", containers, err)
	}
}

func TestEventHistoryMergesByUIDAndCount(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e := K8sEvent{ClusterID: "c1", EventUID: "event-1", InvolvedObjectUID: "pod-1", Reason: "Unhealthy", Count: 1, FirstSeen: "2026-07-27T00:00:00Z", LastSeen: "2026-07-27T00:00:01Z"}
	if err := db.UpsertK8sEventHistory(ctx, e); err != nil {
		t.Fatal(err)
	}
	e.Count, e.LastSeen = 3, "2026-07-27T00:00:03Z"
	if err := db.UpsertK8sEventHistory(ctx, e); err != nil {
		t.Fatal(err)
	}
	var count, rows int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(occurrence_count) FROM k8s_event_history`).Scan(&rows, &count); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || count != 3 {
		t.Fatalf("expected one merged row at count 3, rows=%d count=%d", rows, count)
	}
}

func TestPodLifecycleTracksConditionsRestartsAndFailureDuration(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "advanced.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	item := K8sInventoryItem{
		ClusterID: "c1", Kind: "Pod", Namespace: "apps", Name: "api-0", UID: "pod-advanced",
		CreationTimestamp: "2026-07-27T00:00:00Z", ObservedAt: "2026-07-27T00:00:10Z", Spec: map[string]any{},
		StatusObject: map[string]any{
			"phase":      "Running",
			"conditions": []any{map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": "2026-07-27T00:00:10Z"}},
			"containerStatuses": []any{map[string]any{"name": "app", "ready": true, "started": true, "restartCount": float64(0),
				"state": map[string]any{"running": map[string]any{"startedAt": "2026-07-27T00:00:05Z"}}}},
		},
	}
	if err := db.ObservePodLifecycle(ctx, item); err != nil {
		t.Fatal(err)
	}
	event := K8sEvent{ClusterID: "c1", EventUID: "probe-1", InvolvedObjectUID: item.UID, InvolvedKind: "Pod", Type: "Warning",
		Reason: "Unhealthy", Message: "Readiness probe failed: connection refused", FirstSeen: "2026-07-27T00:14:07Z", LastSeen: "2026-07-27T00:14:07Z"}
	if err := db.UpsertK8sEventHistory(ctx, event); err != nil {
		t.Fatal(err)
	}

	item.ObservedAt = "2026-07-27T00:17:21Z"
	item.StatusObject = map[string]any{
		"phase":      "Running",
		"conditions": []any{map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": "2026-07-27T00:17:21Z"}},
		"containerStatuses": []any{map[string]any{"name": "app", "ready": true, "started": true, "restartCount": float64(1),
			"containerID": "containerd://second",
			"state":       map[string]any{"running": map[string]any{"startedAt": "2026-07-27T00:14:11Z"}},
			"lastState":   map[string]any{"terminated": map[string]any{"startedAt": "2026-07-27T00:00:05Z", "finishedAt": "2026-07-27T00:14:08Z", "exitCode": float64(137), "reason": "Error"}}}},
	}
	if err := db.ObservePodLifecycle(ctx, item); err != nil {
		t.Fatal(err)
	}

	failures, err := db.ListK8sPodFailureIntervals(ctx, "c1", item.UID, item.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 || failures[0].FailureCategory != "probe_failed" || failures[0].FailureDurationMS != 194000 {
		t.Fatalf("unexpected failure intervals: %+v", failures)
	}
	conditions, err := db.ListK8sPodConditionTransitions(ctx, "c1", item.UID)
	if err != nil {
		t.Fatal(err)
	}
	if len(conditions) != 1 {
		t.Fatalf("unchanged Ready=True must not duplicate condition transitions: %+v", conditions)
	}
	containers, err := db.ListK8sContainerLifecycles(ctx, "c1", item.UID)
	if err != nil {
		t.Fatal(err)
	}
	if len(containers) != 2 || containers[0].RestartNo != 0 || containers[0].FinishedAt == "" || containers[1].RestartNo != 1 {
		t.Fatalf("restart generations were not reconstructed: %+v", containers)
	}
	containerTransitions, err := db.ListK8sContainerStateTransitions(ctx, "c1", item.UID)
	if err != nil {
		t.Fatal(err)
	}
	foundTermination := false
	for _, transition := range containerTransitions {
		if transition.RestartNo == 0 && transition.Property == "state" && transition.CurrentValue == "terminated" {
			foundTermination = true
		}
	}
	if !foundTermination {
		t.Fatalf("previous generation termination missing: %+v", containerTransitions)
	}
	lifecycle, err := db.GetK8sPodLifecycleByName(ctx, "c1", "apps", "api-0", item.UID)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle.FailureDurationMS != 194000 || lifecycle.DegradedDurationMS != 194000 {
		t.Fatalf("durations not accumulated: %+v", lifecycle)
	}
}
