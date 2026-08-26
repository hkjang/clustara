package store

import (
	"context"
	"testing"
)

// Error writes carry no success timestamp. Overwriting last_success_at with that
// blank erased the one fact an operator needs during an incident — when this
// collector last actually worked — so the first failure destroyed the evidence.
func TestCollectorStatusErrorKeepsLastSuccess(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()

	if err := db.UpsertK8sCollectorStatus(ctx, K8sCollectorStatus{
		ID: "1", ClusterID: "c1", Collector: "snapshot", Status: "ok",
		LastSuccessAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sCollectorStatus(ctx, K8sCollectorStatus{
		ID: "2", ClusterID: "c1", Collector: "snapshot", Status: "error", LastError: "boom",
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListK8sCollectorStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one collector row, got %d", len(rows))
	}
	if rows[0].Status != "error" || rows[0].LastError != "boom" {
		t.Errorf("error was not recorded: %+v", rows[0])
	}
	if rows[0].LastSuccessAt != "2026-01-01T00:00:00Z" {
		t.Errorf("last success was erased by the error write: %q", rows[0].LastSuccessAt)
	}

	// A later success must move it forward.
	if err := db.UpsertK8sCollectorStatus(ctx, K8sCollectorStatus{
		ID: "3", ClusterID: "c1", Collector: "snapshot", Status: "ok",
		LastSuccessAt: "2026-01-02T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	rows, _ = db.ListK8sCollectorStatus(ctx, 10)
	if rows[0].LastSuccessAt != "2026-01-02T00:00:00Z" {
		t.Errorf("a real success must advance last_success_at, got %q", rows[0].LastSuccessAt)
	}
	if rows[0].LastError != "" {
		t.Errorf("a success must clear the last error, got %q", rows[0].LastError)
	}
}

// A collector that has never succeeded must be distinguishable from one that
// succeeded and then broke.
func TestCollectorStatusListsWorstFirst(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	for _, st := range []K8sCollectorStatus{
		{ID: "a", ClusterID: "c1", Collector: "snapshot", Status: "ok", LastSuccessAt: "2026-01-01T00:00:00Z"},
		{ID: "b", ClusterID: "c2", Collector: "agent", Status: "error", LastError: "watch closed"},
	} {
		if err := db.UpsertK8sCollectorStatus(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.ListK8sCollectorStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Status != "error" {
		t.Fatalf("failing collector must sort first: %+v", rows)
	}
	if rows[0].LastSuccessAt != "" {
		t.Errorf("a collector that never succeeded must report no last success, got %q", rows[0].LastSuccessAt)
	}
}
