package store

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func openK8sAgentTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestK8sAgentHeartbeatUpsertAndList(t *testing.T) {
	ctx := context.Background()
	db := openK8sAgentTestStore(t)

	if err := db.UpsertK8sAgentHeartbeat(ctx, K8sAgentHeartbeat{
		ClusterID: "c1", AgentID: "a1", Version: "v1", LastResourceVersion: "100",
		WatchLagMS: 50, EventsReceived: 10, Reconnects: 0, LastSeen: "2026-06-24T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	// Same key updates in place (no duplicate row).
	if err := db.UpsertK8sAgentHeartbeat(ctx, K8sAgentHeartbeat{
		ClusterID: "c1", AgentID: "a1", Version: "v2", LastResourceVersion: "250",
		WatchLagMS: 80, EventsReceived: 25, Reconnects: 1, LastSeen: "2026-06-24T00:01:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sAgentHeartbeat(ctx, K8sAgentHeartbeat{
		ClusterID: "c2", AgentID: "a2", LastSeen: "2026-06-24T00:02:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	all, err := db.ListK8sAgentHeartbeats(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 distinct agents, got %d", len(all))
	}
	c1, err := db.ListK8sAgentHeartbeats(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(c1) != 1 || c1[0].Version != "v2" || c1[0].LastResourceVersion != "250" || c1[0].EventsReceived != 25 || c1[0].Reconnects != 1 {
		t.Fatalf("upsert should overwrite in place: %+v", c1)
	}
}

func TestDeleteK8sInventoryItem(t *testing.T) {
	ctx := context.Background()
	db := openK8sAgentTestStore(t)
	item := K8sInventoryItem{ID: "i1", ClusterID: "c1", Kind: "Pod", Namespace: "ns", Name: "p1"}
	if err := db.UpsertK8sInventory(ctx, item); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ListK8sInventory(ctx, K8sInventoryFilter{ClusterID: "c1"}); len(got) != 1 {
		t.Fatalf("expected 1 item before delete, got %d", len(got))
	}
	if err := db.DeleteK8sInventoryItem(ctx, "c1", "Pod", "ns", "p1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ListK8sInventory(ctx, K8sInventoryFilter{ClusterID: "c1"}); len(got) != 0 {
		t.Fatalf("expected 0 items after delete, got %d", len(got))
	}
}

func TestK8sWatchEventsAndOffsets(t *testing.T) {
	ctx := context.Background()
	db := openK8sAgentTestStore(t)

	event := K8sWatchEvent{
		ID: "we1", EventKey: "c1/a1/100/MODIFIED/Pod/ns/p1", ClusterID: "c1", AgentID: "a1",
		EventType: "MODIFIED", ResourceVersion: "100", Kind: "Pod", Namespace: "ns", Name: "p1",
		ObservedAt: "2026-06-24T00:00:00Z", CreatedAt: "2026-06-24T00:00:00Z",
	}
	inserted, err := db.InsertK8sWatchEvent(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first watch event insert should be accepted")
	}
	dupe, err := db.InsertK8sWatchEvent(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if dupe {
		t.Fatal("duplicate watch event should be ignored by event_key")
	}
	recent, err := db.ListK8sWatchEvents(ctx, "c1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0].ResourceVersion != "100" {
		t.Fatalf("unexpected watch events: %+v", recent)
	}

	if err := db.UpsertK8sCollectorOffset(ctx, K8sCollectorOffset{
		ClusterID: "c1", AgentID: "a1", ResourceKind: "Pod", LastResourceVersion: "100",
		LastObservedAt: "2026-06-24T00:00:00Z", EventsSeen: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sCollectorOffset(ctx, K8sCollectorOffset{
		ClusterID: "c1", AgentID: "a1", ResourceKind: "Pod", LastResourceVersion: "120",
		LastObservedAt: "2026-06-24T00:01:00Z", EventsSeen: 2, DuplicateEvents: 1,
	}); err != nil {
		t.Fatal(err)
	}
	offsets, err := db.ListK8sCollectorOffsets(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(offsets) != 1 || offsets[0].LastResourceVersion != "120" || offsets[0].EventsSeen != 3 || offsets[0].DuplicateEvents != 1 {
		t.Fatalf("offset should accumulate counters and advance rv: %+v", offsets)
	}
}
