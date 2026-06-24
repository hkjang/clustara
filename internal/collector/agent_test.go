package collector

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
	"clustara/internal/store"
)

func openAgentTestStore(t *testing.T) *store.SQLStore {
	t.Helper()
	db, err := store.Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestApplyAgentBatch(t *testing.T) {
	ctx := context.Background()
	db := openAgentTestStore(t)

	pod := func(name string, spec map[string]any) store.K8sInventoryItem {
		return store.K8sInventoryItem{Kind: "Pod", Namespace: "ns", Name: name, Spec: spec}
	}

	// Batch 1: two ADDED pods + heartbeat.
	res, err := ApplyAgentBatch(ctx, db, AgentBatch{
		ClusterID: "c1", AgentID: "a1", Version: "v1", ResourceVersion: "100", WatchLagMS: 40, EventsTotal: 2,
		Events: []AgentEvent{
			{Type: AgentAdded, Object: pod("p1", map[string]any{"replicas": 1})},
			{Type: AgentAdded, Object: pod("p2", nil)},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upserted != 2 || res.Revisions != 2 {
		t.Fatalf("batch1 upserted/revisions: %+v", res)
	}
	if got, _ := db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: "c1"}); len(got) != 2 {
		t.Fatalf("expected 2 inventory items, got %d", len(got))
	}

	// Batch 2: MODIFY p1 (spec change → new revision), DELETE p2.
	res, err = ApplyAgentBatch(ctx, db, AgentBatch{
		ClusterID: "c1", AgentID: "a1", Version: "v1", ResourceVersion: "150", EventsTotal: 4, Reconnects: 1,
		Events: []AgentEvent{
			{Type: AgentModified, Object: pod("p1", map[string]any{"replicas": 3})},
			{Type: AgentDeleted, Object: pod("p2", nil)},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upserted != 1 || res.Deleted != 1 || res.Revisions != 1 {
		t.Fatalf("batch2 result: %+v", res)
	}
	got, _ := db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: "c1"})
	if len(got) != 1 || got[0].Name != "p1" {
		t.Fatalf("after delete only p1 should remain: %+v", got)
	}

	// Heartbeat reflects the latest batch.
	hbs, _ := db.ListK8sAgentHeartbeats(ctx, "c1")
	if len(hbs) != 1 || hbs[0].LastResourceVersion != "150" || hbs[0].Reconnects != 1 || hbs[0].EventsReceived != 4 {
		t.Fatalf("heartbeat not updated: %+v", hbs)
	}
}

func TestApplyAgentBatchValidation(t *testing.T) {
	ctx := context.Background()
	db := openAgentTestStore(t)
	if _, err := ApplyAgentBatch(ctx, db, AgentBatch{AgentID: "a1"}, nil); err == nil {
		t.Fatal("expected error when cluster_id is empty")
	}
	if _, err := ApplyAgentBatch(ctx, db, AgentBatch{ClusterID: "c1"}, nil); err == nil {
		t.Fatal("expected error when agent_id is empty")
	}

	// Heartbeat-only batch (no events) still records liveness.
	res, err := ApplyAgentBatch(ctx, db, AgentBatch{ClusterID: "c1", AgentID: "a1", ResourceVersion: "5"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upserted != 0 {
		t.Fatalf("heartbeat-only batch should upsert nothing: %+v", res)
	}
	if hbs, _ := db.ListK8sAgentHeartbeats(ctx, "c1"); len(hbs) != 1 {
		t.Fatalf("heartbeat-only batch should record a heartbeat, got %d", len(hbs))
	}
}
