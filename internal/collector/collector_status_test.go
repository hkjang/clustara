package collector

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
	"clustara/internal/store"
)

func openCollectorStatusStore(t *testing.T) *store.SQLStore {
	t.Helper()
	db, err := store.Open(context.Background(), config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    filepath.Join(t.TempDir(), "collector.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// The watch agent recorded nothing in the collector health table, so an agent
// failing every batch was invisible on the operator surface while the snapshot
// collector's older "ok" was all that showed.
func TestAgentBatchRecordsCollectorHealth(t *testing.T) {
	db := openCollectorStatusStore(t)
	ctx := context.Background()

	if _, err := ApplyAgentBatch(ctx, db, AgentBatch{
		ClusterID: "c1", AgentID: "agent-1", ObservedAt: "2026-01-01T00:00:00Z",
	}, nil); err != nil {
		t.Fatalf("empty batch should succeed: %v", err)
	}
	rows, err := db.ListK8sCollectorStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var agent *store.K8sCollectorStatus
	for i := range rows {
		if rows[i].Collector == "agent" {
			agent = &rows[i]
		}
	}
	if agent == nil {
		t.Fatalf("the agent ingestion path reported no collector health: %+v", rows)
	}
	if agent.Status != "ok" || agent.LastSuccessAt != "2026-01-01T00:00:00Z" {
		t.Errorf("unexpected agent health: %+v", *agent)
	}
}

// A batch rejected before ingestion has no cluster to attribute health to, and must
// not create a phantom row.
func TestAgentBatchWithoutClusterRecordsNothing(t *testing.T) {
	db := openCollectorStatusStore(t)
	ctx := context.Background()
	if _, err := ApplyAgentBatch(ctx, db, AgentBatch{AgentID: "agent-1"}, nil); err == nil {
		t.Fatal("a batch without cluster_id must be rejected")
	}
	rows, err := db.ListK8sCollectorStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no collector rows, got %+v", rows)
	}
}
