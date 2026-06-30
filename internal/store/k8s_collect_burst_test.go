package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
)

func openCollectBurstTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "burst.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestK8sCollectBurstActiveAndPrune(t *testing.T) {
	ctx := context.Background()
	db := openCollectBurstTestStore(t)
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	rfc := func(tm time.Time) string { return tm.Format(time.RFC3339Nano) }

	// One active (expires in the future), one expired.
	if err := db.RegisterK8sCollectBurst(ctx, K8sCollectBurst{
		ID: "b1", ClusterID: "c1", Namespace: "ns1", Trigger: "stack_apply",
		StartedAt: rfc(now.Add(-1 * time.Minute)), ExpiresAt: rfc(now.Add(4 * time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.RegisterK8sCollectBurst(ctx, K8sCollectBurst{
		ID: "b2", ClusterID: "c2", Namespace: "ns2", Trigger: "action",
		StartedAt: rfc(now.Add(-10 * time.Minute)), ExpiresAt: rfc(now.Add(-5 * time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}

	active, err := db.ListActiveK8sCollectBursts(ctx, "", rfc(now))
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != "b1" {
		t.Fatalf("only b1 should be active: %+v", active)
	}

	// Cluster filter excludes the active one when querying a different cluster.
	if got, _ := db.ListActiveK8sCollectBursts(ctx, "c2", rfc(now)); len(got) != 0 {
		t.Fatalf("c2 has no active burst: %+v", got)
	}

	// Prune removes expired rows (b2) but keeps the still-active b1.
	if err := db.PruneExpiredK8sCollectBursts(ctx, rfc(now)); err != nil {
		t.Fatal(err)
	}
	all, _ := db.ListActiveK8sCollectBursts(ctx, "", rfc(now))
	if len(all) != 1 || all[0].ID != "b1" {
		t.Fatalf("prune should keep only the unexpired b1: %+v", all)
	}
}
