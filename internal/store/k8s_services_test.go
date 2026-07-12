package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
)

func openServiceStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "services.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

func TestServiceReconcileLeasePreventsDuplicateOwnersAndExpires(t *testing.T) {
	db := openServiceStore(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	acquired, err := db.TryAcquireK8sServiceReconcileLease(ctx, "svc-1", "pod-a", now, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("first lease acquire = %v, %v", acquired, err)
	}
	acquired, err = db.TryAcquireK8sServiceReconcileLease(ctx, "svc-1", "pod-b", now.Add(time.Second), time.Minute)
	if err != nil || acquired {
		t.Fatalf("second owner should be blocked = %v, %v", acquired, err)
	}
	acquired, err = db.TryAcquireK8sServiceReconcileLease(ctx, "svc-1", "pod-b", now.Add(2*time.Minute), time.Minute)
	if err != nil || !acquired {
		t.Fatalf("expired lease should be acquirable = %v, %v", acquired, err)
	}
	if err := db.ReleaseK8sServiceReconcileLease(ctx, "svc-1", "pod-a"); err != nil {
		t.Fatal(err)
	}
	acquired, err = db.TryAcquireK8sServiceReconcileLease(ctx, "svc-1", "pod-c", now.Add(2*time.Minute+time.Second), time.Minute)
	if err != nil || acquired {
		t.Fatalf("non-owner release must not clear current lease = %v, %v", acquired, err)
	}
}

func TestServiceInstancesDueAndHealthSnapshotPruning(t *testing.T) {
	db := openServiceStore(t)
	defer db.Close()
	ctx := context.Background()
	instance := K8sServiceInstance{ID: "svc-due", ClusterID: "c1", Namespace: "apps", CatalogID: "cat", VersionID: "ver", Name: "api", Status: "ready"}
	if err := db.UpsertK8sServiceInstance(ctx, instance); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListK8sServiceInstancesDue(ctx, time.Now().UTC().Format(time.RFC3339Nano), 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("instance without snapshot should be due: rows=%d err=%v", len(rows), err)
	}
	now := time.Now().UTC()
	if err := db.InsertK8sServiceHealthSnapshot(ctx, K8sServiceHealthSnapshot{ID: "health-new", ServiceInstanceID: instance.ID, ClusterID: "c1", Score: 100, Status: "ready", ObservedAt: now.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	rows, err = db.ListK8sServiceInstancesDue(ctx, now.Add(-time.Minute).Format(time.RFC3339Nano), 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("fresh snapshot must not be due: rows=%d err=%v", len(rows), err)
	}
	if err := db.InsertK8sServiceHealthSnapshot(ctx, K8sServiceHealthSnapshot{ID: "health-old", ServiceInstanceID: instance.ID, ClusterID: "c1", Score: 70, Status: "degraded", ObservedAt: now.Add(-48 * time.Hour).Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	pruned, err := db.PruneK8sServiceHealthSnapshots(ctx, now.Add(-24*time.Hour).Format(time.RFC3339Nano))
	if err != nil || pruned != 1 {
		t.Fatalf("expected one old snapshot pruned: count=%d err=%v", pruned, err)
	}
}
