package proxy

import (
	"context"
	"testing"
	"time"

	"clustara/internal/store"
)

const reconcileStackManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  replicas: 1
`

// The reconciler already refuses to render a health verdict from inventory it
// does not trust: when serviceInventoryFreshness reports anything but
// "observed", health becomes "collecting" and the instance status is left alone.
//
// Freshness catches inventory that is old. It cannot catch inventory that is
// incomplete. A truncated window drops declared components, which are recorded
// "missing" and drive the verdict down — and unlike the drift report, this
// verdict is written back onto the instance row.
func TestReconcileTreatsATruncatedInventoryAsNotObserved(t *testing.T) {
	srv, db, _ := newServiceUnwindStore(t)
	ctx := context.Background()
	instance := seedReconcileInstance(t, db)

	original := serviceReconcileScanBudget
	serviceReconcileScanBudget = 1
	t.Cleanup(func() { serviceReconcileScanBudget = original })

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, name := range []string{"api", "sidecar"} {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID: "inv_" + name, ClusterID: "c1", Kind: "Deployment", Namespace: "prod",
			Name: name, Status: "observed", ObservedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	result, err := srv.reconcileServiceInstance(ctx, instance, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Health.CollectionStatus == "observed" {
		t.Fatalf("collection status = %q with a truncated inventory; a window that drops declared "+
			"components produces 'missing' entries that are actually deployed", result.Health.CollectionStatus)
	}
	if result.Health.Status != "collecting" {
		t.Fatalf("health = %q, want collecting: a verdict must not be rendered from an incomplete view",
			result.Health.Status)
	}
	if result.Instance.Status != instance.Status {
		t.Fatalf("instance status was overwritten to %q from a truncated view (was %q)",
			result.Instance.Status, instance.Status)
	}
}

// A complete, fresh inventory must still produce a real verdict, or the guard
// would simply disable the reconciler.
func TestReconcileStillJudgesACompleteInventory(t *testing.T) {
	srv, db, _ := newServiceUnwindStore(t)
	ctx := context.Background()
	instance := seedReconcileInstance(t, db)

	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "inv_api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod",
		Name: "api", Status: "observed", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	result, err := srv.reconcileServiceInstance(ctx, instance, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Health.CollectionStatus != "observed" {
		t.Fatalf("collection status = %q for a complete, fresh inventory", result.Health.CollectionStatus)
	}
	if result.Health.Status == "collecting" {
		t.Fatal("a complete inventory must produce a real verdict, not 'collecting'")
	}
}

func seedReconcileInstance(t *testing.T, db *store.SQLStore) store.K8sServiceInstance {
	t.Helper()
	ctx := context.Background()
	if _, _, err := db.UpsertK8sStack(ctx, store.K8sApplicationStack{
		ID: "stack_rec", Name: "rec", ClusterID: "c1", Namespace: "prod",
		SourceType: "manifest", Manifest: reconcileStackManifest, Status: "saved",
	}, func(p string) string { return p + "_x" }); err != nil {
		t.Fatal(err)
	}
	instance := store.K8sServiceInstance{
		ID: "svcinst_rec", ClusterID: "c1", Namespace: "prod", StackID: "stack_rec",
		Name: "api", Status: "validating", CreatedBy: "tester",
	}
	if err := db.UpsertK8sServiceInstance(ctx, instance); err != nil {
		t.Fatal(err)
	}
	return instance
}
