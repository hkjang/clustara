package collector

import (
	"context"
	"testing"

	"clustara/internal/store"
)

func TestApplySnapshotFullSyncPrunesMissingInventory(t *testing.T) {
	ctx := context.Background()
	db := openAgentTestStore(t)

	pod := func(name string) store.K8sInventoryItem {
		return store.K8sInventoryItem{Kind: "Pod", Namespace: "ns", Name: name, Spec: map[string]any{"name": name}}
	}

	if _, err := ApplySnapshot(ctx, db, Snapshot{
		ClusterID:     "c1",
		FullSync:      true,
		FullSyncKinds: []string{"Pod"},
		Resources:     []store.K8sInventoryItem{pod("p1"), pod("p2")},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: "c1", Kind: "Pod", Limit: 10}); len(got) != 2 {
		t.Fatalf("initial full sync should store 2 pods, got %d", len(got))
	}

	res, err := ApplySnapshot(ctx, db, Snapshot{
		ClusterID:     "c1",
		FullSync:      true,
		FullSyncKinds: []string{"Pod"},
		Resources:     []store.K8sInventoryItem{pod("p1")},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StaleDeleted != 1 {
		t.Fatalf("expected one stale pod to be pruned, got %+v", res)
	}
	got, _ := db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: "c1", Kind: "Pod", Limit: 10})
	if len(got) != 1 || got[0].Name != "p1" {
		t.Fatalf("after prune only p1 should remain: %+v", got)
	}
}

func TestApplySnapshotPartialDoesNotPruneMissingInventory(t *testing.T) {
	ctx := context.Background()
	db := openAgentTestStore(t)

	pod := func(name string) store.K8sInventoryItem {
		return store.K8sInventoryItem{Kind: "Pod", Namespace: "ns", Name: name, Spec: map[string]any{"name": name}}
	}

	if _, err := ApplySnapshot(ctx, db, Snapshot{
		ClusterID: "c1",
		Resources: []store.K8sInventoryItem{pod("p1"), pod("p2")},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplySnapshot(ctx, db, Snapshot{
		ClusterID: "c1",
		Resources: []store.K8sInventoryItem{pod("p1")},
	}, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: "c1", Kind: "Pod", Limit: 10})
	if len(got) != 2 {
		t.Fatalf("partial snapshot must not prune p2, got %+v", got)
	}
}
