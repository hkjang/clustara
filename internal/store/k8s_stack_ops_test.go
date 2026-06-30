package store

import (
	"context"
	"testing"
)

func TestK8sStackOps(t *testing.T) {
	ctx := context.Background()
	db := openAgentSessionTestStore(t)

	// Create a stack with two revisions.
	st := K8sApplicationStack{Name: "web", ClusterID: "c1", Namespace: "prod", SourceType: "manifest", Manifest: "v1", ManifestHash: "h1", SyncPolicy: "manual", CreatedBy: "admin"}
	saved, isNew, err := db.UpsertK8sStack(ctx, st, func(p string) string { return p + "_1" })
	if err != nil || !isNew || saved.RevisionNo != 1 {
		t.Fatalf("first upsert: %+v new=%v err=%v", saved, isNew, err)
	}
	saved.Manifest, saved.ManifestHash = "v2", "h2"
	saved, _, err = db.UpsertK8sStack(ctx, saved, func(p string) string { return p + "_2" })
	if err != nil || saved.RevisionNo != 2 {
		t.Fatalf("second upsert revision = %d, want 2 (%v)", saved.RevisionNo, err)
	}

	// Fetch a specific revision.
	rev1, err := db.GetK8sStackRevision(ctx, saved.ID, 1)
	if err != nil || rev1.Manifest != "v1" {
		t.Fatalf("get revision 1: %+v %v", rev1, err)
	}
	if _, err := db.GetK8sStackRevision(ctx, saved.ID, 99); err != ErrNotFound {
		t.Fatalf("missing revision should be ErrNotFound, got %v", err)
	}

	// Status update.
	if err := db.SetK8sStackStatus(ctx, saved.ID, "applied"); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetK8sStack(ctx, saved.ID)
	if got.Status != "applied" {
		t.Fatalf("status = %q, want applied", got.Status)
	}
	if err := db.SetK8sStackStatus(ctx, "missing", "applied"); err != ErrNotFound {
		t.Fatalf("status on missing should be ErrNotFound, got %v", err)
	}

	// Apply history records.
	for _, h := range []K8sStackApplyHistory{
		{ID: "h1", StackID: saved.ID, Operation: "apply", RevisionNo: 2, ClusterID: "c1", Status: "success", Applied: 3},
		{ID: "h2", StackID: saved.ID, Operation: "rollback", RevisionNo: 3, Status: "success"},
	} {
		if err := db.InsertK8sStackApplyHistory(ctx, h); err != nil {
			t.Fatalf("insert history %s: %v", h.ID, err)
		}
	}
	hist, err := db.ListK8sStackApplyHistory(ctx, saved.ID, 50)
	if err != nil || len(hist) != 2 {
		t.Fatalf("expected 2 history rows, got %d (%v)", len(hist), err)
	}
}
