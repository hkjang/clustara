package store

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"clustara/internal/config"
)

func openStackTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "stack.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestK8sStackUpsertRevisions(t *testing.T) {
	ctx := context.Background()
	db := openStackTestStore(t)
	n := 0
	id := func(p string) string { n++; return p + "_" + strconv.Itoa(n) } // unique per call

	// Create.
	st, isNew, err := db.UpsertK8sStack(ctx, K8sApplicationStack{
		Name: "web", ClusterID: "c1", Namespace: "prod", Manifest: "kind: Deployment", ManifestHash: "h1",
	}, id)
	if err != nil || !isNew || st.RevisionNo != 1 {
		t.Fatalf("create should be new rev1: %+v new=%v err=%v", st, isNew, err)
	}

	// Update with SAME hash → no new revision.
	st2, isNew2, err := db.UpsertK8sStack(ctx, K8sApplicationStack{
		ID: st.ID, Name: "web", ClusterID: "c1", Namespace: "prod", Manifest: "kind: Deployment", ManifestHash: "h1",
	}, id)
	if err != nil || isNew2 || st2.RevisionNo != 1 {
		t.Fatalf("same-hash update should stay rev1: %+v", st2)
	}

	// Update with NEW hash → revision bumps to 2.
	st3, _, err := db.UpsertK8sStack(ctx, K8sApplicationStack{
		ID: st.ID, Name: "web", ClusterID: "c1", Namespace: "prod", Manifest: "kind: Deployment\n# changed", ManifestHash: "h2",
	}, id)
	if err != nil || st3.RevisionNo != 2 {
		t.Fatalf("changed-hash update should bump to rev2: %+v", st3)
	}

	revs, err := db.ListK8sStackRevisions(ctx, st.ID, 50)
	if err != nil || len(revs) != 2 {
		t.Fatalf("expected 2 revisions, got %d (%v)", len(revs), err)
	}
	if revs[0].RevisionNo != 2 || revs[1].RevisionNo != 1 {
		t.Fatalf("revisions should be newest-first: %+v", revs)
	}

	// List + Get.
	list, _ := db.ListK8sStacks(ctx, "c1")
	if len(list) != 1 {
		t.Fatalf("expected 1 stack, got %d", len(list))
	}
	got, err := db.GetK8sStack(ctx, st.ID)
	if err != nil || got.RevisionNo != 2 || got.ManifestHash != "h2" {
		t.Fatalf("get should reflect latest: %+v %v", got, err)
	}

	// Delete cascades revisions.
	if err := db.DeleteK8sStack(ctx, st.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetK8sStack(ctx, st.ID); err != ErrNotFound {
		t.Fatalf("stack should be gone: %v", err)
	}
	if revs, _ := db.ListK8sStackRevisions(ctx, st.ID, 50); len(revs) != 0 {
		t.Fatalf("revisions should be deleted with the stack, got %d", len(revs))
	}
}
