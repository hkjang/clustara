package store

import (
	"context"
	"errors"
	"testing"
)

func manifestRollbackSource(t *testing.T, db *SQLStore, id, status string) K8sManifestChangeRequest {
	t.Helper()
	ctx := context.Background()
	req := K8sManifestChangeRequest{
		ID: id, ClusterID: "c1", Namespace: "prod", Kind: "Deployment", APIVersion: "apps/v1",
		Name: "api", Status: "draft", RiskLevel: "low", BeforeYAML: "before", AfterYAML: "after",
		BeforeHash: "h1", AfterHash: "h2", CreatedBy: "admin-1",
	}
	if err := db.CreateK8sManifestChangeRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if status != "draft" {
		if _, err := db.db.ExecContext(ctx, db.bind(`UPDATE k8s_manifest_change_requests SET status=? WHERE id=?`), status, id); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := db.GetK8sManifestChangeRequest(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func rollbackCandidate(id string) K8sManifestChangeRequest {
	return K8sManifestChangeRequest{
		ID: id, ClusterID: "c1", Namespace: "prod", Kind: "Deployment", APIVersion: "apps/v1",
		Name: "api", Status: "draft", RiskLevel: "low", RequiresApproval: true,
		BeforeYAML: "after", AfterYAML: "before", CreatedBy: "admin-1",
	}
}

func TestCreateK8sManifestRollbackRequestMarksTheSource(t *testing.T) {
	ctx := context.Background()
	db := openStoreForTest(t)
	source := manifestRollbackSource(t, db, "src-1", "applied")

	if err := db.CreateK8sManifestRollbackRequest(ctx, source.ID, "admin-1", "rollback request: rb-1", rollbackCandidate("rb-1")); err != nil {
		t.Fatal(err)
	}
	updated, err := db.GetK8sManifestChangeRequest(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "rollback_requested" {
		t.Fatalf("source status = %q, want rollback_requested", updated.Status)
	}
	if _, err := db.GetK8sManifestChangeRequest(ctx, "rb-1"); err != nil {
		t.Fatalf("rollback request was not created: %v", err)
	}
}

// A source that cannot be rolled back must not leave a rollback request behind.
// Previously the guarded transition silently did nothing while the request was
// created anyway, and the caller reported success.
func TestCreateK8sManifestRollbackRequestRejectsIneligibleSource(t *testing.T) {
	ctx := context.Background()
	db := openStoreForTest(t)
	source := manifestRollbackSource(t, db, "src-2", "draft")

	err := db.CreateK8sManifestRollbackRequest(ctx, source.ID, "admin-1", "rollback request: rb-2", rollbackCandidate("rb-2"))
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition for a draft source", err)
	}
	if _, err := db.GetK8sManifestChangeRequest(ctx, "rb-2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a rollback request was created for a source that cannot be rolled back")
	}
	unchanged, err := db.GetK8sManifestChangeRequest(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status != "draft" {
		t.Fatalf("source status = %q, want it untouched", unchanged.Status)
	}
}

// Requesting a rollback twice must not create a second request: after the first
// call the source is no longer in a rollback-eligible state.
func TestCreateK8sManifestRollbackRequestIsNotRepeatable(t *testing.T) {
	ctx := context.Background()
	db := openStoreForTest(t)
	source := manifestRollbackSource(t, db, "src-3", "verified")

	if err := db.CreateK8sManifestRollbackRequest(ctx, source.ID, "admin-1", "rollback request: rb-3", rollbackCandidate("rb-3")); err != nil {
		t.Fatal(err)
	}
	err := db.CreateK8sManifestRollbackRequest(ctx, source.ID, "admin-1", "rollback request: rb-4", rollbackCandidate("rb-4"))
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second rollback error = %v, want ErrInvalidTransition", err)
	}
	if _, err := db.GetK8sManifestChangeRequest(ctx, "rb-4"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a duplicate rollback request was created for the same source")
	}
}

func TestCreateK8sManifestRollbackRequestReportsMissingSource(t *testing.T) {
	ctx := context.Background()
	db := openStoreForTest(t)
	if err := db.CreateK8sManifestRollbackRequest(ctx, "src-missing", "admin-1", "x", rollbackCandidate("rb-5")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}
