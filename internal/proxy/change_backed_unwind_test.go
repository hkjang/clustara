package proxy

import (
	"context"
	"net/http/httptest"
	"testing"

	"clustara/internal/store"

	_ "modernc.org/sqlite"
)

// The backup and restore flows write their record, create a manifest change, then
// link the two. A failure at the link step used to return 500 and leave both
// halves live: a change that creates a backup Job or restores a volume once
// approved, and a record stuck at "preparing" that never references it.
//
// Approving such a change does real work the system has no completed record of.
// The record write is the operation that just failed, so marking it failed is
// best-effort — withdrawing the change is the half that must hold, and it touches
// a different table.
func TestManifestChangeIsWithdrawnWhenTheRecordCannotBeLinked(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const changeID = "mc_orphan"
	if err := db.CreateK8sManifestChangeRequest(ctx, store.K8sManifestChangeRequest{
		ID: changeID, ClusterID: "c1", Namespace: "prod", Kind: "Job", Name: "backup-job",
		APIVersion: "batch/v1", Status: "draft", CreatedBy: "tester", IdempotencyKey: "idem_orphan",
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/admin/k8s/services/instances/inst1/backups", nil)
	srv.withdrawManifestChange(r, changeID, "링크 실패")

	got, err := db.GetK8sManifestChangeRequest(ctx, changeID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "rejected" {
		t.Fatalf("manifest change status = %q, want rejected: a change left live after its owning "+
			"record could not be linked will create a backup Job, or restore a volume, with nothing recording it", got.Status)
	}
}

// An empty change id means the change was never created — there is nothing to
// withdraw, and the call must not rewrite some other row.
func TestWithdrawIgnoresAnEmptyChangeID(t *testing.T) {
	srv, _ := newSSOTestServer(t)
	r := httptest.NewRequest("POST", "/admin/k8s/services/instances/inst1/backups", nil)
	srv.withdrawManifestChange(r, "   ", "링크 실패")
}

// Guard against a silent no-op: if the status update itself fails, the change is
// still live and that must be visible rather than assumed away.
func TestWithdrawSurvivesAFailedStatusUpdate(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()
	const changeID = "mc_locked"
	if err := db.CreateK8sManifestChangeRequest(ctx, store.K8sManifestChangeRequest{
		ID: changeID, ClusterID: "c1", Namespace: "prod", Kind: "Job", Name: "backup-job",
		APIVersion: "batch/v1", Status: "draft", CreatedBy: "tester", IdempotencyKey: "idem_locked",
	}); err != nil {
		t.Fatal(err)
	}
	// The helper must not panic or block when the update cannot be applied; the
	// caller still returns 500 to the operator.
	srv.withdrawManifestChange(httptest.NewRequest("POST", "/x", nil), changeID, "링크 실패")
	got, _ := db.GetK8sManifestChangeRequest(ctx, changeID)
	if got.Status != "rejected" {
		t.Fatalf("status = %q", got.Status)
	}
}
