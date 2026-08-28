package proxy

import (
	"context"
	"net/http/httptest"
	"testing"

	"clustara/internal/store"
)

// The service operations ledger is read for decisions, not just display:
// jupyterHubBackupWorkspaceOwner recovers a restore's ownership evidence from it,
// and the approval and execution paths move rows by request id.
//
// Four of the five writers discarded the insert error, so a failed write left the
// request reporting success while its operation never appeared and the later
// status updates matched nothing. The reads are fail-closed — a missing row
// blocks the restore rather than misdirecting it — but nothing said the write had
// failed, so an operator would see a blocked restore with no explanation.
func TestServiceOperationLedgerWriteFailureIsReported(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	op := store.K8sServiceOperation{
		ID: "svcop_dup", ServiceInstanceID: "inst1", OperationType: "backup_workspace",
		Status: "pending_approval", RequestID: "req1", IdempotencyKey: "k1",
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
	}
	if err := db.InsertK8sServiceOperation(ctx, op); err != nil {
		t.Fatal(err)
	}

	// The same id again: a primary-key collision, standing in for any write failure.
	r := httptest.NewRequest("POST", "/admin/k8s/services/instances/inst1/backups", nil)
	if srv.recordServiceOperationRow(r, op) {
		t.Fatal("a failed ledger write reported success; the operation is missing from the " +
			"instance history and the later status updates will match nothing")
	}

	// The healthy path still reports success.
	op.ID, op.IdempotencyKey = "svcop_fresh", "k2"
	if !srv.recordServiceOperationRow(r, op) {
		t.Fatal("a successful ledger write reported failure")
	}
	ops, err := db.ListK8sServiceOperations(ctx, "inst1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("expected both rows in the ledger, got %d", len(ops))
	}
}
