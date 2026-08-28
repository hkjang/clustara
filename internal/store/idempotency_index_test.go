package store

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every unique index on an idempotency_key must be partial on <> ”.
//
// The column defaults to the empty string, so a plain unique index makes the
// SECOND row that omits a key collide with the first. That failure is quiet
// where it matters most: four of the five writers of k8s_service_operations
// discard the insert error, so the operation would simply not appear in the
// ledger while the request reported success.
//
// idx_k8s_service_operations_idem was the one index written without the
// predicate its three siblings all carry. Every writer happens to default the
// key today, so this pins the shape rather than a live failure — and a new
// index, or a new writer that leaves the key empty, is exactly how it would
// become one.
func TestIdempotencyIndexesArePartial(t *testing.T) {
	raw, err := os.ReadFile("sqlstore.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)

	indexRe := regexp.MustCompile("CREATE UNIQUE INDEX[^`]*\\(\\s*idempotency_key\\s*\\)[^`]*")
	found := indexRe.FindAllString(src, -1)
	if len(found) < 4 {
		t.Fatalf("only %d idempotency indexes found; the scan is not matching the migrations", len(found))
	}
	for _, stmt := range found {
		if !strings.Contains(stmt, "WHERE") {
			t.Errorf("unique index on idempotency_key without a partial predicate:\n  %s\n"+
				"The column defaults to '', so the second keyless row collides with the first. "+
				"Add WHERE idempotency_key <> ''.", strings.TrimSpace(stmt))
		}
	}
}

// The behaviour the predicate buys: rows that carry no key are independent, while
// rows that do carry one are still deduplicated.
func TestKeylessServiceOperationsDoNotCollide(t *testing.T) {
	db := openStoreForTest(t)
	defer db.Close()
	ctx := context.Background()

	for _, id := range []string{"svcop_a", "svcop_b"} {
		if err := db.InsertK8sServiceOperation(ctx, K8sServiceOperation{
			ID: id, ServiceInstanceID: "inst1", OperationType: "restart", Status: "pending_approval",
			CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		}); err != nil {
			t.Fatalf("insert %s with no idempotency key: %v", id, err)
		}
	}

	if err := db.InsertK8sServiceOperation(ctx, K8sServiceOperation{
		ID: "svcop_keyed", ServiceInstanceID: "inst1", OperationType: "restart", Status: "pending_approval",
		IdempotencyKey: "key1", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sServiceOperation(ctx, K8sServiceOperation{
		ID: "svcop_keyed_dup", ServiceInstanceID: "inst1", OperationType: "restart", Status: "pending_approval",
		IdempotencyKey: "key1", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
	}); err == nil {
		t.Fatal("a repeated idempotency key was accepted; the index must still deduplicate keyed rows")
	}
}
