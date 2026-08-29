package proxy

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/config"
	"clustara/internal/store"
)

// When policy demands approval the gateway answers 423 and hands the caller an approval id,
// both in the body and in X-Governance-Approval-ID, so a human can go and decide it. The
// insert that creates that approval had its error discarded, so on a write failure the id
// referred to nothing: the administrator asked to decide it got "approval not found", the
// request stayed blocked with no way forward, and nothing recorded that the approval had
// never been created.
//
// Measured before the fix: the gate returned allowed=false with a real-looking id, and
// GetApproval on that id came back found=false.
func TestApprovalGateDoesNotHandOutAPhantomID(t *testing.T) {
	db, server, dbPath := approvalFailureServer(t)
	failApprovalInsert(t, dbPath)

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	gctx := governanceContext{RequestID: "req_1", APIKeyID: "ak_1", SubjectType: "openai_request"}
	allowed, id, reason := server.governanceApprovalGate(r, gctx, "high risk")

	if allowed {
		t.Fatal("a request whose approval could not be recorded was allowed through; the policy " +
			"asked for an approval and none was obtained")
	}
	if id != "" {
		if _, found, err := db.GetApproval(context.Background(), id); err == nil && !found {
			t.Fatalf("the gate handed back approval id %q that exists nowhere; whoever is asked "+
				"to decide it will be told it does not exist", id)
		}
		t.Fatalf("approval id %q was returned even though the record could not be written", id)
	}
	if !strings.Contains(reason, "기록하지 못해") {
		t.Fatalf("the refusal must say the approval could not be recorded, got %q", reason)
	}
}

// The normal path must keep returning a real, findable id — the fix must not turn every
// approval into a failure.
func TestApprovalGateStillCreatesRealApprovals(t *testing.T) {
	db, server, _ := approvalFailureServer(t)

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	gctx := governanceContext{RequestID: "req_1", APIKeyID: "ak_1", SubjectType: "openai_request"}
	allowed, id, _ := server.governanceApprovalGate(r, gctx, "high risk")
	if allowed || id == "" {
		t.Fatalf("expected a blocked request carrying a new approval id, got allowed=%v id=%q", allowed, id)
	}
	approval, found, err := db.GetApproval(context.Background(), id)
	if err != nil || !found {
		t.Fatalf("the returned approval id is not in the store: found=%v err=%v", found, err)
	}
	if approval.Status != "pending" || approval.APIKeyID != "ak_1" {
		t.Fatalf("unexpected approval record: %+v", approval)
	}
}

func approvalFailureServer(t *testing.T) (*store.SQLStore, *Server, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	db, err := store.Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return db, server, dbPath
}

// failApprovalInsert makes INSERTs on approvals fail while leaving reads working, so the
// gate reaches the write through the real code path.
func failApprovalInsert(t *testing.T, dbPath string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open store file: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER fail_approval_insert BEFORE INSERT ON approvals
		BEGIN SELECT RAISE(ABORT, 'injected approval insert failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}
