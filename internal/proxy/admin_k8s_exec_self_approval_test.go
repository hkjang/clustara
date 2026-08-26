package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func selfApprovalFixture(t *testing.T, requestedBy string) (*httptest.Server, *store.SQLStore, string) {
	t.Helper()
	ctx := context.Background()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	sess := store.K8sPodExecSession{
		ID: "sess-1", ClusterID: "c1", Namespace: "prod", Pod: "api-1", Container: "app",
		Command: "/bin/sh", Role: "admin", RequestedBy: requestedBy, Status: "pending_approval",
		RequireApproval: true, AuditEnabled: true, MaxSessionMinutes: 15,
		PolicyResult: `{"access_mode":"terminal"}`,
	}
	if err := db.CreateK8sPodExecSession(ctx, &sess); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)
	return ts, db, sess.ID
}

// postExecCommand acts as a specific administrator. adminID derives the actor
// from the bearer token, so distinct tokens are distinct identities.
func postExecCommand(t *testing.T, ts *httptest.Server, id, command, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/k8s/exec/sessions/"+id+"/"+command, strings.NewReader(`{"note":"n"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// execActorID mirrors adminID's bearer-token derivation so a fixture can be
// created as a specific administrator.
func execActorID(token string) string {
	return "admin_" + hashProxyKey(token)[:12]
}

// The policy engine asked for a second pair of eyes on this session. Without
// this check the requester supplies them, which makes RequireApproval a control
// that never actually applies.
func TestExecSessionRequesterCannotApproveOwnRequest(t *testing.T) {
	ctx := context.Background()
	ts, db, id := selfApprovalFixture(t, execActorID("requester-token"))

	status, body := postExecCommand(t, ts, id, "approve", "requester-token")
	if status != http.StatusForbidden {
		t.Fatalf("self-approval returned %d: %s", status, body)
	}
	if !strings.Contains(body, "exec_session_self_approval") {
		t.Fatalf("body = %s, want the self-approval code", body)
	}

	sess, err := db.GetK8sPodExecSession(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != "pending_approval" {
		t.Fatalf("session status = %q, want it left awaiting a real approver", sess.Status)
	}
}

// A different administrator still approves normally.
func TestExecSessionAnotherAdminCanApprove(t *testing.T) {
	ctx := context.Background()
	ts, db, id := selfApprovalFixture(t, execActorID("requester-token"))

	status, body := postExecCommand(t, ts, id, "approve", "approver-token")
	if status != http.StatusOK {
		t.Fatalf("approval by another admin returned %d: %s", status, body)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	sess, err := db.GetK8sPodExecSession(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != "ready" {
		t.Fatalf("session status = %q, want ready", sess.Status)
	}
}

// Withdrawing your own request grants no access, so rejecting it stays allowed.
func TestExecSessionRequesterCanRejectOwnRequest(t *testing.T) {
	ctx := context.Background()
	ts, db, id := selfApprovalFixture(t, execActorID("requester-token"))

	status, body := postExecCommand(t, ts, id, "reject", "requester-token")
	if status != http.StatusOK {
		t.Fatalf("self-rejection returned %d: %s", status, body)
	}
	sess, err := db.GetK8sPodExecSession(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != "rejected" {
		t.Fatalf("session status = %q, want rejected", sess.Status)
	}
}

// With admin auth disabled every caller is "anonymous", so there are no two
// identities to separate. Blocking there would stop every approval without
// making anything safer, so the rule deliberately does not apply.
func TestExecSessionSelfApprovalRuleNeedsIdentities(t *testing.T) {
	ctx := context.Background()
	ts, db, id := selfApprovalFixture(t, "anonymous")

	status, body := postExecCommand(t, ts, id, "approve", "")
	if status != http.StatusOK {
		t.Fatalf("approval without identities returned %d: %s", status, body)
	}
	sess, err := db.GetK8sPodExecSession(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != "ready" {
		t.Fatalf("session status = %q, want ready", sess.Status)
	}
}
