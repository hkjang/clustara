package proxy

import (
	"testing"
	"time"

	"clustara/internal/store"
)

// Everything about the operator's credential is validated when the ticket is
// consumed, but a full-TTY terminal then runs for up to ten minutes. The ticket
// row carried AuthSessionID and AuthExpiresAt for exactly this purpose, yet
// consumeTerminalTicket dropped both, so nothing could re-check them and a
// revoked operator kept a live root shell until the session cap expired.
func TestConsumedTicketCarriesTheAuthBindingForward(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	createReadyTerminalTestSession(t, db, "session-carry")
	if err := db.CreateAuthUser(t.Context(), store.AuthUser{
		ID: "usr_operator", Email: "operator@example.com", PasswordHash: "unused", Role: "super_admin", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertAuthSession(t.Context(), "auth-session", "usr_operator", "192.0.2.1", "terminal-test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	authExpiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := db.CreateK8sTerminalTicket(t.Context(), "carry", store.K8sTerminalTicket{
		SessionID: "session-carry", AdminID: "usr_operator", AuthSessionID: "auth-session",
		AuthExpiresAt: authExpiry, ClientIP: "192.0.2.1",
		UserAgentHash: hashProxyKey("terminal-test"), ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	auth, ok := s.consumeTerminalTicket(terminalTestRequest("/admin/k8s/exec/sessions/session-carry/stream?ticket=carry"), "session-carry", "carry")
	if !ok {
		t.Fatal("valid ticket must be consumable")
	}
	if auth.AuthSessionID != "auth-session" {
		t.Errorf("auth session binding lost: got %q", auth.AuthSessionID)
	}
	if !auth.AuthExpiresAt.Equal(authExpiry) {
		t.Errorf("credential expiry lost: got %v want %v", auth.AuthExpiresAt, authExpiry)
	}
}

// The live-stream re-check must treat revocation and expiry as definite denials,
// and must not deny a terminal opened with a legacy admin token, which has no
// auth session to check.
func TestTerminalAuthStillValidTracksTheOperatorCredential(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	if err := db.CreateAuthUser(t.Context(), store.AuthUser{
		ID: "usr_operator", Email: "operator@example.com", PasswordHash: "unused", Role: "super_admin", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertAuthSession(t.Context(), "auth-live", "usr_operator", "192.0.2.1", "terminal-test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	live := terminalStreamAuth{AuthSessionID: "auth-live", AuthExpiresAt: time.Now().Add(time.Hour)}

	if valid, indeterminate := s.terminalAuthStillValid(live); !valid || indeterminate {
		t.Fatalf("active credential must stay valid: valid=%v indeterminate=%v", valid, indeterminate)
	}

	// Legacy admin-token terminals carry no session and no expiry; they must not be
	// closed by the re-check.
	if valid, indeterminate := s.terminalAuthStillValid(terminalStreamAuth{}); !valid || indeterminate {
		t.Fatalf("terminal without an auth session must stay valid: valid=%v indeterminate=%v", valid, indeterminate)
	}

	expired := live
	expired.AuthExpiresAt = time.Now().Add(-time.Second)
	if valid, indeterminate := s.terminalAuthStillValid(expired); valid || indeterminate {
		t.Fatalf("expired credential must be a definite denial: valid=%v indeterminate=%v", valid, indeterminate)
	}

	if err := db.RevokeAuthSession(t.Context(), "auth-live"); err != nil {
		t.Fatal(err)
	}
	if valid, indeterminate := s.terminalAuthStillValid(live); valid || indeterminate {
		t.Fatalf("revoked session must be a definite denial: valid=%v indeterminate=%v", valid, indeterminate)
	}
}

// A verification failure the server cannot resolve (DB unreachable) must be
// reported as indeterminate, so the caller tolerates a blip but still closes the
// terminal once it persists.
func TestTerminalAuthLookupFailureIsIndeterminate(t *testing.T) {
	db := openTestStore(t)
	s := &Server{db: db}
	db.Close()
	valid, indeterminate := s.terminalAuthStillValid(terminalStreamAuth{AuthSessionID: "auth-gone"})
	if valid || !indeterminate {
		t.Fatalf("unreachable store must be indeterminate, not authorized: valid=%v indeterminate=%v", valid, indeterminate)
	}
	if terminalAuthLapseTolerance < 2 {
		t.Fatal("tolerance must allow at least one transient failure")
	}
}
