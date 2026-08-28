package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"

	_ "modernc.org/sqlite"
)

// A password change reports "sessions_revoked" to the caller and writes "all
// sessions revoked" into the audit trail. Both claims used to be printed
// unconditionally while the revocation error was discarded:
//
//	_ = s.db.RevokeAuthSessionsForUser(r.Context(), user.ID)
//	writeJSON(w, 200, map[string]any{..., "sessions_revoked": true})
//
// Session revocation is the only thing that stops an already-issued access
// token — password_changed_at is stored and displayed but never consulted
// during validation — so a discarded failure leaves the old session live. The
// user who just changed a compromised password is told the attacker was logged
// out, and the auditor later reads the same false record.
//
// The failure is injected with a trigger on the UPDATE, so SELECTs still work
// and the request reaches the revocation through the real code path.
func TestPasswordChangeReportsAFailedSessionRevocation(t *testing.T) {
	proxy, _, dbPath := newRevocationTestServer(t)

	token, _ := loginForAccessToken(t, proxy, "root@example.com", "correct-password")
	failSessionRevocation(t, dbPath)

	resp := postJSON(t, proxy.URL+"/auth/password/change", token, map[string]string{
		"current_password": "correct-password",
		"new_password":     "An0ther-Str0ng-Passw0rd!",
	})
	defer resp.Body.Close()

	// The password change itself committed before the revocation, so this stays 200.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password change: got %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["changed"] != true {
		t.Fatalf("password should still have changed: %v", body)
	}
	if body["sessions_revoked"] != false {
		t.Fatalf("sessions_revoked = %v, want false: the revocation failed, and reporting success here "+
			"tells a user whose password was just compromised that the attacker's session is gone when it is not", body["sessions_revoked"])
	}
}

// The healthy path must be unchanged: a successful revocation still reports true.
func TestPasswordChangeReportsASuccessfulSessionRevocation(t *testing.T) {
	proxy, _, _ := newRevocationTestServer(t)
	token, _ := loginForAccessToken(t, proxy, "root@example.com", "correct-password")

	resp := postJSON(t, proxy.URL+"/auth/password/change", token, map[string]string{
		"current_password": "correct-password",
		"new_password":     "An0ther-Str0ng-Passw0rd!",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password change: got %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["sessions_revoked"] != true {
		t.Fatalf("sessions_revoked = %v, want true on the healthy path", body["sessions_revoked"])
	}
}

// The store contract the handlers now rely on: a failed auth_sessions update is
// returned, because that row is what rotateRefreshToken re-checks and therefore
// what actually stops an issued token.
func TestRevokeAuthSessionsForUserReturnsTheSessionUpdateError(t *testing.T) {
	proxy, db, dbPath := newRevocationTestServer(t)
	// A live session is required: a BEFORE UPDATE trigger fires per matched row,
	// so with nothing to revoke the failure would never be injected and the test
	// would pass against any implementation.
	_, userID := loginForAccessToken(t, proxy, "root@example.com", "correct-password")
	failSessionRevocation(t, dbPath)
	if err := db.RevokeAuthSessionsForUser(context.Background(), userID); err == nil {
		t.Fatal("RevokeAuthSessionsForUser returned nil while the session update failed")
	}
}

// failSessionRevocation makes UPDATEs on auth_sessions fail while leaving SELECTs
// working, so the request reaches the revocation through the real code path
// instead of failing earlier at session validation.
func failSessionRevocation(t *testing.T, dbPath string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open store file: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER fail_session_revoke BEFORE UPDATE ON auth_sessions
		BEGIN SELECT RAISE(ABORT, 'injected revocation failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}

func newRevocationTestServer(t *testing.T) (*httptest.Server, *store.SQLStore, string) {
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
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := testConfig("http://example.invalid", "secret")
	cfg.Auth.Enabled = true
	cfg.Auth.JWTSecret = "test-jwt-secret"
	cfg.Auth.AccessTokenTTL = 15 * time.Minute
	cfg.Auth.RefreshTokenTTL = time.Hour
	cfg.Auth.APIKeyPrefix = "vc_sk_"
	cfg.Auth.ServiceKeyPrefix = "vc_sa_"
	cfg.Auth.BootstrapEmail = "root@example.com"
	cfg.Auth.BootstrapPassword = "correct-password"

	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	t.Cleanup(srv.Close)
	return srv, db, dbPath
}

func loginForAccessToken(t *testing.T, proxy *httptest.Server, email, password string) (string, string) {
	t.Helper()
	resp := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": email, "password": password})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		User        struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.AccessToken == "" || body.User.ID == "" {
		t.Fatalf("login returned no access token or user id: %+v", body)
	}
	return body.AccessToken, body.User.ID
}
