package proxy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// An administrator disabling an account is an explicit decision, and the admin
// path revokes that account's live sessions when it is applied. SSO login used to
// undo it in one click:
//
//	_ = s.db.UpdateAuthUserRoleStatus(ctx, user.ID, newRole, "active")
//
// The status was forced to "active" unconditionally on every SSO sign-in, so a
// disabled user simply pressed "sign in with SSO" and came back fully restored,
// role and all — while local login refused the same account outright. Account
// status is enforced in exactly two places (local login and refresh rotation)
// and in neither of the SSO paths, so nothing downstream caught it either.
func TestSSOLoginCannotReviveADisabledAccount(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID, sub = "usr_sso_disabled", "kc-sub-disabled"
	mustCreateUser(t, db, userID, "disabled@example.com", "admin")
	srv.finishKeycloakLink(ctx, userID, sub, "disabled@example.com", "disabled", "")
	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "", "disabled"); err != nil {
		t.Fatal(err)
	}

	_, _, err := srv.provisionKeycloakUser(ctx, map[string]any{
		"sub": sub, "email": "disabled@example.com", "name": "Disabled User",
	})
	if err == nil {
		t.Fatal("SSO login was allowed for a disabled account; the administrator's disable is undone by a single sign-in")
	}

	after, ok, _ := db.AuthUserByID(ctx, userID)
	if !ok {
		t.Fatal("user vanished")
	}
	if after.Status != "disabled" {
		t.Fatalf("status is now %q; the SSO path re-activated an account an administrator disabled", after.Status)
	}
}

// The same gate must hold on the email-merge branch, which links a local account
// to a Keycloak subject it has never seen before.
func TestSSOEmailMergeCannotReviveADisabledAccount(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID = "usr_local_disabled"
	mustCreateUser(t, db, userID, "merge@example.com", "admin")
	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "", "disabled"); err != nil {
		t.Fatal(err)
	}

	// No linked identity: this reaches the merge-by-email branch.
	if _, _, err := srv.provisionKeycloakUser(ctx, map[string]any{
		"sub": "kc-sub-never-seen", "email": "merge@example.com",
	}); err == nil {
		t.Fatal("SSO email merge was allowed for a disabled account")
	}
}

// An active account must still sign in, and an explicit role from the IdP must
// still be applied — the fix must not turn the role sync off.
func TestSSOLoginStillWorksForAnActiveAccount(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID, sub = "usr_sso_active", "kc-sub-active"
	mustCreateUser(t, db, userID, "active@example.com", "member")
	srv.finishKeycloakLink(ctx, userID, sub, "active@example.com", "active", "")

	user, _, err := srv.provisionKeycloakUser(ctx, map[string]any{
		"sub": sub, "email": "active@example.com",
	})
	if err != nil {
		t.Fatalf("active account was refused: %v", err)
	}
	if user.ID != userID {
		t.Fatalf("resolved %q, want %q", user.ID, userID)
	}
	after, _, _ := db.AuthUserByID(ctx, userID)
	if after.Status != "active" {
		t.Fatalf("an active account's status changed to %q", after.Status)
	}
}

func mustCreateUser(t *testing.T, db *store.SQLStore, id, email, role string) {
	t.Helper()
	if err := db.CreateAuthUser(context.Background(), store.AuthUser{
		ID: id, Email: email, Name: email, Role: role, Status: "active",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func newSSOTestServer(t *testing.T) (*Server, *store.SQLStore) {
	t.Helper()
	db, err := store.Open(context.Background(), config.DatabaseConfig{
		Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "gateway.db"),
	})
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
	cfg.Keycloak.Enabled = true
	cfg.Keycloak.IssuerURL = "https://kc.example.invalid/realms/test"
	cfg.Keycloak.ClientID = "clustara"
	cfg.Keycloak.DefaultRole = "member"

	srv, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv, db
}
