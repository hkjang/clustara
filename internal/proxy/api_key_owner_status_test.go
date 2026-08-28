package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"clustara/internal/store"
)

// Disabling an account revokes its sessions, so the browser stops working at
// once. A personal API key carried no equivalent check: authentication looked at
// the key's own status, expiry, IP allowlist and scopes, but never at the
// account it belongs to — and nothing revoked the key on disable either.
//
// A departing user's programmatic access to models, spend and MCP tools
// therefore survived their offboarding completely, while the admin UI showed
// them as disabled.
func TestAPIKeyOfADisabledOwnerIsRefused(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID, rawKey = "usr_keyowner", "pcg_test_owner_key"
	mustCreateUser(t, db, userID, "keyowner@example.com", "member")
	mustCreateAPIKey(t, db, "ak_owner", userID, rawKey)

	// The key must work first, or the assertion below proves nothing.
	if _, _, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey)); !ok {
		t.Fatal("the key should authenticate while its owner is active")
	}

	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "", "disabled"); err != nil {
		t.Fatal(err)
	}

	if _, _, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey)); ok {
		t.Fatal("the API key still authenticates after its owner was disabled: " +
			"programmatic access to models, spend and tools outlives offboarding")
	}
}

// Re-enabling must restore the key. Enforcing at the gate rather than revoking
// keys on disable is what makes this reversible; a test pins that choice.
func TestAPIKeyWorksAgainWhenTheOwnerIsReEnabled(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID, rawKey = "usr_keyowner2", "pcg_test_owner_key_2"
	mustCreateUser(t, db, userID, "keyowner2@example.com", "member")
	mustCreateAPIKey(t, db, "ak_owner2", userID, rawKey)

	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey)); ok {
		t.Fatal("key accepted while the owner was disabled")
	}
	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "", "active"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey)); !ok {
		t.Fatal("the key stayed dead after the owner was re-enabled")
	}
}

// Keys with no owning user — service accounts, external/passthrough keys, and
// rows predating the user_id column — must be untouched by the join.
func TestOwnerlessAPIKeyIsUnaffected(t *testing.T) {
	srv, db := newSSOTestServer(t)
	const rawKey = "pcg_test_ownerless_key"
	mustCreateAPIKey(t, db, "ak_ownerless", "", rawKey)

	if _, _, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey)); !ok {
		t.Fatal("a key with no owning user was refused; the owner check must not apply to service accounts")
	}
}

func mustCreateAPIKey(t *testing.T, db *store.SQLStore, id, userID, raw string) {
	t.Helper()
	if err := db.UpsertAPIKey(context.Background(), store.APIKeyRecord{
		ID: id, Name: id, KeyHash: hashProxyKey(raw), Owner: userID, UserID: userID,
		Role: "member", Status: "active", Scopes: []string{"chat:completion", "models:read"},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func requestWithKey(t *testing.T, raw string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	return r
}

// An API key freezes the role and scopes it was minted with. Demoting a user
// updates the users row and revokes their sessions — the browser reflects the
// new boundary at once — but the key kept the old one. That reaches further than
// it looks: withMCPAdminIdentity copies this role, and evaluateAdminAccess
// grants full admin to an MCP identity whose role reads "super_admin", which
// includes k8s_apply_manifest_change and the other direct cluster-change tools.
func TestAPIKeyIsClampedToTheOwnersCurrentRole(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID, rawKey = "usr_demoted", "pcg_test_demoted_key"
	mustCreateUser(t, db, userID, "demoted@example.com", "super_admin")
	if err := db.UpsertAPIKey(ctx, store.APIKeyRecord{
		ID: "ak_demoted", Name: "ak_demoted", KeyHash: hashProxyKey(rawKey),
		Owner: userID, UserID: userID, Role: "super_admin", Status: "active",
		Scopes:    []string{"chat:completion", "admin:read", "admin:write"},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	_, authCtx, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey))
	if !ok || authCtx == nil {
		t.Fatal("the key should authenticate while its owner is a super_admin")
	}
	if authCtx.Role != "super_admin" {
		t.Fatalf("role = %q before the demotion, want super_admin", authCtx.Role)
	}

	// Demote to a role that still permits chat, so this isolates the loss of the
	// elevated role and its admin scopes from the loss of chat access itself.
	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "developer", ""); err != nil {
		t.Fatal(err)
	}

	_, authCtx, ok = srv.authenticateProxyContext(requestWithKey(t, rawKey))
	if !ok || authCtx == nil {
		t.Fatal("a developer's key should still authenticate for chat after the demotion")
	}
	if authCtx.Role == "super_admin" {
		t.Fatal("the API key still carries super_admin after its owner was demoted: " +
			"via withMCPAdminIdentity that grants the MCP admin gate, including direct cluster-change tools")
	}
	if hasScope(authCtx.Scopes, "admin:write") {
		t.Fatalf("admin:write survived the demotion: %v", authCtx.Scopes)
	}
	if !hasScope(authCtx.Scopes, "chat:completion") {
		t.Fatalf("chat:completion was stripped from a developer's key: %v", authCtx.Scopes)
	}

	// Demoting further to viewer, which carries no chat:completion at all, must
	// take the chat request with it — the clamp feeds the scope gate.
	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "viewer", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey)); ok {
		t.Fatal("a viewer's key was accepted for /v1/chat/completions; viewer has no chat:completion scope")
	}
}

// Clamping must only ever remove reach, and must be reversible: re-promoting the
// user restores the key without rotating it.
func TestClampIsReversibleAndNeverWidens(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID, rawKey = "usr_narrow", "pcg_test_narrow_key"
	// A deliberately narrowed key: fewer scopes than the owner's role implies.
	mustCreateUser(t, db, userID, "narrow@example.com", "admin")
	if err := db.UpsertAPIKey(ctx, store.APIKeyRecord{
		ID: "ak_narrow", Name: "ak_narrow", KeyHash: hashProxyKey(rawKey),
		Owner: userID, UserID: userID, Role: "admin", Status: "active",
		Scopes: []string{"chat:completion"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	_, authCtx, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey))
	if !ok {
		t.Fatal("narrowed key should authenticate")
	}
	if len(authCtx.Scopes) != 1 || authCtx.Scopes[0] != "chat:completion" {
		t.Fatalf("a deliberately narrowed key was widened to %v", authCtx.Scopes)
	}

	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "viewer", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "admin", ""); err != nil {
		t.Fatal(err)
	}
	_, authCtx, ok = srv.authenticateProxyContext(requestWithKey(t, rawKey))
	if !ok || authCtx.Role != "admin" {
		t.Fatalf("re-promoting the owner did not restore the key (ok=%v role=%q)", ok, authCtx.Role)
	}
}

// A promotion must not lift the key: clamping only ever lowers.
func TestOwnerPromotionDoesNotElevateTheKey(t *testing.T) {
	srv, db := newSSOTestServer(t)
	ctx := context.Background()

	const userID, rawKey = "usr_promoted", "pcg_test_promoted_key"
	mustCreateUser(t, db, userID, "promoted@example.com", "viewer")
	if err := db.UpsertAPIKey(ctx, store.APIKeyRecord{
		ID: "ak_promoted", Name: "ak_promoted", KeyHash: hashProxyKey(rawKey),
		Owner: userID, UserID: userID, Role: "viewer", Status: "active",
		Scopes: []string{"chat:completion"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateAuthUserRoleStatus(ctx, userID, "super_admin", ""); err != nil {
		t.Fatal(err)
	}
	_, authCtx, ok := srv.authenticateProxyContext(requestWithKey(t, rawKey))
	if !ok {
		t.Fatal("key should authenticate")
	}
	if authCtx.Role != "viewer" {
		t.Fatalf("role = %q; promoting the owner must not elevate an existing key", authCtx.Role)
	}
}
