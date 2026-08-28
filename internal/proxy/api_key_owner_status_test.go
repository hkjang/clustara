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
