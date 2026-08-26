package proxy

import (
	"context"
	"testing"

	"clustara/internal/store"
)

// The key-creation endpoint accepts a custom role (effectiveValidRole) but used to
// resolve its scopes with the built-in map, which falls back to viewer for anything
// unknown. A custom role deliberately narrower than viewer therefore produced a key
// carrying viewer's scopes — admin:read among them — which is broader than what the
// operator defined. Accepting the role and then ignoring it is the defect.
func TestAPIKeyScopesFollowCustomRole(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	ctx := context.Background()

	narrow := []string{"models:read"}
	if err := db.UpsertCustomRole(ctx, store.CustomRole{Role: "kiosk", Scopes: narrow}); err != nil {
		t.Fatal(err)
	}

	got := s.defaultAPIKeyScopesFor(ctx, "kiosk", false)
	if len(got) != 1 || got[0] != "models:read" {
		t.Fatalf("custom role scopes were not applied: got %v, want %v", got, narrow)
	}
	for _, leaked := range []string{"admin:read", "security:read", "costs:read", "service:read"} {
		if hasScope(got, leaked) {
			t.Errorf("key received %q, which the custom role does not grant", leaked)
		}
	}
}

// A custom role broader than viewer must also be honoured, so the feature works in
// both directions.
func TestAPIKeyScopesFollowBroaderCustomRole(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	ctx := context.Background()

	if err := db.UpsertCustomRole(ctx, store.CustomRole{
		Role: "deployer", Scopes: []string{"models:read", "service:read", "service:update"},
	}); err != nil {
		t.Fatal(err)
	}
	got := s.defaultAPIKeyScopesFor(ctx, "deployer", false)
	if !hasScope(got, "service:update") {
		t.Fatalf("custom role scope service:update missing from %v", got)
	}
}

// Built-in roles and the empty-role defaults must be unchanged.
func TestAPIKeyScopesUnchangedForBuiltinRoles(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	ctx := context.Background()

	for _, role := range []string{"viewer", "developer", "service_account"} {
		got := s.defaultAPIKeyScopesFor(ctx, role, false)
		want := scopesForRole(role)
		if len(got) != len(want) {
			t.Errorf("built-in role %q: got %v, want %v", role, got, want)
			continue
		}
		for _, sc := range want {
			if !hasScope(got, sc) {
				t.Errorf("built-in role %q lost scope %q", role, sc)
			}
		}
	}
	// Empty role keeps its service-account / developer split.
	if got := s.defaultAPIKeyScopesFor(ctx, "", true); !hasScope(got, "chat:completion") {
		t.Errorf("empty role for a service account: %v", got)
	}
	if got := s.defaultAPIKeyScopesFor(ctx, "", false); !hasScope(got, "service:create") {
		t.Errorf("empty role should default to developer scopes: %v", got)
	}
}

// An unknown role that is neither built-in nor custom must still fall back to the
// most restrictive built-in rather than erroring or granting nothing meaningful.
func TestAPIKeyScopesFallbackForUnknownRole(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	got := s.defaultAPIKeyScopesFor(context.Background(), "no-such-role", false)
	want := scopesForRole("viewer")
	if len(got) != len(want) {
		t.Fatalf("unknown role fallback changed: got %v, want viewer scopes %v", got, want)
	}
}
