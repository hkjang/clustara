package proxy

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"clustara/internal/config"
	"clustara/internal/store"
)

// effectiveScopesForRole fell back to scopesForRole whenever the custom-role lookup did not
// return a row — including when it FAILED. scopesForRole answers an unrecognised name with
// viewer's scopes, so a custom role deliberately narrower than viewer was handed more than
// it was ever granted.
//
// Measured: a custom role holding only chat:completion came back as viewer's seven scopes,
// which include admin:read (the operator surface) and do NOT include chat:completion. The
// role did not merely widen; it became a different role.
//
// tokenScopesForUser and the SSO path mint access-token scopes at login, so a read failure
// at that moment bakes the wrong grant into a JWT for its whole lifetime.
func TestUnreadableCustomRoleGrantsNothing(t *testing.T) {
	db, server, dbPath := customRoleServer(t)
	if err := db.UpsertCustomRole(context.Background(), store.CustomRole{
		Role: "bot", Description: "narrow", Scopes: []string{"chat:completion"},
	}); err != nil {
		t.Fatal(err)
	}
	healthy := server.effectiveScopesForRole(context.Background(), "bot")
	if len(healthy) != 1 || healthy[0] != "chat:completion" {
		t.Fatalf("the custom role does not resolve as configured: %v", healthy)
	}

	breakCustomRoles(t, dbPath)

	got := server.effectiveScopesForRole(context.Background(), "bot")
	if hasScope(got, "admin:read") {
		t.Fatalf("a role that was granted only chat:completion gained admin:read because its "+
			"definition could not be read; scopes = %v", got)
	}
	if len(got) != 0 {
		t.Fatalf("scopes = %v; with the definition unreadable we know nothing about this role, "+
			"so it must be granted nothing", got)
	}
	// The two helpers must agree about the same failure.
	if server.effectiveValidRole(context.Background(), "bot") {
		t.Fatal("effectiveValidRole reported the role valid while its scopes were unknowable")
	}
}

// A built-in role can never be a custom role, so a custom_roles read failure says nothing
// about it. Ordinary users must not be locked out by an unrelated table being unreadable.
func TestBuiltinRolesSurviveAnUnreadableCustomRoleTable(t *testing.T) {
	_, server, dbPath := customRoleServer(t)
	breakCustomRoles(t, dbPath)

	for _, role := range []string{"developer", "viewer", "admin"} {
		got := server.effectiveScopesForRole(context.Background(), role)
		if len(got) == 0 {
			t.Fatalf("built-in role %q lost every scope because custom_roles was unreadable", role)
		}
	}
	if got := server.effectiveScopesForRole(context.Background(), "developer"); !hasScope(got, "chat:completion") {
		t.Fatalf("developer lost chat:completion: %v", got)
	}
}

// An unknown role name with a HEALTHY table keeps its old meaning: viewer's scopes. The fix
// is about not knowing, not about unknown names.
func TestUnknownRoleWithAHealthyTableIsUnchanged(t *testing.T) {
	_, server, _ := customRoleServer(t)
	got := server.effectiveScopesForRole(context.Background(), "no-such-role")
	if !hasScope(got, "admin:read") || hasScope(got, "chat:completion") {
		t.Fatalf("an unknown role no longer resolves to viewer's scopes: %v", got)
	}
}

func customRoleServer(t *testing.T) (*store.SQLStore, *Server, string) {
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

func breakCustomRoles(t *testing.T, dbPath string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open store file: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE custom_roles`); err != nil {
		t.Fatalf("break custom_roles: %v", err)
	}
}
