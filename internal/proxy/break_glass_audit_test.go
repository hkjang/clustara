package proxy

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"clustara/internal/store"
)

// The break-glass header bypasses the administrator IP allowlist. Two of its four call sites
// recorded that (withAdminIPPolicy, enforceAdminLoginIP) and two did not — including
// consumeTerminalTicket, the path that opens a shell inside a pod. The same emergency
// override was therefore audited on the ordinary admin surface and silent on the most
// sensitive one.
func TestBreakGlassOnTheTerminalPathIsRecorded(t *testing.T) {
	db, server := breakGlassServer(t, "emergency-token-value")

	r := httptest.NewRequest("GET", "/admin/k8s/terminal/stream?session=sess_1", nil)
	r.Header.Set(adminBreakGlassHeader, "emergency-token-value")
	// The ticket is not valid; the bypass of the IP policy is the event, and it has already
	// happened by the time the ticket is looked at.
	_, _ = server.consumeTerminalTicket(r, "sess_1", "no-such-ticket")

	if !hasBreakGlassEvent(t, db, "terminal_stream") {
		t.Fatal("break-glass opened the terminal path past the IP allowlist and left no audit " +
			"event; the same header is recorded on the ordinary admin surface")
	}
}

// Every place that consults validBreakGlass must record the bypass. This is the rule the two
// silent sites broke, so it is pinned rather than left to review: a new bypass site added
// without an audit call fails here by name.
func TestEveryBreakGlassSiteRecordsIt(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			uses, audits := false, false
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch callee := call.Fun.(type) {
				case *ast.Ident:
					if callee.Name == "validBreakGlass" {
						uses = true
					}
				case *ast.SelectorExpr:
					if callee.Sel.Name == "auditIPPolicyDecision" {
						audits = true
					}
				}
				return true
			})
			// validBreakGlass's own declaration is not a use site.
			if uses && fn.Name.Name != "validBreakGlass" && !audits {
				t.Errorf("%s: %s consults validBreakGlass but records nothing; an emergency "+
					"override of the administrator IP allowlist must leave a trace", name, fn.Name.Name)
			}
			return true
		})
	}
}

func breakGlassServer(t *testing.T, token string) (*store.SQLStore, *Server) {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.adminIPPolicy.Store(&adminIPPolicy{
		Enabled:        true,
		EmergencyToken: token,
		Allowed:        nil, // no address is allowed, so only break-glass gets through
	})
	return db, server
}

func hasBreakGlassEvent(t *testing.T, db *store.SQLStore, detailFragment string) bool {
	t.Helper()
	events, err := db.ListAuditEvents(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.EventType == "admin_ip_break_glass" && strings.Contains(e.Detail, detailFragment) {
			return true
		}
	}
	return false
}
