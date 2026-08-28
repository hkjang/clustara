package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestMainDoesNotExitPastCleanup pins the shutdown contract of this package:
// os.Exit may be called from exactly one place, main, whose body is nothing but
// os.Exit(run()). Every resource — the async logger queue above all — is
// released by a deferred call inside run, and os.Exit does not run deferred
// functions.
//
// This is not hypothetical tidiness. Before v0.9.206 the drain path read:
//
//	if err := httpServer.Shutdown(ctx); err != nil { slog.Error(...); os.Exit(1) }
//
// and exceeding that window is routine, not exceptional: HTTP_WRITE_TIMEOUT
// defaults to 10 minutes so streaming responses can be long-lived, while the
// drain window is 15 seconds. Every deploy that caught a live stream took the
// os.Exit branch and dropped the queued request/audit rows for the requests
// that were still running — the ones an operator most wants afterwards.
// TestAsyncLoggerStopDrainsQueuedRecords measures the loss: 196 of 200.
//
// A new error path in run() must therefore `return 1`, never os.Exit.
func TestMainDoesNotExitPastCleanup(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	sawMain, sawRun := false, false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			continue
		}
		switch fn.Name.Name {
		case "main":
			sawMain = true
			// main is allowed to exit, and must do nothing else: any statement
			// before os.Exit(run()) would be work whose cleanup can't be deferred.
			if len(fn.Body.List) != 1 || !isOSExitOfRun(fn.Body.List[0]) {
				t.Fatalf("func main must be exactly `os.Exit(run())`; found %d statement(s). "+
					"Move the work into run() so its defers execute.", len(fn.Body.List))
			}
		default:
			if fn.Name.Name == "run" {
				sawRun = true
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if pos, ok := osExitPos(n); ok {
					t.Errorf("%s: os.Exit in func %s — os.Exit skips deferred cleanup, "+
						"so the async logger queue (request/audit rows held only in memory) is lost. "+
						"Return a non-zero code instead and let run() unwind.",
						fset.Position(pos), fn.Name.Name)
				}
				return true
			})
		}
	}
	if !sawMain || !sawRun {
		t.Fatalf("expected both main and run in main.go (main=%v run=%v); "+
			"if the wrapper was renamed, update this test rather than deleting it", sawMain, sawRun)
	}
}

func isOSExitOfRun(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	if _, ok := osExitPos(expr.X); !ok {
		return false
	}
	args := expr.X.(*ast.CallExpr).Args
	if len(args) != 1 {
		return false
	}
	inner, ok := args[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := inner.Fun.(*ast.Ident)
	return ok && ident.Name == "run"
}

// osExitPos reports whether n is a call to os.Exit, and where.
func osExitPos(n ast.Node) (token.Pos, bool) {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return 0, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Exit" {
		return 0, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "os" {
		return 0, false
	}
	return call.Pos(), true
}
