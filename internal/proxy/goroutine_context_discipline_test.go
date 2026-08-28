package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// unboundedGoroutineCtxMarker opts one call out of the rule below. Put it in a
// comment inside the goroutine, with a reason.
const unboundedGoroutineCtxMarker = "unbounded-goroutine-ctx:"

// TestGoroutineContextsAreBounded pins the discipline that every detached
// goroutine bounds its own work.
//
// A `go func(){...}()` that builds its context from context.Background() has no
// caller left to cancel it: the request that spawned it has returned, and
// nothing waits on it or counts it. If a call inside runs on that bare context
// it can block forever, and because these goroutines are spawned per request
// their number grows with traffic — each one parked on a connection-pool slot.
//
// This is not hypothetical. Four ClickHouse fact emitters bounded their insert
// at 30s but then took the error path on a bare Background():
//
//	_ = s.db.RecordClickHouseFactRetry(context.Background(), table, payload, ...)
//
// An unbounded error path inside an otherwise-bounded goroutine is the worst
// shape of this bug, because the branch runs precisely when the downstream is
// already unhealthy — so they all take it at once, and a ClickHouse outage
// becomes a goroutine and connection leak in the gateway itself.
//
// A goroutine that closes over a caller's context is fine and not flagged; only
// a freshly minted root context is.
func TestGoroutineContextsAreBounded(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "release", "web":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			goStmt, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			lit, ok := goStmt.Call.Fun.(*ast.FuncLit)
			if !ok {
				// `go w.run()` — a named method owns its own lifecycle and is
				// reviewed as a worker, not as fire-and-forget.
				return true
			}
			scanned++

			// A Background() handed straight to WithTimeout/WithDeadline/WithCancel
			// is the correct construction, not a finding.
			wrapped := map[token.Pos]bool{}
			ast.Inspect(lit.Body, func(m ast.Node) bool {
				if isContextCall(m, "WithTimeout", "WithDeadline", "WithCancel") {
					for _, arg := range m.(*ast.CallExpr).Args {
						wrapped[arg.Pos()] = true
					}
				}
				return true
			})

			ast.Inspect(lit.Body, func(m ast.Node) bool {
				if !isContextCall(m, "Background", "TODO") || wrapped[m.Pos()] {
					return true
				}
				if hasMarker(fset, file, goStmt) {
					return true
				}
				t.Errorf("%s: context.Background()/TODO() used directly inside a detached goroutine. "+
					"Nothing can cancel it and nothing waits on it, so a blocked call here leaks a goroutine "+
					"and a connection-pool slot for every request that reaches this code. Wrap it in "+
					"context.WithTimeout, or add a %q comment with the reason.",
					fset.Position(m.Pos()), unboundedGoroutineCtxMarker)
				return true
			})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Guard against the scan silently matching nothing (a moved directory, a
	// parser change) and reporting a clean audit it never performed.
	if scanned < 15 {
		t.Fatalf("only %d goroutine literals scanned; the walk is not reaching the source tree", scanned)
	}
}

func isContextCall(n ast.Node, names ...string) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "context" {
		return false
	}
	for _, name := range names {
		if sel.Sel.Name == name {
			return true
		}
	}
	return false
}

// hasMarker reports whether an opt-out comment sits inside the goroutine.
func hasMarker(fset *token.FileSet, file *ast.File, goStmt *ast.GoStmt) bool {
	lo, hi := fset.Position(goStmt.Pos()).Offset, fset.Position(goStmt.End()).Offset
	for _, group := range file.Comments {
		off := fset.Position(group.Pos()).Offset
		if off < lo || off > hi {
			continue
		}
		if strings.Contains(group.Text(), unboundedGoroutineCtxMarker) {
			return true
		}
	}
	return false
}
