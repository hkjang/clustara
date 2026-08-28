package proxy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// classifiedLockFindings records every field in the tree that is guarded by a
// mutex in some methods and touched without it in others, together with why that
// is correct. Anything not listed here fails.
//
// This exists because the two lock-discipline tests written earlier in this
// session pin one mutex each — chSinkMu and statsMu — out of the seventeen in
// the codebase. Named "lock discipline", they covered 2/17, the same gap the
// route audit turned out to have. Inverting the rule is what closes it: a new
// mutex, or a new unguarded access to an existing one, has to be classified
// before the build passes.
//
// Every entry below was read before it was written down.
var classifiedLockFindings = map[string]string{
	"sessionInferer.mu/entries": "gc and evictIfFull require the caller to hold si.mu; all three call sites do. " +
		"Go mutexes are not reentrant, so locking inside them would deadlock.",
	"sessionInferer.mu/idle": "read by gc under the caller's lock; set once at construction.",
	"stateStore.mu/data":     "saveLocked names its contract and both callers (Set, Clear) hold s.mu.",
	"Runner.statsMu/events": "false positive: events is a channel and is not guarded by statsMu, which " +
		"protects reconnects, eventsTotal, lastError and lastResourceRV. Channels are safe concurrently.",
	"PodTerminalStream.mu/conn": "Close must not take s.mu: that mutex serialises frame writes, so holding it " +
		"would block Close behind a write to a stuck peer — the situation Close exists to escape. " +
		"net.Conn is safe to close while another goroutine writes.",
}

// TestLockDisciplineFindingsAreClassified reports any field that is mutex-guarded
// in most places and reached without the lock in a few — the shape of the
// chSinkMu defect fixed in v0.9.203, where one function of many read a guarded
// flag unlocked.
func TestLockDisciplineFindingsAreClassified(t *testing.T) {
	findings, scanned := scanLockDiscipline(t)
	if scanned < 10 {
		t.Fatalf("only %d mutexes were scanned; the walk is not reaching the source tree", scanned)
	}

	for _, key := range sortedKeys(findings) {
		if _, ok := classifiedLockFindings[key]; ok {
			continue
		}
		t.Errorf("%s is guarded by the mutex in %s but reached without it in %s. "+
			"Either take the lock, or add it to classifiedLockFindings with the reason it is safe.",
			key, findings[key].locked, findings[key].unlocked)
	}
	for key := range classifiedLockFindings {
		if _, ok := findings[key]; !ok {
			t.Errorf("classifiedLockFindings still lists %s, which the scan no longer reports; remove it "+
				"so it cannot excuse a future finding under the same name", key)
		}
	}
}

type lockFinding struct{ locked, unlocked []string }

// scanLockDiscipline returns fields touched both with and without their type's
// mutex, and how many mutexes were examined. Fields reached without the lock in
// many places are skipped: those are not "mostly guarded", they are fields the
// mutex does not protect at all (Server.cfg, for instance, is immutable after
// construction and read everywhere).
func scanLockDiscipline(t *testing.T) (map[string]lockFinding, int) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File

	root := filepath.Join("..", "..", "internal")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	mutexes := map[string][]string{}
	fields := map[string]map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, fl := range st.Fields.List {
					typ := exprText(fl.Type)
					for _, n := range fl.Names {
						if typ == "sync.Mutex" || typ == "sync.RWMutex" {
							mutexes[ts.Name.Name] = append(mutexes[ts.Name.Name], n.Name)
							continue
						}
						if fields[ts.Name.Name] == nil {
							fields[ts.Name.Name] = map[string]bool{}
						}
						fields[ts.Name.Name][n.Name] = true
					}
				}
			}
		}
	}

	out := map[string]lockFinding{}
	count := 0
	for typeName, mus := range mutexes {
		for _, mu := range mus {
			count++
			acc := map[string]*lockFinding{}
			for _, f := range files {
				for _, decl := range f.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Recv == nil || fn.Body == nil || len(fn.Recv.List) == 0 {
						continue
					}
					if receiverTypeName(fn.Recv.List[0].Type) != typeName || len(fn.Recv.List[0].Names) == 0 {
						continue
					}
					recv := fn.Recv.List[0].Names[0].Name
					var sels []string
					ast.Inspect(fn.Body, func(n ast.Node) bool {
						if s, ok := n.(*ast.SelectorExpr); ok {
							sels = append(sels, exprText(s))
						}
						return true
					})
					text := strings.Join(sels, "\n")
					locked := strings.Contains(text, recv+"."+mu+".Lock") || strings.Contains(text, recv+"."+mu+".RLock")
					for name := range fields[typeName] {
						if !strings.Contains(text, recv+"."+name) {
							continue
						}
						if acc[name] == nil {
							acc[name] = &lockFinding{}
						}
						if locked {
							acc[name].locked = append(acc[name].locked, fn.Name.Name)
						} else {
							acc[name].unlocked = append(acc[name].unlocked, fn.Name.Name)
						}
					}
				}
			}
			for name, a := range acc {
				if len(a.locked) >= 2 && len(a.unlocked) > 0 && len(a.unlocked) <= 3 {
					sort.Strings(a.locked)
					sort.Strings(a.unlocked)
					out[fmt.Sprintf("%s.%s/%s", typeName, mu, name)] = *a
				}
			}
		}
	}
	return out, count
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return exprText(v.X)
	}
	return ""
}

func sortedKeys(m map[string]lockFinding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
