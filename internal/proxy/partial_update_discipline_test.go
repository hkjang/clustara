package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// wholesaleUpsertExceptions records handlers that decode a request body into a
// store record carrying a bool, slice or map field and upsert it wholesale,
// together with why that is safe. Anything not listed here fails.
//
// The rule exists because this defect appeared three times in a row, each time
// with a different consequence:
//
//   - policies: omitting "enabled" disabled the rule, and a disabled rule makes
//     the compliance report go quiet, which reads as compliant
//   - service catalogs: omitting "enabled" performed the delete, because the
//     DELETE branch of that endpoint is exactly Enabled = false
//   - contexts: the opposite polarity — an explicit "enabled": false was
//     discarded, so a context injected into every prompt could never be turned off
//
// A handler that upserts by an id the caller supplies must use
// decodeWithPresence and keep fields the body did not mention. One that always
// mints a fresh id is a create and needs nothing.
var wholesaleUpsertExceptions = map[string]string{
	"handleServiceCatalogVersion":       "create-only: assigns in.ID = newID(\"svcver\") on every call, so it never edits an existing row.",
	"handleGoldenWorkflows":             "create-only in practice; Steps and Tags are the record's substance and a caller omitting them is creating an empty workflow, not silently clearing one.",
	"handleCatalogEntities":             "Tags is the payload being edited, not a setting that changes behaviour when cleared.",
	"handleAccessBindings":              "Conditions is the binding's substance; an omitted Conditions is a binding without conditions, which is what it means.",
	"upsertEnterpriseRecordFromRequest": "Payload is the record body itself; there is nothing to preserve behind it.",
	"handleEnterpriseOrganizations":     "create/replace of the whole record by design; no behavioural flag.",
	"handleEnterpriseWorkspaces":        "create/replace of the whole record by design; no behavioural flag.",
	"handleEnterpriseProjects":          "create/replace of the whole record by design; no behavioural flag.",
	"handleHarborMappings":              "create/replace of the whole mapping; no behavioural flag.",
	"handleK8sGroups":                   "create path; the by-id editor is handleK8sGroupByID.",
	"handleK8sOwnership":                "create/replace of the whole ownership row; no behavioural flag.",
	"handleServiceCatalogs":             "create path; the by-id editor is handleServiceCatalogByID.",
	"handleAdminModelTags":              "replaces the tag set for a model, which is the operation.",
	"handleK8sGroupByID":                "known gap, string fields only: a rename clears kind and description. No zero-value trap of the bool kind and the blast radius is metadata; tracked separately rather than folded into the bool fixes.",
}

// TestWholesaleUpsertsAreClassified finds handlers that decode a body straight
// into a store record and upsert it, and requires each either to merge absent
// fields via decodeWithPresence or to be classified above.
func TestWholesaleUpsertsAreClassified(t *testing.T) {
	risky := riskyRecordTypes(t)
	if len(risky) < 10 {
		t.Fatalf("only %d store types with bool/slice/map fields found; the scan is not reaching the store", len(risky))
	}

	fset := token.NewFileSet()
	decl := regexp.MustCompile(`var (\w+) store\.(\w+)`)
	upsert := regexp.MustCompile(`Upsert\w+\((?:\w+\.Context\(\)|ctx)\s*,\s*(\w+)\)`)
	// The defect is decode-then-upsert of the SAME variable. A handler that loads
	// the stored record and edits it — handleMultiRunGolden appends a step to the
	// workflow it fetched — is doing the right thing already and must not be
	// flagged for it.
	decodedInto := regexp.MustCompile(`Decode\(&(\w+)\)|decodeWithPresence\(r, &(\w+)\)`)

	checked := 0
	root := filepath.Join("..", "..", "internal", "proxy")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		src := repoFileAt(t, path)
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			body := src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset]
			for _, m := range decl.FindAllStringSubmatch(body, -1) {
				varName, typeName := m[1], m[2]
				if !risky[typeName] {
					continue
				}
				upserted := false
				for _, u := range upsert.FindAllStringSubmatch(body, -1) {
					if u[1] == varName {
						upserted = true
					}
				}
				if !upserted {
					continue
				}
				fromBody := false
				for _, d := range decodedInto.FindAllStringSubmatch(body, -1) {
					if d[1] == varName || d[2] == varName {
						fromBody = true
					}
				}
				if !fromBody {
					continue
				}
				checked++
				if strings.Contains(body, "decodeWithPresence") {
					continue
				}
				if _, ok := wholesaleUpsertExceptions[fn.Name.Name]; ok {
					continue
				}
				t.Errorf("%s upserts store.%s wholesale, and that record has a bool, slice or map field. "+
					"Every key the caller omits arrives as a zero value. Use decodeWithPresence to keep "+
					"unmentioned fields, or record it in wholesaleUpsertExceptions with the reason.",
					fn.Name.Name, typeName)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked < 8 {
		t.Fatalf("only %d wholesale upserts analysed; the scan is probably broken", checked)
	}

	// The list must not outlive its handlers.
	joined := strings.Join(valuesOf(proxySources(t)), "\n")
	for _, name := range sortedStrings(wholesaleUpsertExceptions) {
		if !strings.Contains(joined, "func (s *Server) "+name+"(") && !strings.Contains(joined, ") "+name+"(") {
			t.Errorf("wholesaleUpsertExceptions lists %s, which no longer exists; remove it so it cannot "+
				"excuse a future handler reusing the name", name)
		}
	}
}

// riskyRecordTypes returns store types with a bool, slice or map field — the
// fields whose zero value silently changes behaviour rather than blanking text.
func riskyRecordTypes(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	root := filepath.Join("..", "..", "internal", "store")
	fset := token.NewFileSet()
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, f := range st.Fields.List {
				switch ft := f.Type.(type) {
				case *ast.Ident:
					if ft.Name == "bool" {
						out[ts.Name.Name] = true
					}
				case *ast.ArrayType, *ast.MapType:
					out[ts.Name.Name] = true
				}
			}
			return true
		})
		return nil
	})
	return out
}

func repoFileAt(t *testing.T, path string) string {
	t.Helper()
	return repoFile(t, strings.Split(strings.TrimPrefix(filepath.ToSlash(path), "../../"), "/")...)
}

func sortedStrings(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
