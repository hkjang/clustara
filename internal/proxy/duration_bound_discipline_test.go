package proxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Projecting a future instant from a rate means dividing by that rate, and a low
// rate makes the result enormous. float64 → time.Duration overflows past roughly
// 106,751 days into a NEGATIVE duration, so t.Add(d) lands centuries in the past
// — and a "not after the deadline" test then passes and publishes it.
//
// That is exactly how a budget with 0.05 KRW spent reported an exhaustion date of
// 1734-04-22. The two sibling projections (node disk pressure, GPU VRAM) already
// do it correctly: they bound the hours against a horizon before converting.
//
// The rule: bound the value in its natural unit first, then convert. This finds
// every float→Duration conversion and requires a comparison against the same
// identifier somewhere in the enclosing function.
func TestFloatDurationConversionsAreBounded(t *testing.T) {
	// time.Duration(x) where the expression mentions a float scale — the shape
	// that can overflow. Integer conversions like time.Duration(n) * time.Second
	// cannot.
	conv := regexp.MustCompile(`time\.Duration\(([A-Za-z_]\w*)\s*\*[^)]*float64\(time\.`)

	checked := 0
	for _, dir := range []string{"analyzer", "store", "proxy", "agent", "kube"} {
		root := filepath.Join("..", "..", "internal", dir)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parse %s: %v", path, perr)
			}
			src := repoFileAt(t, path)
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				body := src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset]
				for _, m := range conv.FindAllStringSubmatch(body, -1) {
					name := m[1]
					checked++
					// A bound is any comparison of that identifier against something
					// else in the same function: hours > 168, daysToExhaust <= daysInMonth.
					bounded := regexp.MustCompile(`\b`+regexp.QuoteMeta(name)+`\s*(<=|>=|<|>)`).MatchString(body) ||
						regexp.MustCompile(`(<=|>=|<|>)\s*`+regexp.QuoteMeta(name)+`\b`).MatchString(body)
					if !bounded {
						t.Errorf("%s: %s converts %s to a time.Duration without bounding it first. "+
							"A low rate makes it enormous, the conversion overflows to a negative duration, "+
							"and the projected instant lands in the past.",
							fset.Position(fn.Pos()), fn.Name.Name, name)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if checked < 3 {
		t.Fatalf("only %d float→Duration conversions found; the scan is not reaching the source", checked)
	}
}

// A failure to encode a response cannot be turned into an error status — the
// status is already written — but it must not be invisible.
func TestResponseEncodeFailureIsNotDiscarded(t *testing.T) {
	src := repoFile(t, "internal", "proxy", "server.go")
	if strings.Contains(src, "_ = json.NewEncoder(w).Encode(body)") {
		t.Fatal("writeJSON still discards its encode error; a NaN or unsupported value anywhere in a " +
			"report yields a 200 with a truncated body and no record on either side")
	}
	if !strings.Contains(src, "response encoding failed after the status was written") {
		t.Error("writeJSON does not report an encode failure")
	}
}
