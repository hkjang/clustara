package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scopeReferenceCounts counts, per scope, how many times it appears as a string
// literal in production code outside the catalog itself. A scope that appears
// nowhere else cannot be gating anything.
func scopeReferenceCounts(t *testing.T) map[string]int {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	// Comments legitimately name scopes while discussing them, so they are stripped:
	// only real code references count as enforcement.
	lineComment := regexp.MustCompile(`(?m)//.*$`)
	blockComment := regexp.MustCompile(`(?s)/\*.*?\*/`)
	catalog := regexp.MustCompile(`(?s)var allScopes = \[\]string\{.*?\n\}`)
	roles := regexp.MustCompile(`(?s)var roleScopes = map\[string\]\[\]string\{.*?\n\}`)
	unenf := regexp.MustCompile(`(?s)var unenforcedScopes = map\[string\]string\{.*?\n\}`)

	counts := map[string]int{}
	for _, sc := range allScopes {
		counts[sc] = 0
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		body := blockComment.ReplaceAllString(string(raw), "")
		body = lineComment.ReplaceAllString(body, "")
		if name == "auth.go" {
			body = catalog.ReplaceAllString(body, "")
			body = roles.ReplaceAllString(body, "")
			body = unenf.ReplaceAllString(body, "")
		}
		for _, sc := range allScopes {
			counts[sc] += strings.Count(body, `"`+sc+`"`)
		}
	}
	return counts
}

// The scope catalog is shown to operators for role assignment, so a scope listed
// there that no code checks is a permission an operator can grant or withhold with
// no effect — withholding "rollout:force" would look like a control and be none.
// This keeps the unenforcedScopes annotation matching reality in both directions:
// a scope claimed enforced must actually be referenced, and one claimed unenforced
// must not be. Wiring a gate without updating the list, or vice versa, fails here.
func TestScopeEnforcementAnnotationMatchesCode(t *testing.T) {
	counts := scopeReferenceCounts(t)
	for _, sc := range allScopes {
		_, claimedUnenforced := unenforcedScopes[sc]
		referenced := counts[sc] > 0
		switch {
		case claimedUnenforced && referenced:
			t.Errorf("%q is listed in unenforcedScopes but is referenced %d time(s); remove it from the list now that it gates something",
				sc, counts[sc])
		case !claimedUnenforced && !referenced:
			t.Errorf("%q is offered for role assignment but no code references it; either enforce it or add it to unenforcedScopes with a reason",
				sc)
		}
	}
}

// Every annotated scope must carry a reason and still exist in the catalog, so the
// roles API can explain itself.
func TestUnenforcedScopeAnnotationIsWellFormed(t *testing.T) {
	for sc, reason := range unenforcedScopes {
		if !hasScope(allScopes, sc) {
			t.Errorf("unenforcedScopes lists %q which is not in allScopes", sc)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%q has no reason recorded", sc)
		}
	}
	catalog := unenforcedScopeCatalog()
	if len(catalog) != len(unenforcedScopes) {
		t.Fatalf("catalog rendered %d entries, want %d", len(catalog), len(unenforcedScopes))
	}
	for _, row := range catalog {
		if row["scope"] == "" || row["reason"] == "" {
			t.Errorf("incomplete catalog row: %+v", row)
		}
	}
}
