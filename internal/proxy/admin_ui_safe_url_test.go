package proxy

import (
	"strings"
	"testing"
)

// escapeAttr keeps a value inside an href attribute but does not neutralise the
// scheme, so a stored "javascript:" URL still executes when an operator clicks
// it. Links that carry externally supplied data - VCS webhook payloads, catalog
// repo/docs URLs - must go through the scheme allow-list.
func TestAdminUIExternalLinksAllowListTheScheme(t *testing.T) {
	for _, want := range []string{
		"function safeURL(value) {",
		"probe.startsWith('http://') || probe.startsWith('https://')",
		"const titleURL = safeURL(e.url);",
		"const labelURL = safeURL(e.url);",
		"if (safeURL(e.repo_url)) links.push(",
		"if (safeURL(e.docs_url)) links.push(",
		"escapeAttr(safeURL(gpuCatalog.source_url)",
	} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin UI should include %q", want)
		}
	}

	// The unguarded forms must not come back.
	for _, bad := range []string{
		`e.url ? '<a href="' + escapeAttr(e.url) + '" target="_blank"`,
		`if (e.repo_url) links.push('<a href="' + escapeAttr(e.repo_url)`,
		`if (e.docs_url) links.push('<a href="' + escapeAttr(e.docs_url)`,
	} {
		if strings.Contains(adminHTML, bad) {
			t.Fatalf("external link renders an unchecked scheme: %q", bad)
		}
	}
}

// The scheme test has to run against a control-character-stripped copy, or
// evasion that hides them inside the scheme still gets through.
func TestAdminUISafeURLNormalisesBeforeTestingScheme(t *testing.T) {
	if !strings.Contains(adminHTML, `const probe = raw.replace(/[\u0000-\u0020]/g, '').toLowerCase();`) {
		t.Fatal("safeURL must normalise control characters before testing the scheme")
	}
}
