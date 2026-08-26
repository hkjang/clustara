package proxy

import (
	"strings"
	"testing"
)

// loadNavigation documents that "a navigation-policy error must never reveal
// every menu". applyNavPermissions used to contradict that: when the policy was
// absent or malformed it treated the caller as allowed to see everything.
// authState.nav is null before the first load and is reset to null when the
// legacy admin token changes, so that state is reachable.
func TestAdminUINavigationFailsClosedWithoutAPolicy(t *testing.T) {
	if strings.Contains(adminHTML, "(!allowed || allowed.has(tab))") {
		t.Fatal("navigation must not show every menu when no policy is loaded")
	}
	for _, want := range []string{
		"const allowed = new Set(nav && Array.isArray(nav.allowed_tabs) ? nav.allowed_tabs : []);",
		"a.style.display = allowed.has(tab) ? '' : 'none';",
		"allowed_tabs: ['access-denied']",
	} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin navigation should include %q", want)
		}
	}
}
