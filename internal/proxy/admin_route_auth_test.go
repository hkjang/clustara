package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// unauthenticatedAdminRoutes are the /admin paths that intentionally answer without
// a credential. The UI shell must render so the login overlay can appear (pinned by
// TestAdminLoginFlowBootContract), and its static assets carry no data.
var unauthenticatedAdminRoutes = map[string]string{
	"/admin":               "admin UI shell; must load so the login form can render",
	"/admin/":              "admin UI shell; must load so the login form can render",
	"/admin/assets/xterm/": "static terminal assets, no data",
	"/metrics":             "Prometheus scrape endpoint; aggregate process counters only, no per-key, per-team or per-user labels",
}

// identityGatedPrefixes are the route families that must establish who is calling.
// /admin needs an operator; /me and /team must resolve the caller before returning
// anything, since their whole contract is that you see only your own data or your
// own team's.
var identityGatedPrefixes = []string{"/admin", "/me", "/team", "/metrics"}

// The /me and /team families identify the caller through their own helpers. Those
// helpers do reach currentAccessClaims internally, so delegation-following already
// covers them, but naming them keeps the check working if a helper is ever
// restructured.
var authGatePattern = regexp.MustCompile(`authorize\w*\(|requireAdmin|currentAccessClaims|requireScope|verifyAccessToken|authenticate|adminIdentity|meUserID|meKeyContext|resolveTeamScope|meIdentity`)

func proxySources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(raw)
	}
	return out
}

// Every /admin, /me and /team route must reach an authorization check, directly or through the
// handler it delegates to. /admin/llm/prompts/compare did not: it served prompt
// telemetry — names, call volumes, token counts, KRW cost, latency, error rates —
// to anyone, with the api_key_id/team filter taken from the query string, while
// every sibling handler in the same file gated on authorizeAdmin.
func TestEveryIdentityGatedRouteIsAuthorized(t *testing.T) {
	src := proxySources(t)
	joined := strings.Join(valuesOf(src), "\n")

	routeRe := regexp.MustCompile(`(?:mux|r)\.HandleFunc\("([^"]+)",\s*s\.(\w+)\)`)
	funcRe := regexp.MustCompile(`(?s)func \(s \*Server\) (\w+)\([^)]*\)[^{]*\{(.*?)\n\}`)

	bodies := map[string]string{}
	for _, body := range src {
		for _, m := range funcRe.FindAllStringSubmatch(body, -1) {
			if _, seen := bodies[m[1]]; !seen {
				bodies[m[1]] = m[2]
			}
		}
	}

	var gated func(fn string, depth int, seen map[string]bool) bool
	gated = func(fn string, depth int, seen map[string]bool) bool {
		if depth > 3 || seen[fn] {
			return false
		}
		seen[fn] = true
		body, ok := bodies[fn]
		if !ok {
			return false
		}
		if authGatePattern.MatchString(body) {
			return true
		}
		for _, call := range regexp.MustCompile(`s\.(\w+)\(`).FindAllStringSubmatch(body, -1) {
			if _, known := bodies[call[1]]; known && gated(call[1], depth+1, seen) {
				return true
			}
		}
		return false
	}

	checked := 0
	for _, m := range routeRe.FindAllStringSubmatch(joined, -1) {
		path, handler := m[1], m[2]
		relevant := false
		for _, prefix := range identityGatedPrefixes {
			if strings.HasPrefix(path, prefix) {
				relevant = true
				break
			}
		}
		if !relevant {
			continue
		}
		if _, allowed := unauthenticatedAdminRoutes[path]; allowed {
			continue
		}
		checked++
		if !gated(handler, 0, map[string]bool{}) {
			t.Errorf("%s (%s) reaches no authorization check; add one, or record it in unauthenticatedAdminRoutes with the reason",
				path, handler)
		}
	}
	if checked < 100 {
		t.Fatalf("only %d identity-gated routes were analysed; the route scan is probably broken", checked)
	}
}

// The allowlist must not accumulate entries for routes that no longer exist, or it
// would silently excuse a future route reusing the path.
func TestUnauthenticatedAdminAllowlistIsCurrent(t *testing.T) {
	joined := strings.Join(valuesOf(proxySources(t)), "\n")
	for path, reason := range unauthenticatedAdminRoutes {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s has no recorded reason", path)
		}
		if !strings.Contains(joined, `HandleFunc("`+path+`"`) {
			t.Errorf("%s is allowlisted but no longer registered; remove it", path)
		}
	}
}

func valuesOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
