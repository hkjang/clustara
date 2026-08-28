package proxy

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
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
//
// TestEveryRegisteredRouteIsAccountedFor covers everything else, so this list is
// only about which families get the stricter per-family framing.
var identityGatedPrefixes = []string{"/admin", "/me", "/team", "/metrics"}

// publicRoutes are the paths that intentionally answer without an authenticated
// caller, each with the reason it is safe.
//
// This exists because the prefix list above audited four families out of a mux
// carrying well over five hundred routes. Everything else — the /api/v1 rollout
// surface among them, which drives real cluster changes — was simply outside the
// guard. Those handlers did all gate correctly, but nothing would have caught a
// new one that did not. Inverting the rule closes that: a route is either gated
// or named here, and a path nobody classified fails the build.
var publicRoutes = map[string]string{
	"/health":       "liveness probe; no data",
	"/healthz":      "liveness probe; no data",
	"/ready":        "readiness probe; no data",
	"/readyz":       "readiness probe; no data",
	"/favicon.ico":  "static icon",
	"/openapi.json": "API shape only; the spec documents the auth each route requires",
	"/swagger":      "renders the spec above",

	// Sign-in surface: these are how a caller obtains a credential, so they
	// cannot require one. Each carries its own protection instead — password
	// verification, the OIDC state/nonce check, or a signed logout_token.
	"/auth/login":                        "issues the credential; throttled and audited",
	"/auth/refresh":                      "the refresh token is the credential",
	"/auth/logout":                       "revokes whatever credential was presented",
	"/auth/sso/status":                   "advertises whether SSO is configured",
	"/auth/keycloak/login":               "starts the OIDC flow",
	"/auth/keycloak/callback":            "validates state, nonce and the signed id_token",
	"/auth/keycloak/logout":              "revokes the presented session",
	"/auth/keycloak/backchannel-logout":  "authenticated by the RS256 logout_token, verified against JWKS",
	"/auth/keycloak/frontchannel-logout": "issuer-checked; revokes by sid only",

	// Machine surfaces that authenticate on something other than a user identity.
	"/ingest/k8s/agent/events":         "cluster-scoped agent token, validated after decoding the batch",
	"/integrations/mattermost/command": "verified against the configured Mattermost token",
	"/vcs/events":                      "webhook signature",
	"/vcs/webhook/":                    "webhook signature",
}

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
	// Strict: only delegation through Server methods counts for these families.
	isGated := routeAuthAnalyzer(t, src, false)
	gated := func(fn string, _ int, _ map[string]bool) bool { return isGated(fn) }

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

// TestEveryRegisteredRouteIsAccountedFor is the inverted rule: every path handed
// to the mux must reach an authorization check, or be named in publicRoutes with
// the reason it needs none. The per-family test above only ever looked at four
// prefixes, so whole surfaces — /api/v1 (rollout requests and approvals),
// /billing, /security, /permissions, /mcp, /v1 — were never examined at all.
func TestEveryRegisteredRouteIsAccountedFor(t *testing.T) {
	src := proxySources(t)
	// Broad: the proxy surface gates inside a pipeline step reached through a
	// method value on another receiver, so following Server methods alone would
	// report /v1/chat/completions as ungated when stepAuth gates it.
	gated := routeAuthAnalyzer(t, src, true)

	routeRe := regexp.MustCompile(`(?:mux|r)\.HandleFunc\("([^"]+)",\s*s\.(\w+)\)`)
	joined := strings.Join(valuesOf(src), "\n")

	checked := 0
	for _, m := range routeRe.FindAllStringSubmatch(joined, -1) {
		path, handler := m[1], m[2]
		if _, ok := publicRoutes[path]; ok {
			continue
		}
		if _, ok := unauthenticatedAdminRoutes[path]; ok {
			continue
		}
		checked++
		if !gated(handler) {
			t.Errorf("%s (%s) reaches no authorization check and is not listed in publicRoutes. "+
				"Add a gate, or record it in publicRoutes with the reason it is safe without one.",
				path, handler)
		}
	}
	// The mux carries hundreds of routes; a scan finding only a handful has broken.
	if checked < 400 {
		t.Fatalf("only %d routes were analysed; the route scan is probably broken", checked)
	}
}

// TestPublicRouteAllowlistIsCurrent keeps publicRoutes from outliving its routes,
// which would silently excuse a future handler that reuses the path.
func TestPublicRouteAllowlistIsCurrent(t *testing.T) {
	joined := strings.Join(valuesOf(proxySources(t)), "\n")
	for path, reason := range publicRoutes {
		if !strings.Contains(joined, `"`+path+`"`) {
			t.Errorf("publicRoutes lists %s (%q) but no such route is registered; remove it", path, reason)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("publicRoutes[%s] has no reason recorded", path)
		}
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

// routeAuthAnalyzer builds the shared "does this handler reach an authorization
// check" predicate. It follows delegation up to three levels, because handlers
// commonly gate inside a helper rather than at the top of the route function.
// routeAuthAnalyzer builds the shared "does this handler reach an authorization
// check" predicate, following delegation up to three levels because handlers
// commonly gate inside a helper rather than at the top of the route function.
//
// It parses rather than pattern-matches. A regex over the file text has to guess
// where a function body ends, and that guess shifts as the set of declarations it
// matches changes — the first draft of the broad mode reported the correctly
// gated handleRequestDiff as ungated purely because its declaration fell inside
// another match's span.
//
// allReceivers widens the walk to every method in the package and follows method
// values as well as calls, because the proxy pipeline reaches its gate through
// `stepFunc{"auth", (*requestPipeline).stepAuth}`, never a direct call. The
// strict mode stays Server-only so the /admin, /me and /team families keep the
// tighter guarantee that caught the ungated prompt-compare route.
func routeAuthAnalyzer(t *testing.T, src map[string]string, allReceivers bool) func(fn string) bool {
	t.Helper()
	fset := token.NewFileSet()

	type method struct {
		gated bool
		calls []string
	}
	methods := map[string]method{}
	serverMethod := map[string]bool{}

	for name, body := range src {
		file, err := parser.ParseFile(fset, name, body, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Body == nil {
				continue
			}
			onServer := receiverTypeName(fn.Recv.List[0].Type) == "Server"
			if !onServer && !allReceivers {
				continue
			}
			// A Server method always wins the name, so a same-named method on
			// another type cannot shadow it and hide its gate.
			if _, taken := methods[fn.Name.Name]; taken && (!onServer || serverMethod[fn.Name.Name]) {
				continue
			}

			var buf bytes.Buffer
			if err := printer.Fprint(&buf, fset, fn.Body); err != nil {
				t.Fatal(err)
			}
			m := method{gated: authGatePattern.MatchString(buf.String())}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					m.calls = append(m.calls, sel.Sel.Name)
				}
				return true
			})
			methods[fn.Name.Name] = m
			serverMethod[fn.Name.Name] = onServer
		}
	}

	var walk func(fn string, depth int, seen map[string]bool) bool
	walk = func(fn string, depth int, seen map[string]bool) bool {
		if depth > 3 || seen[fn] {
			return false
		}
		seen[fn] = true
		m, ok := methods[fn]
		if !ok {
			return false
		}
		if m.gated {
			return true
		}
		for _, call := range m.calls {
			if _, known := methods[call]; known && walk(call, depth+1, seen) {
				return true
			}
		}
		return false
	}
	return func(fn string) bool { return walk(fn, 0, map[string]bool{}) }
}

func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}
