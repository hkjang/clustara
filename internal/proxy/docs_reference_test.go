package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The docs are the promises made outside the code, and this session has already found two
// that had drifted: the ClusterRole in K8S_OPERATIONS_HUB granted permissions the collector
// no longer matched (v0.9.243), and SAFETY_GUIDE promised a bypass audit trail that did not
// exist (v0.9.255). Both were caught by reading. These pin the classes that can be checked
// mechanically, so the next drift is caught by the suite instead.
//
// All three surfaces were clean when this was written; the value is that they stay clean.

// docsDir is repo-root relative to this package.
const docsDir = "../../docs"

// Every endpoint the docs name in backticks must be a route the server registers. A doc that
// sends an operator to a path that 404s is worse than one that says nothing.
func TestDocumentedEndpointsAreRegistered(t *testing.T) {
	routes := registeredRoutePaths(t)
	pattern := regexp.MustCompile("`((?:/admin|/v1|/auth|/me|/ingest|/mcp|/healthz|/readyz|/metrics)[A-Za-z0-9_\\-/{}.:]*)`")

	forEachDoc(t, func(name, text string) {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			path := strings.SplitN(match[1], "?", 2)[0]
			// Prose notation, not a path: "/v1/..." means "any /v1 route", "/admin/okf/*" a
			// family. Both are documentation shorthand and there is nothing to resolve.
			if strings.HasSuffix(path, "...") || strings.HasSuffix(path, "*") {
				continue
			}
			path = strings.TrimSuffix(path, ".")
			if routeExists(routes, path) {
				continue
			}
			t.Errorf("%s documents %q, which no mux route serves", name, path)
		}
	})
}

// Every environment variable the docs name must be one the gateway actually reads. A
// documented knob nobody reads is a setting an operator sets and then wonders why nothing
// changed.
func TestDocumentedEnvVarsAreRead(t *testing.T) {
	known := envNamesReferencedInCode(t)
	pattern := regexp.MustCompile(`\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b`)

	forEachDoc(t, func(name, text string) {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			token := match[1]
			if known[token] || docEnvExceptions[token] || strings.HasPrefix(token, "REPLACE_WITH") ||
				strings.HasPrefix(token, "REDACTED_") {
				continue
			}
			t.Errorf("%s documents environment variable %q, which no code path reads", name, token)
		}
	})
}

// Every runtime setting key the docs name must exist in the registry, either as a key or as
// a category an operator can navigate to.
func TestDocumentedSettingKeysExist(t *testing.T) {
	keys, categories := settingKeysAndCategories()
	pattern := regexp.MustCompile("`([a-z][a-z0-9_]*(?:\\.[a-z0-9_]+)+)`")

	forEachDoc(t, func(name, text string) {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			token := match[1]
			// Only judge tokens whose first segment is a real settings category; everything
			// else with a dot in it is a filename, a hostname or a version string.
			head := strings.SplitN(token, ".", 2)[0]
			if !categoryHeads(categories)[head] {
				continue
			}
			if keys[token] || categories[token] {
				continue
			}
			t.Errorf("%s documents setting %q, which is neither a registry key nor a category",
				name, token)
		}
	})
}

// docEnvExceptions are tokens that look like environment variables but are not gateway
// configuration, with the reason each is exempt.
var docEnvExceptions = map[string]bool{
	// Third-party process configuration shown in deployment examples.
	"CGO_ENABLED": true, "POSTGRES_DB": true, "POSTGRES_USER": true, "POSTGRES_PASSWORD": true,
	"REDISCLI_AUTH": true, "ON_ERROR_STOP": true, "DCGM_EXPORTER_KUBERNETES": true,
	// Shell variables defined inside the doc's own example commands.
	"GATEWAY_VERSION": true, "PROXY_KEY": true,
	// Prose: a masked value and a concept name, not settings.
	"MASKED_API_KEY": true, "LEASE_TTL": true,
	// Documentation file names written in caps.
	"ADMIN_GUIDE": true, "ADMIN_UI_DESIGN": true, "ARCHITECTURE_MODULES": true,
	"GITOPS_CHANGE_MANAGER": true, "K8S_AGENT": true, "K8S_OPERATIONS_HUB": true,
	"K8S_PHASE2_PLAN": true, "OPERATIONS": true, "POSTGRES_GUIDE": true, "RELEASE_GUIDE": true,
	"SAFETY_GUIDE": true, "SERVICE_PLATFORM": true, "USER_GUIDE": true,
	// GPU metric label names quoted from DCGM output.
	"GPU_I_ID": true, "GPU_I_PROFILE": true,
	// Kubernetes flags quoted in agent install instructions.
	"KUBE_INSECURE_TLS": true, "CLUSTARA_AGENT_BATCH_INTERVAL": true,
	"CLUSTARA_AGENT_HEARTBEAT_INTERVAL": true,
}

func forEachDoc(t *testing.T, visit func(name, text string)) {
	t.Helper()
	entries, err := os.ReadDir(docsDir)
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	seen := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(docsDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		seen++
		visit(entry.Name(), string(raw))
	}
	if seen < 5 {
		t.Fatalf("only %d markdown docs found; the scan is looking at the wrong place", seen)
	}
}

func registeredRoutePaths(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`).FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = true
	}
	if len(out) < 100 {
		t.Fatalf("only %d routes found; the scan is looking at the wrong place", len(out))
	}
	return out
}

func routeExists(routes map[string]bool, path string) bool {
	if routes[path] || routes[path+"/"] || routes[strings.TrimSuffix(path, "/")] {
		return true
	}
	// Prefix routes serve everything below them, including documented {id} segments.
	base := regexp.MustCompile(`\{[^}]+\}.*$`).ReplaceAllString(path, "")
	for route := range routes {
		if !strings.HasSuffix(route, "/") || isCatchAllRoute(route) {
			continue
		}
		if strings.HasPrefix(path, route) || strings.HasPrefix(base, route) {
			return true
		}
	}
	return false
}

// isCatchAllRoute reports whether a prefix route is the shell rather than an API surface.
// "/admin/" serves the SPA for anything under it, so counting it as a match made this whole
// check vacuous for every documented admin path — the first version of this test could not
// fail, which is how injecting a fake endpoint into a doc found it.
func isCatchAllRoute(route string) bool {
	return len(strings.FieldsFunc(route, func(r rune) bool { return r == '/' })) < 2
}

func envNamesReferencedInCode(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	literal := regexp.MustCompile(`"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"`)
	for _, dir := range []string{".", "../config", "../store", "../collector", "../kube", "../agent", "../audit", "../analyzer"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			for _, m := range literal.FindAllStringSubmatch(string(raw), -1) {
				out[m[1]] = true
			}
		}
	}
	if len(out) < 100 {
		t.Fatalf("only %d env-shaped literals found in code; the scan is looking at the wrong place", len(out))
	}
	return out
}

func settingKeysAndCategories() (map[string]bool, map[string]bool) {
	keys := map[string]bool{}
	categories := map[string]bool{}
	for _, d := range settingRegistry {
		keys[d.Key] = true
		if d.Category != "" {
			categories[d.Category] = true
		}
	}
	return keys, categories
}

func categoryHeads(categories map[string]bool) map[string]bool {
	out := map[string]bool{}
	for c := range categories {
		out[strings.SplitN(c, ".", 2)[0]] = true
	}
	return out
}
