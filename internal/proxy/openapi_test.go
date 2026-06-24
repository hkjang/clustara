package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestOpenAPISwaggerAndVersion(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	// openapi.json: valid JSON carrying the gateway version.
	resp, err := http.Get(srv.URL + "/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/openapi.json = %d", resp.StatusCode)
	}
	var spec map[string]any
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	info, _ := spec["info"].(map[string]any)
	if info["version"] != AppVersion {
		t.Errorf("openapi version = %v, want %s", info["version"], AppVersion)
	}
	pathsMap, _ := spec["paths"].(map[string]any)
	if _, ok := pathsMap["/v1/chat/completions"]; !ok {
		t.Error("openapi.json missing /v1/chat/completions path")
	}
	// Comprehensive coverage: the spec should document the whole surface, not a handful.
	if len(pathsMap) < 120 {
		t.Errorf("expected comprehensive spec (>=120 paths), got %d", len(pathsMap))
	}
	for _, p := range []string{
		"/admin/text2sql/golden", "/admin/okf/documents", "/admin/llm/traces",
		"/me/keys", "/admin/settings/by-key/{key}", "/admin/dw/clickhouse/overview",
		"/admin/mcp/policies/{server}", "/admin/routing/decisions/{id}",
	} {
		if _, ok := pathsMap[p]; !ok {
			t.Errorf("openapi.json missing expected path %s", p)
		}
	}

	// swagger page renders and points at the spec.
	sw, err := http.Get(srv.URL + "/swagger")
	if err != nil {
		t.Fatal(err)
	}
	swBody, _ := io.ReadAll(sw.Body)
	sw.Body.Close()
	if sw.StatusCode != http.StatusOK || !strings.Contains(string(swBody), "/openapi.json") {
		t.Fatalf("/swagger should render and reference /openapi.json (status %d)", sw.StatusCode)
	}

	// /auth/me exposes the version (legacy/no-auth mode in testConfig).
	me, err := http.Get(srv.URL + "/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	var meBody map[string]any
	json.NewDecoder(me.Body).Decode(&meBody)
	me.Body.Close()
	if meBody["version"] != AppVersion {
		t.Errorf("/auth/me version = %v, want %s", meBody["version"], AppVersion)
	}
}

// TestAppVersionMatchesNewestRelease pins AppVersion to the NEWEST (top-most) entry in
// changelog.txt — which is exactly what the release tag is cut from (scripts/gh_release.ps1).
//
// Note: changelog.txt intentionally retains the pre-rebrand gateway lineage (v0.1.x … v0.71.x)
// below the current Clustara line (v0.2.0 → v0.4.0 → …). We therefore compare against the newest
// ENTRY (file order), not the numeric max across the whole file — the latter would wrongly pin
// AppVersion to the defunct higher-numbered lineage and is the root of past version drift.
func TestAppVersionMatchesNewestRelease(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "changelog.txt")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read changelog: %v", err)
	}
	re := regexp.MustCompile(`(?m)^v0\.(\d+)\.(\d+):`)
	m := re.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("no v0.x.y release entry found in %s", path)
	}
	newest := "v0." + m[1] + "." + m[2]
	if _, _, ok := parseAppVersion(AppVersion); !ok {
		t.Fatalf("AppVersion must use v0.x.y format, got %q", AppVersion)
	}
	if !strings.EqualFold(AppVersion, newest) {
		t.Fatalf("AppVersion %s != newest changelog entry %s — bump AppVersion when cutting a release", AppVersion, newest)
	}
}

func parseAppVersion(v string) (minor, patch int, ok bool) {
	re := regexp.MustCompile(`^v0\.(\d+)\.(\d+)$`)
	m := re.FindStringSubmatch(strings.TrimSpace(v))
	if len(m) != 3 {
		return 0, 0, false
	}
	minor, _ = strconv.Atoi(m[1])
	patch, _ = strconv.Atoi(m[2])
	return minor, patch, true
}
