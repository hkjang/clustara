package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleaseScriptEncoding ensures that scripts/gh_release.ps1 contains only ASCII
// characters. All Korean string literals in the script must be Unicode-escaped
// (e.g., [regex]::Unescape("\uXXXX")) to prevent encoding corruption when executed
// in Windows PowerShell 5.1 (which defaults to ANSI/CP949).
func TestReleaseScriptEncoding(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "gh_release.ps1")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read gh_release.ps1: %v", err)
	}

	for i, b := range data {
		// Allow UTF-8 BOM at the very beginning
		if i < 3 && (b == 0xef || b == 0xbb || b == 0xbf) {
			continue
		}
		if b > 127 {
			t.Errorf("FAIL: scripts/gh_release.ps1 contains non-ASCII byte 0x%x at index %d. To prevent Korean character corruption in Windows PowerShell, all Korean string literals in the script must be Unicode-escaped using [regex]::Unescape(\"\\uXXXX\").", b, i)
			break
		}
	}
}

// TestAppVersionMatchesChangelog ensures that the AppVersion constant in
// internal/proxy/server.go matches the latest version documented at the top
// of scripts/changelog.txt.
func TestAppVersionMatchesChangelog(t *testing.T) {
	serverGoPath := filepath.Join("..", "..", "internal", "proxy", "server.go")
	serverData, err := os.ReadFile(serverGoPath)
	if err != nil {
		t.Fatalf("failed to read server.go: %v", err)
	}

	// Extract const AppVersion = "vX.Y.Z"
	// Match: const AppVersion = "vX.Y.Z"
	// We use a simple regex to find the version string.
	importBlockEnd := string(serverData)
	constPrefix := `const AppVersion = "`
	start := strings.Index(importBlockEnd, constPrefix)
	if start == -1 {
		t.Fatalf("could not find 'const AppVersion = \"' in server.go")
	}
	start += len(constPrefix)
	end := strings.Index(importBlockEnd[start:], `"`)
	if end == -1 {
		t.Fatalf("could not find closing quote for AppVersion in server.go")
	}
	appVersion := importBlockEnd[start : start+end]

	changelogPath := filepath.Join("..", "..", "scripts", "changelog.txt")
	changelogData, err := os.ReadFile(changelogPath)
	if err != nil {
		t.Fatalf("failed to read changelog.txt: %v", err)
	}

	changelogStr := string(changelogData)
	firstLineEnd := strings.Index(changelogStr, "\n")
	if firstLineEnd == -1 {
		firstLineEnd = len(changelogStr)
	}
	firstLine := strings.TrimSpace(changelogStr[:firstLineEnd])
	if !strings.HasSuffix(firstLine, ":") {
		t.Fatalf("changelog.txt first line %q does not end with ':'", firstLine)
	}
	changelogVersion := strings.TrimSuffix(firstLine, ":")

	if appVersion != changelogVersion {
		t.Errorf("FAIL: version mismatch! server.go AppVersion is %q but changelog.txt latest version is %q", appVersion, changelogVersion)
	}
}
