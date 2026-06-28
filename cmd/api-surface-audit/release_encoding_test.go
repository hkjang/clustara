package main

import (
	"os"
	"path/filepath"
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
