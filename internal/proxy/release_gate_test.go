package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Release Quality Gate 2.0 (CLU-REQ-13).
//
// As releases ship fast (v0.9.x cadence), small consistency drifts (changelog/doc/version) slip
// through. These tests are the durable gate: they fail `go test` (and therefore the release) when
// the version isn't consistently propagated across the binary, changelog, and operations doc, or
// when the changelog has structural problems. TestAppVersionMatchesNewestRelease (openapi_test.go)
// covers AppVersion↔changelog; this adds the docs + structural checks.

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

// TestReleaseGateDocVersionMatches asserts the operations doc header + feature-status heading carry
// the current AppVersion, so docs never lag the binary at release time.
func TestReleaseGateDocVersionMatches(t *testing.T) {
	doc := repoFile(t, "docs", "K8S_OPERATIONS_HUB.md")

	headerRe := regexp.MustCompile(`\*\*버전:\s*(v0\.\d+\.\d+)\*\*`)
	hm := headerRe.FindStringSubmatch(doc)
	if hm == nil {
		t.Fatalf("docs header version marker not found (expected '**버전: v0.x.y**')")
	}
	if !strings.EqualFold(hm[1], AppVersion) {
		t.Fatalf("docs header version %s != AppVersion %s — bump the doc header when cutting a release", hm[1], AppVersion)
	}

	statusRe := regexp.MustCompile(`기능 상태 \((v0\.\d+\.\d+)\)`)
	sm := statusRe.FindStringSubmatch(doc)
	if sm == nil {
		t.Fatalf("docs feature-status heading not found (expected '기능 상태 (v0.x.y)')")
	}
	if !strings.EqualFold(sm[1], AppVersion) {
		t.Fatalf("docs feature-status heading %s != AppVersion %s", sm[1], AppVersion)
	}
}

// TestReleaseGateChangelogStructure asserts the changelog has no duplicate top-level version
// headers and that versions descend from the top (newest first), so the "newest entry" the release
// gate keys on is unambiguous.
func TestReleaseGateChangelogStructure(t *testing.T) {
	body := repoFile(t, "scripts", "changelog.txt")
	re := regexp.MustCompile(`(?m)^v0\.(\d+)\.(\d+):`)
	matches := re.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		t.Fatal("no version entries in changelog")
	}
	seen := map[string]bool{}
	prevRank := 1 << 30
	for _, m := range matches {
		v := "v0." + m[1] + "." + m[2]
		if seen[v] {
			t.Fatalf("duplicate changelog entry for %s — each version must appear once", v)
		}
		seen[v] = true
		minor := atoiSafe(m[1])
		patch := atoiSafe(m[2])
		rank := minor*1000 + patch
		if rank > prevRank {
			t.Fatalf("changelog not newest-first: %s appears after a newer entry", v)
		}
		prevRank = rank
	}
}

// TestReleaseGateChangelogMentionsVersion asserts the newest changelog entry's body cites its own
// version (the "(v0.x.y)" tag), catching copy-paste bumps that forget to update the inline version.
func TestReleaseGateChangelogMentionsVersion(t *testing.T) {
	body := repoFile(t, "scripts", "changelog.txt")
	headerRe := regexp.MustCompile(`(?m)^v0\.\d+\.\d+:`)
	loc := headerRe.FindStringIndex(body)
	if loc == nil {
		t.Fatal("no version entry")
	}
	// The newest entry spans from its header to the next header (or EOF).
	rest := body[loc[1]:]
	if next := headerRe.FindStringIndex(rest); next != nil {
		rest = rest[:next[0]]
	}
	if !strings.Contains(rest, "("+AppVersion+")") && !strings.Contains(rest, AppVersion) {
		t.Fatalf("newest changelog entry does not mention %s in its body", AppVersion)
	}
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
