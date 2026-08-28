package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// The passthrough path (AUTH_ENABLED=false, the documented mode for editor
// clients) runs before any credential check. It derives an id from the bearer
// token's hash, caches it in extSeen and lazily writes an api_keys row whose name
// and team come straight from client headers.
//
// Neither the cache nor the labels were bounded: the map grew with the number of
// DISTINCT tokens the gateway had ever seen, and a single oversized header became
// an oversized database column.
func TestExternalKeyDedupeCacheIsBounded(t *testing.T) {
	srv, _ := newSSOTestServer(t)

	for i := 0; i < extSeenCap+50; i++ {
		srv.rememberExternalKey("key_probe_" + strings.Repeat("x", i%7) + itoa(i))
	}

	n := 0
	srv.extSeen.Range(func(_, _ any) bool {
		n++
		return true
	})
	if n > extSeenCap {
		t.Fatalf("the dedupe cache holds %d entries, above its %d cap; it grows with every distinct "+
			"bearer token the gateway has ever seen, on a path that runs before any credential check",
			n, extSeenCap)
	}
	if n == 0 {
		t.Fatal("the cache is empty after the reset; it should keep caching, just bounded")
	}
}

// A label from a client header must not become an unbounded column value, and
// must be cut on a character boundary.
func TestExternalLabelIsClamped(t *testing.T) {
	long := strings.Repeat("a", externalLabelMax*3)
	got := clampExternalLabel(long)
	if utf8.RuneCountInString(got) != externalLabelMax {
		t.Fatalf("clamped to %d runes, want %d", utf8.RuneCountInString(got), externalLabelMax)
	}

	// Multi-byte input must not be cut mid-rune.
	multi := strings.Repeat("한", externalLabelMax*2)
	got = clampExternalLabel(multi)
	if !utf8.ValidString(got) {
		t.Fatal("clamping produced an invalid UTF-8 string; the cut landed inside a rune")
	}
	if utf8.RuneCountInString(got) != externalLabelMax {
		t.Fatalf("multi-byte input clamped to %d runes, want %d", utf8.RuneCountInString(got), externalLabelMax)
	}

	// Ordinary values pass through untouched.
	if got := clampExternalLabel("  alice  "); got != "alice" {
		t.Fatalf("a normal label was altered: %q", got)
	}
}

// The clamp has to be reached from the request path, not just exist.
func TestExternalKeyRegistrationClampsHeaderLabels(t *testing.T) {
	srv, db := newSSOTestServer(t)
	srv.cfg.Auth.AttributeExternalKeys = true

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("X-Vibe-User", strings.Repeat("n", externalLabelMax*4))
	r.Header.Set("X-Vibe-Team", strings.Repeat("t", externalLabelMax*4))

	id := srv.attributeExternalKey(r, strings.Repeat("a", 64))
	if id == "passthrough" {
		t.Fatal("attribution was disabled; the test needs it on")
	}

	keys, err := db.ListAPIKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.ID != id {
			continue
		}
		if utf8.RuneCountInString(k.Name) > externalLabelMax {
			t.Fatalf("stored name is %d runes; a client header became an oversized column",
				utf8.RuneCountInString(k.Name))
		}
		if utf8.RuneCountInString(k.Team) > externalLabelMax {
			t.Fatalf("stored team is %d runes", utf8.RuneCountInString(k.Team))
		}
		return
	}
	t.Fatalf("no api_keys row was registered for %s", id)
}
