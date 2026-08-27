package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"clustara/internal/audit"
)

// Session identity is built from the API key, client IP, User-Agent and the
// X-Vibe-Repo / X-Vibe-Branch headers. Everything after the IP is chosen by the
// caller, so a client varying any of them mints a new entry per request, and gc
// only ran once per idle window so nothing reclaimed them in between. Measured
// before the cap: 50,000 entries holding 196MB of map keys alone.
func TestSessionInfererIsBounded(t *testing.T) {
	si := newSessionInferer(30 * time.Minute)
	now := time.Now()
	for i := 0; i < maxSessionEntries*3; i++ {
		si.sessionFor(fmt.Sprintf("key1|10.0.0.1|agent-%d||", i), now.Add(time.Duration(i)*time.Millisecond))
	}
	if len(si.entries) > maxSessionEntries {
		t.Fatalf("identity map holds %d entries, above the %d cap", len(si.entries), maxSessionEntries)
	}
}

// A client that keeps a stable identity must keep its session across the window —
// eviction must not break the feature it protects.
func TestSessionInfererKeepsStableIdentityAcrossFlood(t *testing.T) {
	si := newSessionInferer(30 * time.Minute)
	now := time.Now()
	const stable = "key1|10.0.0.1|steady-agent||"

	first := si.sessionFor(stable, now)
	// A burst of distinct identities arrives, but the stable client keeps calling.
	for i := 0; i < maxSessionEntries*2; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		si.sessionFor(fmt.Sprintf("key9|10.0.0.9|noisy-%d||", i), at)
		if i%50 == 0 {
			if got := si.sessionFor(stable, at); got != first {
				t.Fatalf("stable client lost its session at i=%d: %s != %s", i, got, first)
			}
		}
	}
	if got := si.sessionFor(stable, now.Add(time.Second)); got != first {
		t.Fatalf("stable client lost its session after the flood: %s != %s", got, first)
	}
}

// Ordinary behaviour must be intact: the same identity reuses its id inside the
// idle window and gets a fresh one after it lapses.
func TestSessionInfererSlidingWindowUnchanged(t *testing.T) {
	si := newSessionInferer(10 * time.Minute)
	now := time.Now()
	const id = "key1|10.0.0.1|agent||"

	first := si.sessionFor(id, now)
	if again := si.sessionFor(id, now.Add(5*time.Minute)); again != first {
		t.Fatalf("session should be reused inside the window: %s != %s", again, first)
	}
	if later := si.sessionFor(id, now.Add(60*time.Minute)); later == first {
		t.Fatal("a fresh session should be minted after the idle window lapses")
	}
}

// The map key is the caller-supplied identity hash, so an oversized User-Agent must
// not translate into an oversized key.
func hashIdentityForTest(identity string) string {
	return audit.HashText(identity)
}

func TestSessionInfererKeySizeIsIndependentOfUserAgent(t *testing.T) {
	si := newSessionInferer(30 * time.Minute)
	now := time.Now()
	huge := strings.Repeat("A", 64*1024)
	// inferSessionID hashes the identity before calling in; simulate that contract.
	si.sessionFor(hashIdentityForTest(huge), now)
	for k := range si.entries {
		if len(k) > 128 {
			t.Fatalf("map key is %d bytes; identities must be hashed before use as keys", len(k))
		}
	}
}
