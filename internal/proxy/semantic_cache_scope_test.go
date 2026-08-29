package proxy

import (
	"context"
	"testing"
	"time"

	"clustara/internal/store"
)

// The semantic cache matches on SIMILARITY, not equality. A global pool therefore serves one
// caller another caller's answer to a DIFFERENT question — which the exact cache never does,
// because an identical prompt only ever returns something the caller could have obtained by
// sending it themselves.
//
// The pool is now bounded by tenant. Reuse across the boundary requires the operator to ask
// for it by name.
func TestSemanticCacheDoesNotCrossTenants(t *testing.T) {
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()

	ref := []float64{1, 0, 0}
	if err := db.PutChatSemanticEntry(ctx, "e_alpha", "m", "team:alpha", ref,
		"application/json", []byte(`{"secret":"alpha internals"}`), time.Hour); err != nil {
		t.Fatal(err)
	}

	// A near-identical question from another team must not reach alpha's answer.
	near := []float64{0.99, 0.01, 0}
	if _, found, err := db.SearchChatSemantic(ctx, "m", "team:beta", near, 0.95, 200); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("a caller in one team was served another team's cached answer to a different question")
	}
	// The owning team still gets its own entry — the scoping must not simply break the cache.
	if _, found, err := db.SearchChatSemantic(ctx, "m", "team:alpha", near, 0.95, 200); err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatal("the team that stored the entry can no longer read it")
	}
	// The global pool is a separate pool, not a superset: an operator switching to global
	// does not retroactively gain access to entries stored under a tenant.
	if _, found, _ := db.SearchChatSemantic(ctx, "m", "", near, 0.95, 200); found {
		t.Fatal("a tenant-scoped entry leaked into the global pool")
	}
}

// The scope resolver is what decides the pool, so pin each mode — including the case that
// used to be the whole problem: nobody identified, everybody sharing.
func TestSemanticCacheScopeResolution(t *testing.T) {
	withTeam := &store.AuthContext{APIKeyID: "ak_1", TeamID: "alpha"}
	keyOnly := &store.AuthContext{APIKeyID: "ak_1"}

	if scope, usable := semanticCacheScope("global", nil); !usable || scope != "" {
		t.Fatalf("global mode = (%q, %v); it is the explicit shared pool", scope, usable)
	}
	if scope, usable := semanticCacheScope("team", withTeam); !usable || scope != "team:alpha" {
		t.Fatalf("team mode = (%q, %v)", scope, usable)
	}
	// A caller with a key but no team is still one identifiable caller: scope to the key
	// rather than dropping them into the shared pool.
	if scope, usable := semanticCacheScope("team", keyOnly); !usable || scope != "key:ak_1" {
		t.Fatalf("team mode with no team = (%q, %v); a known key still identifies a caller", scope, usable)
	}
	if scope, usable := semanticCacheScope("key", withTeam); !usable || scope != "key:ak_1" {
		t.Fatalf("key mode = (%q, %v)", scope, usable)
	}
	// Unidentified callers are excluded rather than pooled together — pooling them is the
	// shared pool the mode exists to prevent.
	if _, usable := semanticCacheScope("team", nil); usable {
		t.Fatal("an unidentified caller was given a semantic cache pool under team scope")
	}
	if _, usable := semanticCacheScope("key", &store.AuthContext{}); usable {
		t.Fatal("a caller with no key was given a semantic cache pool under key scope")
	}
	// An unset mode must land on the safe default, not on global.
	if _, usable := semanticCacheScope("", nil); usable {
		t.Fatal("an unset scope defaulted to sharing")
	}
}
