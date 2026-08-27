package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Evicting only expired entries was not a bound: distinct queries arriving faster
// than the TTL retires them leave the sweep with nothing to remove while the insert
// proceeds anyway. Measured before the cap, 50,000 distinct queries inside one TTL
// window left 45,001 entries, each holding result rows.
func TestDWCacheIsBounded(t *testing.T) {
	c := newDWQueryCache(45 * time.Second)
	now := time.Now()
	rows := []map[string]any{{"a": strings.Repeat("x", 512)}}
	for i := 0; i < maxDWCacheEntries*20; i++ {
		c.put(fmt.Sprintf("http://ch\nSELECT %d FORMAT JSON", i), rows, now.Add(time.Duration(i)*time.Millisecond))
	}
	if len(c.entries) > maxDWCacheEntries {
		t.Fatalf("cache holds %d entries, above the %d cap", len(c.entries), maxDWCacheEntries)
	}
}

// A dashboard refreshing the same query must keep hitting the cache even while other
// queries churn — eviction by age must not throw out the actively used entry.
func TestDWCacheKeepsActivelyRefreshedQuery(t *testing.T) {
	c := newDWQueryCache(45 * time.Second)
	now := time.Now()
	rows := []map[string]any{{"a": 1}}
	const hot = "http://ch\nSELECT hot FORMAT JSON"

	for i := 0; i < maxDWCacheEntries*5; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		c.put(fmt.Sprintf("http://ch\nSELECT cold%d FORMAT JSON", i), rows, at)
		c.put(hot, rows, at) // the dashboard keeps refreshing this one
	}
	if _, ok := c.get(hot, now.Add(time.Duration(maxDWCacheEntries*5)*time.Millisecond)); !ok {
		t.Fatal("the actively refreshed query was evicted by churn")
	}
}

// Ordinary use must still cache and expire normally.
func TestDWCacheStillCachesAndExpires(t *testing.T) {
	c := newDWQueryCache(10 * time.Second)
	now := time.Now()
	rows := []map[string]any{{"a": 1}}
	c.put("k", rows, now)
	if _, ok := c.get("k", now.Add(time.Second)); !ok {
		t.Fatal("entry should be served inside the TTL")
	}
	if _, ok := c.get("k", now.Add(time.Minute)); ok {
		t.Fatal("entry should expire after the TTL")
	}
}

// The semantic cache passed the prompt to the embedding model at whatever size the
// request happened to be — a 2MB single-turn message produced a 2MB embedding
// request, a paid round trip that the model would reject anyway.
func TestSemanticEmbedInputIsBounded(t *testing.T) {
	huge := strings.Repeat("q", 2<<20)
	body := []byte(`{"messages":[{"role":"user","content":"` + huge + `"}]}`)
	text := chatPromptText(body)
	if len(text) <= maxSemanticEmbedBytes {
		t.Fatalf("test premise broken: prompt text is only %d bytes", len(text))
	}
	if !semanticEmbedInputTooLarge(text) {
		t.Fatal("an oversized prompt must be declined before the embedding call")
	}
}

// A normal prompt stays well under the cap, so caching is unaffected.
func TestOrdinaryPromptIsUnderEmbedCap(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"What is the capital of France?"}]}`)
	text := chatPromptText(body)
	if semanticEmbedInputTooLarge(text) {
		t.Fatalf("ordinary prompt was declined: %d bytes", len(text))
	}
	if !strings.Contains(text, "capital of France") {
		t.Errorf("prompt text mangled: %q", text)
	}
}
