package proxy

import (
	"sort"
	"sync"
	"time"
)

// dwQueryCache is a short-TTL in-memory cache for DW dashboard ClickHouse reads. The DW
// dashboard is polled by many admins against the same windows; caching identical queries
// for a few tens of seconds shields ClickHouse from repeated full-rollup scans (the spec's
// "30-60s cache" requirement). Keyed by ClickHouse URL + the full query SQL so a runtime
// connection swap never serves another cluster's rows. Cached rows are treated as
// read-only by callers (handlers only read values and build fresh output maps).
type dwQueryCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]dwCacheEntry
}

type dwCacheEntry struct {
	rows   []map[string]any
	stored time.Time
}

// newDWQueryCache builds a cache with the given TTL (default 45s, mid-range of the spec's
// 30-60s window, when ttl <= 0).
func newDWQueryCache(ttl time.Duration) *dwQueryCache {
	if ttl <= 0 {
		ttl = 45 * time.Second
	}
	return &dwQueryCache{ttl: ttl, entries: map[string]dwCacheEntry{}}
}

// get returns cached rows for a key if still within the TTL.
func (c *dwQueryCache) get(key string, now time.Time) ([]map[string]any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || now.Sub(e.stored) > c.ttl {
		return nil, false
	}
	return e.rows, true
}

// maxDWCacheEntries hard-caps the cache. Evicting only *expired* entries was not a
// bound: distinct queries arriving faster than the TTL retires them leave the sweep
// with nothing to remove while the insert proceeds anyway. Measured before this cap,
// 50,000 distinct queries inside one TTL window left 45,001 entries, each holding
// result rows. The key is the full query text, so entries are not small either.
const maxDWCacheEntries = 512

// put stores rows under a key, evicting expired entries and then, if the cache is
// still full, the oldest entries — so the cache stays bounded even when nothing has
// expired yet.
func (c *dwQueryCache) put(key string, rows []map[string]any, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxDWCacheEntries {
		for k, e := range c.entries {
			if now.Sub(e.stored) > c.ttl {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) >= maxDWCacheEntries {
		// Nothing had expired. Drop the oldest quarter in one pass: evicting by age
		// keeps the entries a dashboard is actively refreshing, and batching keeps
		// eviction amortised rather than scanning on every insert.
		stamps := make([]time.Time, 0, len(c.entries))
		for _, e := range c.entries {
			stamps = append(stamps, e.stored)
		}
		sort.Slice(stamps, func(i, j int) bool { return stamps[i].Before(stamps[j]) })
		cutoff := stamps[len(stamps)/4]
		for k, e := range c.entries {
			if !e.stored.After(cutoff) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < maxDWCacheEntries {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = dwCacheEntry{rows: rows, stored: now}
}

// clear drops all cached entries (used by the refresh endpoint) and returns the count cleared.
func (c *dwQueryCache) clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = map[string]dwCacheEntry{}
	return n
}
