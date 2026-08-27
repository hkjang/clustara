package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"sync"
	"time"
)

// sessionInferer groups requests that arrive WITHOUT an explicit session id into
// "inferred" sessions, using a sliding inactivity window keyed by client identity.
//
// Most AI coding tools (Claude Code, Cursor, Roo Code, Qwen Code) never expose a
// session id at the HTTP level — they keep conversation state client-side. Without
// inference every request would be its own session. APMs solve this by running
// "inferred" sessions alongside "explicit" ones: requests from the same client that
// arrive close together are treated as one session until the client goes quiet for
// longer than the idle window, which starts a fresh session.
type sessionInferer struct {
	mu      sync.Mutex
	entries map[string]*inferredSession
	idle    time.Duration
	lastGC  time.Time
}

type inferredSession struct {
	id       string
	lastSeen time.Time
}

// maxSessionEntries bounds the identity map. Identity includes the User-Agent and
// the X-Vibe-Repo / X-Vibe-Branch headers, all chosen by the caller, so a client
// varying any of them mints a new entry on every request — and gc only runs once
// per idle window, so nothing reclaimed them in between. Measured before this cap:
// one client varying its User-Agent produced 50,000 entries holding 196MB of map
// keys alone.
const maxSessionEntries = 20000

func newSessionInferer(idle time.Duration) *sessionInferer {
	if idle <= 0 {
		idle = 30 * time.Minute
	}
	return &sessionInferer{entries: map[string]*inferredSession{}, idle: idle}
}

// sessionFor returns the inferred session id for a client identity at time now.
// If the identity was last seen within the idle window, the same id is reused and
// the window slides forward; otherwise a fresh id is minted.
func (si *sessionInferer) sessionFor(identity string, now time.Time) string {
	si.mu.Lock()
	defer si.mu.Unlock()
	si.gc(now)
	if e, ok := si.entries[identity]; ok && now.Sub(e.lastSeen) <= si.idle {
		e.lastSeen = now
		return e.id
	}
	id := mintSessionID(identity, now)
	si.evictIfFull(now)
	si.entries[identity] = &inferredSession{id: id, lastSeen: now}
	return id
}

func (si *sessionInferer) existingSession(identity string, now time.Time) (string, bool) {
	si.mu.Lock()
	defer si.mu.Unlock()
	si.gc(now)
	if e, ok := si.entries[identity]; ok && now.Sub(e.lastSeen) <= si.idle {
		e.lastSeen = now
		return e.id, true
	}
	return "", false
}

func (si *sessionInferer) sessionForRecovered(identity string, now time.Time, recoveredID string, recoveredLastSeen time.Time) string {
	si.mu.Lock()
	defer si.mu.Unlock()
	si.gc(now)
	if e, ok := si.entries[identity]; ok && now.Sub(e.lastSeen) <= si.idle {
		e.lastSeen = now
		return e.id
	}
	if recoveredID != "" && !recoveredLastSeen.IsZero() && now.Sub(recoveredLastSeen) <= si.idle {
		si.evictIfFull(now)
		si.entries[identity] = &inferredSession{id: recoveredID, lastSeen: now}
		return recoveredID
	}
	id := mintSessionID(identity, now)
	si.evictIfFull(now)
	si.entries[identity] = &inferredSession{id: id, lastSeen: now}
	return id
}

// evictIfFull keeps the identity map bounded. It first drops entries past the idle
// window regardless of the gc interval; if the map is still full — which is what a
// flood of fresh, distinct identities looks like — it removes just enough entries to
// make room, so eviction stays amortised O(1) per insert rather than scanning for a
// single oldest entry every time.
func (si *sessionInferer) evictIfFull(now time.Time) {
	if len(si.entries) < maxSessionEntries {
		return
	}
	si.lastGC = time.Time{}
	si.gc(now)
	if len(si.entries) < maxSessionEntries {
		return
	}
	// Still full: that is what a flood of fresh, distinct identities looks like.
	// Drop the least recently seen quarter in one pass. Evicting by age rather than
	// arbitrarily matters — an actively used identity is refreshed constantly, so it
	// must not be the one a burst of one-shot identities pushes out — and doing it in
	// batches keeps eviction amortised across many inserts.
	stamps := make([]time.Time, 0, len(si.entries))
	for _, e := range si.entries {
		stamps = append(stamps, e.lastSeen)
	}
	sort.Slice(stamps, func(i, j int) bool { return stamps[i].Before(stamps[j]) })
	cutoff := stamps[len(stamps)/4]
	for key, e := range si.entries {
		if !e.lastSeen.After(cutoff) {
			delete(si.entries, key)
		}
	}
	// Safety net for the degenerate case where every timestamp is identical.
	for key := range si.entries {
		if len(si.entries) < maxSessionEntries {
			return
		}
		delete(si.entries, key)
	}
}

// mintSessionID derives a short, opaque, stable id from the identity and the
// session's start time, so re-minting after an idle gap yields a distinct id.
func mintSessionID(identity string, now time.Time) string {
	sum := sha256.Sum256([]byte(identity + "|" + strconv.FormatInt(now.UnixNano(), 10)))
	return "sess_" + hex.EncodeToString(sum[:])[:12]
}

// gc evicts entries that have been idle past the window. Cheap and lazy: runs at
// most once per idle interval.
func (si *sessionInferer) gc(now time.Time) {
	if !si.lastGC.IsZero() && now.Sub(si.lastGC) < si.idle {
		return
	}
	si.lastGC = now
	for k, e := range si.entries {
		if now.Sub(e.lastSeen) > si.idle {
			delete(si.entries, k)
		}
	}
}
