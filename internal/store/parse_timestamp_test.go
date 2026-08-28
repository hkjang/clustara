package store

import (
	"testing"
	"time"
)

// Zero means "absent", and for the expiry columns absent means "never expires".
// Returning zero for a value that is present but unreadable therefore turned
// corrupt data into an unlimited lifetime: the api-key gate, the security-ingest
// key check and the terminal grant all test
// `!ExpiresAt.IsZero() && ExpiresAt.Before(now)`, so an unparseable expires_at
// skipped the check entirely.
func TestUnparseableTimestampReadsAsExpiredNotAbsent(t *testing.T) {
	now := time.Now().UTC()

	if got := parseOptionalTime(""); !got.IsZero() {
		t.Fatalf("an empty value must stay absent, got %v", got)
	}

	for _, raw := range []string{
		"not a timestamp",
		"2026-08-29 05:54:00+00", // a plausible alternative format from another writer
		"0000-00-00",
	} {
		got := parseOptionalTime(raw)
		if got.IsZero() {
			t.Errorf("%q parsed to the zero time, which every expiry check reads as \"never expires\"", raw)
			continue
		}
		if !got.Before(now) {
			t.Errorf("%q parsed to %v, which is not in the past; the expiry checks would still pass", raw, got)
		}
	}
}

// Valid values must be unaffected, or the guard would expire everything.
func TestValidTimestampsStillParse(t *testing.T) {
	want := time.Date(2026, 8, 29, 5, 54, 0, 0, time.UTC)
	for _, raw := range []string{
		want.Format(time.RFC3339Nano),
		want.Format(time.RFC3339),
	} {
		got := parseOptionalTime(raw)
		if !got.Equal(want) {
			t.Fatalf("%q parsed to %v, want %v", raw, got, want)
		}
	}
}

// The revocation columns share the parser, and there the same sentinel means
// "revoked" — also the closed direction.
func TestUnparseableRevocationReadsAsRevoked(t *testing.T) {
	if parseOptionalTime("garbage").IsZero() {
		t.Fatal("an unreadable revoked_at read as \"not revoked\"")
	}
}
