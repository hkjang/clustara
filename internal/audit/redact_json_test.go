package audit

import (
	"strings"
	"testing"
)

// Credentials reach the gateway as JSON far more often than as bare env-style
// assignments. The generic key=value rules used to require the separator to sit
// immediately after the key name, so the closing quote in `"api_key": "..."`
// broke every match and JSON-encoded secrets were logged in clear text unless
// they happened to match a vendor-specific rule. Each shape below must mask.
func TestRedactMasksCredentialAssignmentShapes(t *testing.T) {
	const secret = "internal-token-abcdefghij123"
	shapes := []struct {
		name  string
		input string
	}{
		{"bare equals", `api_key=` + secret},
		{"bare colon", `api_key: ` + secret},
		{"spaced equals", `api_key = "` + secret + `"`},
		{"json", `{"api_key": "` + secret + `"}`},
		{"json no space", `{"token":"` + secret + `"}`},
		{"json password", `{"password": "` + secret + `"}`},
		{"json client secret", `{"client_secret": "` + secret + `"}`},
		{"json camelCase", `{"apiKey": "` + secret + `"}`},
		{"yaml", "api_key: " + secret},
		{"single quoted", `api_key: '` + secret + `'`},
		{"fat arrow", `'api_key' => '` + secret + `'`},
		{"header style", `X-Api-Key: ` + secret},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.input)
			if strings.Contains(got, secret) {
				t.Fatalf("secret survived redaction\ninput:  %s\noutput: %s", tc.input, got)
			}
			if !strings.Contains(got, "[REDACTED") {
				t.Fatalf("no redaction tag emitted\ninput:  %s\noutput: %s", tc.input, got)
			}
		})
	}
}

// Masking a JSON body must leave it parseable-looking: the key and its quotes
// stay put and only the value is replaced.
func TestRedactPreservesJSONShape(t *testing.T) {
	got := Redact(`{"api_key": "internal-token-abcdefghij123", "model": "gpt-4"}`)
	want := `{"api_key": "[REDACTED]", "model": "gpt-4"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// Non-credential text must not be swept up by the widened patterns.
func TestRedactLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{
		`{"model": "claude-opus-5", "max_tokens": 1024}`,
		`the token bucket refills every second`,
		`retry: true`,
	} {
		if got := Redact(s); got != s {
			t.Fatalf("ordinary text was altered\ninput:  %s\noutput: %s", s, got)
		}
	}
}
