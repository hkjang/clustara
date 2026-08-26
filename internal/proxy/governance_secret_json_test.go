package proxy

import (
	"strings"
	"testing"
)

// The secret firewall inspects request bodies, and gateway request bodies are
// JSON. Its key=value patterns used to require the separator immediately after
// the key name, so the closing quote in `"api_key": "..."` defeated every one of
// them — a credential could be sent to an upstream provider without ever being
// detected or blocked. Each shape below must produce a finding.
func TestSecretFirewallDetectsJSONEncodedCredentials(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantTyp string
	}{
		{"bare api key", `api_key=internal-token-abcdefghij123`, "api_key"},
		{"json api key", `{"api_key": "internal-token-abcdefghij123"}`, "api_key"},
		{"json api key no space", `{"api_key":"internal-token-abcdefghij123"}`, "api_key"},
		{"json camelCase", `{"apiKey": "internal-token-abcdefghij123"}`, "api_key"},
		{"json x-api-key", `{"x-api-key": "internal-token-abcdefghij123"}`, "api_key"},
		{"json client secret", `{"client_secret": "s3cr3tinternalvalue1234"}`, "api_key"},
		{"json password", `{"password": "hunter2internal"}`, "password"},
		{"json access token", `{"access_token": "abcdefghijklmnopqrstuvwx"}`, "access_token"},
		{"json refresh token", `{"refresh_token": "abcdefghijklmnopqrstuvwx"}`, "access_token"},
		{"yaml password", "password: hunter2internal", "password"},
		{"fat arrow", `'password' => 'hunter2internal'`, "password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			types := findingTypes(detectSecretsInText(tc.body))
			found := false
			for _, ty := range types {
				if ty == tc.wantTyp {
					found = true
				}
			}
			if !found {
				t.Fatalf("secret firewall missed %s\nbody:  %s\ntypes: %v", tc.wantTyp, tc.body, types)
			}
		})
	}
}

// Masking a detected credential must remove the value while leaving the
// surrounding JSON structure intact.
func TestMaskSecretTextPreservesJSONShape(t *testing.T) {
	got := maskSecretText(`{"api_key": "internal-token-abcdefghij123", "model": "gpt-4"}`)
	if strings.Contains(got, "internal-token-abcdefghij123") {
		t.Fatalf("credential survived masking: %s", got)
	}
	if !strings.Contains(got, `"model": "gpt-4"`) {
		t.Fatalf("masking damaged unrelated fields: %s", got)
	}
}

// An ordinary LLM request body must not be flagged, or the firewall becomes noise.
func TestSecretFirewallIgnoresOrdinaryRequestBody(t *testing.T) {
	body := `{"model":"claude-opus-5","max_tokens":1024,"messages":[{"role":"user","content":"summarize this"}]}`
	if types := findingTypes(detectSecretsInText(body)); len(types) != 0 {
		t.Fatalf("ordinary body flagged as secret-bearing: %v", types)
	}
}
