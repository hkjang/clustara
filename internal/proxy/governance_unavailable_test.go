package proxy

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

const secretBody = `{"model":"test-model","messages":[{"role":"user","content":"my key is AKIAABCDEFGHIJKLMNOP"}]}`
const cleanBody = `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`

// evaluateGovernance discarded the error from ActivePolicyRules and returned
// governanceDecision{SecretAction: "detect"} — byte-identical to "every rule ran and none
// matched". So a database problem silently switched governance off for every LLM request:
// deny lists unenforced, approval requirements skipped, and the secret firewall degraded
// from block to detect. Nothing anywhere said so.
//
// Measured: with the policy set healthy the gate returns blocked=true secretAction="block";
// with policy_rules dropped it returns blocked=false secretAction="detect".
//
// The MCP path already treated the same failure as blocking for destructive tools. This one
// threw it away.
func TestGovernanceBlocksSecretsWhenThePolicySetCannotBeLoaded(t *testing.T) {
	db, server, dbPath := governanceFailureServer(t)
	assertPolicyBlocks(t, server, secretBody, "healthy policy set")
	breakPolicyRules(t, dbPath)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	meta := store.LogRecord{Request: store.RequestLog{ID: "req_1", Model: "test-model", Endpoint: "/v1/chat/completions"}}
	_, blocked := server.enforceOpenAIGovernance(w, r, &meta, []byte(secretBody), nil, nil, 0, true, "request")

	if !blocked {
		t.Fatal("a request carrying a credential was forwarded upstream while the policy set " +
			"could not be read; with the policy unknown, sending the secret is the one " +
			"irreversible option")
	}
	if got := w.Header().Get("X-Governance"); got != "unavailable" {
		t.Fatalf("X-Governance = %q, want unavailable so the caller knows this is not a verdict", got)
	}
	if !strings.Contains(meta.Request.Error, "확인할 수 없다") {
		t.Fatalf("the refusal must say the policy could not be checked rather than implying a "+
			"violation, got %q", meta.Request.Error)
	}
	// The gap has to be visible where governance is read, not only in the response.
	events, err := db.PolicyDecisionEventsForRequest(context.Background(), "req_1")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.RuleName == "POLICY_UNAVAILABLE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no POLICY_UNAVAILABLE decision event was recorded: %+v", events)
	}
}

// Blocking everything on a transient read failure would turn a database blip into a full
// outage, so an ordinary request still goes through — but marked, so nobody reads the
// absence of a block as a pass.
func TestGovernanceMarksButAllowsOrdinaryRequestsWhenUnavailable(t *testing.T) {
	_, server, dbPath := governanceFailureServer(t)
	breakPolicyRules(t, dbPath)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	meta := store.LogRecord{Request: store.RequestLog{ID: "req_2", Model: "test-model", Endpoint: "/v1/chat/completions"}}
	_, blocked := server.enforceOpenAIGovernance(w, r, &meta, []byte(cleanBody), nil, nil, 0, true, "request")

	if blocked {
		t.Fatal("an ordinary request was blocked by a policy read failure; a database blip must " +
			"not become a gateway outage")
	}
	if got := w.Header().Get("X-Governance"); got != "unavailable" {
		t.Fatalf("X-Governance = %q; an unenforced request must not look like an enforced one", got)
	}
}

// A healthy policy set must not be marked unavailable — the marker has to mean something.
func TestHealthyGovernanceIsNotMarkedUnavailable(t *testing.T) {
	_, server, _ := governanceFailureServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	meta := store.LogRecord{Request: store.RequestLog{ID: "req_3", Model: "other-model", Endpoint: "/v1/chat/completions"}}
	_, blocked := server.enforceOpenAIGovernance(w, r, &meta, []byte(cleanBody), nil, nil, 0, true, "request")
	if blocked {
		t.Fatalf("a model the policy does not deny was blocked: %q", meta.Request.Error)
	}
	if got := w.Header().Get("X-Governance"); got != "" {
		t.Fatalf("X-Governance = %q on a healthy evaluation", got)
	}
}

// assertPolicyBlocks pins that the seeded policy really does block, so the failure case
// below is measuring a change in behaviour rather than a policy that never worked.
func assertPolicyBlocks(t *testing.T, server *Server, body, label string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	meta := store.LogRecord{Request: store.RequestLog{ID: "req_pre", Model: "test-model", Endpoint: "/v1/chat/completions"}}
	if _, blocked := server.enforceOpenAIGovernance(w, r, &meta, []byte(body), nil, nil, 0, true, "request"); !blocked {
		t.Fatalf("%s: the seeded deny policy did not block, so this test proves nothing", label)
	}
}

func governanceFailureServer(t *testing.T) (*store.SQLStore, *Server, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	db, err := store.Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.UpsertPolicyWithRules(context.Background(),
		store.Policy{ID: "pol1", Name: "deny", Enabled: true, Priority: 1, RolloutPercent: 100, CreatedAt: now, UpdatedAt: now},
		[]store.PolicyRule{{ID: "r1", PolicyID: "pol1", Name: "deny-rule", Enabled: true, Priority: 1,
			Conditions: map[string]any{},
			Actions:    map[string]any{"deny_models": []string{"test-model"}, "secret_action": "block"},
			CreatedAt:  now, UpdatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "gov.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	return db, server, dbPath
}

// breakPolicyRules makes the active-rule load fail while the rest of the store keeps
// working, so enforcement reaches the failure through the real code path.
func breakPolicyRules(t *testing.T, dbPath string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open store file: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE policy_rules`); err != nil {
		t.Fatalf("break policy_rules: %v", err)
	}
}
