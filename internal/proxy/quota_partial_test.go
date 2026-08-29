package proxy

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// checkQuotas returned on the first lookup error with Allowed=true, and stepQuota then only
// looked at the decision when err was nil. Two things followed.
//
// One: a failure reading an early scope discarded every scope behind it. The scopes run
// global, api_key, ip, team, so one slow aggregate on the global scope silently disabled the
// api-key, ip and team limits that were perfectly readable.
//
// Two: even a breach that WAS found could be suppressed, because any error at all sent the
// caller down the "warn and continue" branch.
//
// The aggregate this depends on scans request_logs joined to token_usage, so it gets slower
// exactly as usage grows: the check is most likely to fail when it matters most.
func TestQuotaBreachSurvivesAnUnreadableScope(t *testing.T) {
	now := time.Now()
	scopes := []quotaScopeRef{
		{"global", "*"},
		{"api_key", "ak_1"},
	}
	loadErr := errors.New("usage aggregate timed out")

	decision, errs := evaluateQuotaScopes(now, scopes,
		func(s quotaScopeRef) ([]store.QuotaRecord, error) {
			if s.scope == "global" {
				return nil, loadErr
			}
			return []store.QuotaRecord{{ID: "q1", Scope: "api_key", ScopeValue: "ak_1", Period: "daily", TokenLimit: 100}}, nil
		},
		func(q store.QuotaRecord, start time.Time) (float64, int64, error) {
			return 0, 500, nil // well over the 100-token limit
		})

	if decision.Allowed {
		t.Fatal("a readable api-key quota was over its limit, but an unreadable global scope " +
			"let the request through; one failed lookup disabled every limit behind it")
	}
	if decision.Reason != "token_limit_exceeded" {
		t.Fatalf("reason = %q, want token_limit_exceeded", decision.Reason)
	}
	// The scope that could not be read must still be reported, or a partial check reads as a
	// complete one.
	if len(decision.Unevaluated) != 1 || decision.Unevaluated[0] != "global" {
		t.Fatalf("unevaluated = %v, want [global]", decision.Unevaluated)
	}
	if len(errs) != 1 || !errors.Is(errs[0], loadErr) {
		t.Fatalf("the underlying error must be reported, got %v", errs)
	}
}

// A usage-aggregate failure on one quota must not discard the other quotas in the same scope
// or the scopes after it.
func TestQuotaUsageFailureDoesNotDiscardTheRest(t *testing.T) {
	now := time.Now()
	decision, errs := evaluateQuotaScopes(now, []quotaScopeRef{{"global", "*"}, {"ip", "10.0.0.1"}},
		func(s quotaScopeRef) ([]store.QuotaRecord, error) {
			if s.scope == "global" {
				return []store.QuotaRecord{{ID: "qg", Scope: "global", ScopeValue: "*", Period: "daily", KRWLimit: 1000}}, nil
			}
			return []store.QuotaRecord{{ID: "qi", Scope: "ip", ScopeValue: "10.0.0.1", Period: "daily", KRWLimit: 10}}, nil
		},
		func(q store.QuotaRecord, start time.Time) (float64, int64, error) {
			if q.ID == "qg" {
				return 0, 0, errors.New("aggregate timed out")
			}
			return 50, 0, nil // over the ip quota's 10 KRW limit
		})

	if decision.Allowed {
		t.Fatal("an ip quota that was readable and breached did not block because an earlier " +
			"quota's usage query failed")
	}
	if decision.Reason != "krw_limit_exceeded" {
		t.Fatalf("reason = %q", decision.Reason)
	}
	if len(decision.Unevaluated) != 1 || decision.Unevaluated[0] != "global" {
		t.Fatalf("unevaluated = %v, want [global]", decision.Unevaluated)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want the one aggregate failure", errs)
	}
}

// When every scope is readable and nothing is over, nothing is reported as unevaluated — the
// marker has to mean something.
func TestFullyEvaluatedQuotaReportsNoGap(t *testing.T) {
	decision, errs := evaluateQuotaScopes(time.Now(), []quotaScopeRef{{"global", "*"}, {"api_key", "ak_1"}},
		func(s quotaScopeRef) ([]store.QuotaRecord, error) {
			return []store.QuotaRecord{{ID: "q", Scope: s.scope, ScopeValue: s.value, Period: "daily", TokenLimit: 1000}}, nil
		},
		func(q store.QuotaRecord, start time.Time) (float64, int64, error) { return 0, 1, nil })

	if !decision.Allowed || len(decision.Unevaluated) != 0 || len(errs) != 0 {
		t.Fatalf("a clean evaluation reported a gap: allowed=%v unevaluated=%v errs=%v",
			decision.Allowed, decision.Unevaluated, errs)
	}
}

// A scope with no value (no team, no client ip) is skipped, not counted as unevaluated:
// there is nothing there to check.
func TestEmptyScopeIsNotAGap(t *testing.T) {
	decision, _ := evaluateQuotaScopes(time.Now(), []quotaScopeRef{{"team", ""}},
		func(s quotaScopeRef) ([]store.QuotaRecord, error) {
			t.Fatal("an empty scope value must not be looked up")
			return nil, nil
		},
		func(q store.QuotaRecord, start time.Time) (float64, int64, error) { return 0, 0, nil })
	if len(decision.Unevaluated) != 0 {
		t.Fatalf("an absent scope was reported as unevaluated: %v", decision.Unevaluated)
	}
}

// End to end: when the quota tables cannot be read at all, the request still goes through —
// a slow aggregate must not become a gateway outage — but the response says so, so an
// unenforced request is not mistaken for an enforced one.
func TestUnreadableQuotasMarkTheResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":2}}`))
	}))
	defer upstream.Close()

	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	db, err := store.Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "q.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig(upstream.URL, "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	// A healthy gateway must not claim a gap.
	if got := chatQuotaHeader(t, proxy); got != "" {
		t.Fatalf("X-Quota = %q with readable quotas; the marker has to mean something", got)
	}

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE quotas`); err != nil {
		t.Fatal(err)
	}

	if got := chatQuotaHeader(t, proxy); got != "partial" {
		t.Fatalf("X-Quota = %q after the quota tables became unreadable; a request nobody "+
			"measured must not look measured", got)
	}
}

func chatQuotaHeader(t *testing.T, proxy *httptest.Server) string {
	t.Helper()
	body := []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer proxy-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header.Get("X-Quota")
}
