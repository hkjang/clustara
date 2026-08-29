package proxy

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// The cost guard is an operator control, and X-Cost-Approve is the caller's own override of
// it. SAFETY_GUIDE says the override is recorded — "해당 우회 이력은 별도 감사 로그로
// 집계됨" — and nothing recorded it.
//
// Measured: an over-threshold request carrying the header came back 200 with an empty
// X-Cost-Guard header, zero auth events, and a request row with no error and no marker. It
// was indistinguishable from a request that never approached the threshold.
func TestCostGuardBypassIsRecorded(t *testing.T) {
	db, proxy, _ := costGuardServer(t)

	resp := postCostApproved(t, proxy)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the approved request must still pass, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Cost-Guard"); got != "approved" {
		t.Fatalf("X-Cost-Guard = %q; the response must say the guard was overridden, not stay "+
			"silent like a request that never hit it", got)
	}

	events, err := db.ListAuditEvents(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var found *store.AuthEvent
	for i := range events {
		if events[i].EventType == "cost_guard_bypassed" {
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatalf("a cost guard override left no audit event; the documented bypass history does "+
			"not exist: %+v", events)
	}
	if !strings.Contains(found.Detail, "premium") {
		t.Fatalf("the record must say what was overridden, got %q", found.Detail)
	}
}

// An override nobody can review is not an override: if the record cannot be written, the
// override is not honoured.
func TestCostGuardBypassFailsClosedWhenItCannotBeRecorded(t *testing.T) {
	_, proxy, dbPath := costGuardServer(t)
	failAuditEventInsert(t, dbPath)

	resp := postCostApproved(t, proxy)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the override was honoured even though it could not be recorded; a caller who " +
			"can make audit writes fail would get an unlogged bypass")
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 so the caller can retry", resp.StatusCode)
	}
}

// A request under the threshold is untouched — no header, no event. The marker has to mean
// something.
func TestUnderThresholdRequestIsNotMarked(t *testing.T) {
	db, proxy, _ := costGuardServer(t)
	if err := db.SetFlag(context.Background(), store.RuntimeFlag{Key: "cost_guard_threshold_krw", Value: "1000000"}); err != nil {
		t.Fatal(err)
	}

	resp := postCostApproved(t, proxy)
	if got := resp.Header.Get("X-Cost-Guard"); got != "" {
		t.Fatalf("X-Cost-Guard = %q on a request that never exceeded the threshold", got)
	}
	events, _ := db.ListAuditEvents(context.Background(), 50)
	for _, e := range events {
		if e.EventType == "cost_guard_bypassed" {
			t.Fatal("a request under the threshold was recorded as an override")
		}
	}
}

func costGuardServer(t *testing.T) (*store.SQLStore, *httptest.Server, string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"total_tokens":7}}`))
	}))
	t.Cleanup(upstream.Close)

	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	db, err := store.Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "cg.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	cfg := testConfig(upstream.URL, "secret")
	cfg.Pricing = pricingFixture()
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)

	if err := db.SetFlag(context.Background(), store.RuntimeFlag{Key: "cost_guard_enabled", Value: "true"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetFlag(context.Background(), store.RuntimeFlag{Key: "cost_guard_threshold_krw", Value: "1"}); err != nil {
		t.Fatal(err)
	}
	return db, proxy, dbPath
}

func postCostApproved(t *testing.T, proxy *httptest.Server) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", jsonReader(chatBody("premium", false)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cost-Approve", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	time.Sleep(200 * time.Millisecond)
	return resp
}

// failAuditEventInsert makes auth_events INSERTs fail while the rest of the store keeps
// working, so the override reaches the write through the real code path.
func failAuditEventInsert(t *testing.T, dbPath string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open store file: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER fail_auth_event BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}
