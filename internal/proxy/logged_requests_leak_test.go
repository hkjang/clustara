package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// loggedRequests is a dedupe marker whose only reader is handleOpenAI's own
// defer, keyed on that handler's request id. Once the defer has run, nothing can
// ever consume the entry again.
//
// The defer's else-branch knows this and deletes the marker after enqueueing.
// The first branch does not — and s.enqueue() stores it. So every request that
// reaches the defer already blocked (quota, governance, model allowlist, cost
// guard, kill switch) leaves a permanent entry, one per rejected request, for the
// lifetime of the process. Rejected requests are exactly what a misconfigured or
// hostile client produces in volume.
func TestBlockedRequestsDoNotLeakDedupeMarkers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	srv, db, proxy := newLeakTestProxy(t, upstream.URL)

	// A per-request cost cap of a fraction of a KRW. That check runs after
	// rc.meta is assigned, which is what puts the defer on its first branch --
	// the one that re-stores the marker. The model-allowlist block, by contrast,
	// fires before the record exists and takes the else-branch, which deletes.
	const rawKey = "pcg_leak_probe"
	if err := db.UpsertAPIKey(context.Background(), store.APIKeyRecord{
		ID: "ak_leak", Name: "leak", KeyHash: hashProxyKey(rawKey), Status: "active",
		Role: "developer", Scopes: []string{"chat:completion"},
		BudgetLimitKRW: 0.000001,
	}); err != nil {
		t.Fatal(err)
	}

	const blocked = 5
	for i := 0; i < blocked; i++ {
		body, _ := json.Marshal(map[string]any{
			"model":    "test-model",
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rawKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("request %d was not blocked (status %d); the test needs a request that is "+
				"rejected after the audit record is built", i, resp.StatusCode)
		}
	}

	if n := countLoggedRequests(srv); n != 0 {
		t.Fatalf("%d dedupe markers left behind by %d blocked requests. Nothing can consume them: the "+
			"only reader is the defer that just finished, so the map grows without bound for every "+
			"rejected request the gateway sees", n, blocked)
	}
}

func countLoggedRequests(s *Server) int {
	n := 0
	s.loggedRequests.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func newLeakTestProxy(t *testing.T, upstreamURL string) (*Server, *store.SQLStore, *httptest.Server) {
	srv, db, proxy, _ := newLeakTestProxyAt(t, upstreamURL)
	return srv, db, proxy
}

// newLeakTestProxyAt also returns the store's file path, so a test can read
// columns no store accessor projects.
func newLeakTestProxyAt(t *testing.T, upstreamURL string) (*Server, *store.SQLStore, *httptest.Server, string) {
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
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := config.Config{
		ListenAddr: ":0",
		Upstream:   config.UpstreamConfig{Provider: "test", BaseURL: upstreamURL, APIKey: "up", Timeout: 5 * time.Second},
		Database:   config.DatabaseConfig{Driver: "sqlite"},
		Logging:    config.LoggingConfig{ResponseMaxBytes: 4096, QueueSize: 32},
		// Pricing must be present or the cost estimate is not "priced" and the
		// per-request cap never engages.
		Pricing: map[string]config.ModelPrice{"test-model": {InputKRWPer1M: 1000, OutputKRWPer1M: 2000}},
	}
	server, serr := NewServer(cfg, db, logger, nil)
	if serr != nil {
		t.Fatal(serr)
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)
	return server, db, proxy, dbPath
}

// The marker still has to do its real job: a request that completes normally is
// logged once by the pipeline, and the defer must not log it a second time.
func TestSuccessfulRequestIsLoggedExactlyOnce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`))
	}))
	defer upstream.Close()

	srv, db, proxy := newLeakTestProxy(t, upstream.URL)
	const rawKey = "pcg_once_probe"
	if err := db.UpsertAPIKey(context.Background(), store.APIKeyRecord{
		ID: "ak_once", Name: "once", KeyHash: hashProxyKey(rawKey), Status: "active",
		Role: "developer", Scopes: []string{"chat:completion"},
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{
		"model":    "test-model",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rawKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request failed: %d", resp.StatusCode)
	}

	waitFor(t, 3*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 10})
		return err == nil && len(rows) >= 1
	})
	rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("a successful request was logged %d times; the dedupe marker must still suppress the "+
			"defer's fallback record", len(rows))
	}
	if n := countLoggedRequests(srv); n != 0 {
		t.Fatalf("%d markers left after a successful request", n)
	}
}
