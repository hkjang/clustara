package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// A streamed chat completion always ends with a chunk carrying finish_reason —
// stop, length, tool_calls or content_filter — before [DONE]. When it does not,
// the answer the caller received is cut off: the upstream, or something between
// it and the gateway, closed the stream mid-completion.
//
// That close is clean at the socket level, so there is no copy error to record.
// The status was already 200 before the first byte, the partial content still
// produces an estimated token count, and the row lands in the log looking like
// any other successful call. The caller is billed for an answer that stopped
// halfway, and nobody reviewing the logs can tell it apart from a complete one.
//
// The signal exists — an empty finish_reason on a stream that produced content —
// and was simply discarded.
func TestTruncatedStreamIsRecordedAsAFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"half an ans\"}}]}\n\n"))
		flusher.Flush()
		// Closes here: no finish_reason chunk, no [DONE].
	}))
	defer upstream.Close()

	db, proxy := newTruncationProxy(t, upstream.URL)
	drainChatStream(t, proxy)

	waitFor(t, 3*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})
	rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected one logged request, got %d (%v)", len(rows), err)
	}
	if rows[0].Error == "" {
		t.Fatalf("a stream that ended without finish_reason was logged as a clean success "+
			"(status=%d, error=%q): the caller got a truncated answer, was billed for it, and the log "+
			"cannot distinguish it from a complete response", rows[0].StatusCode, rows[0].Error)
	}
}

// A normal stream must stay clean — the check must key on the missing
// finish_reason, not on streaming itself.
func TestCompleteStreamIsNotFlagged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"a whole answer\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"choices\":[{\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	db, proxy := newTruncationProxy(t, upstream.URL)
	drainChatStream(t, proxy)

	waitFor(t, 3*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
	if len(rows) == 1 && rows[0].Error != "" {
		t.Fatalf("a complete stream was flagged: error=%q", rows[0].Error)
	}
}

// An upstream that returns a non-2xx has no completion and no finish_reason;
// flagging truncation there would relabel an ordinary upstream error.
func TestUpstreamErrorIsNotRelabelledAsTruncation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
	}))
	defer upstream.Close()

	db, proxy := newTruncationProxy(t, upstream.URL)
	drainChatStream(t, proxy)

	waitFor(t, 3*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
	if len(rows) == 1 && rows[0].Error == truncatedStreamError {
		t.Fatalf("a %d from the upstream was recorded as a truncated stream", rows[0].StatusCode)
	}
}

func newTruncationProxy(t *testing.T, upstreamURL string) (*store.SQLStore, *httptest.Server) {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := config.Config{
		ListenAddr: ":0",
		Upstream: config.UpstreamConfig{
			Provider: "test", BaseURL: upstreamURL, APIKey: "upstream-secret", Timeout: 5 * time.Second,
		},
		Database: config.DatabaseConfig{Driver: "sqlite"},
		Logging:  config.LoggingConfig{ResponseText: true, ResponseMaxBytes: 4096, QueueSize: 32},
		Pricing:  map[string]config.ModelPrice{"test-model": {InputKRWPer1M: 1, OutputKRWPer1M: 2}},
	}
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)
	return db, proxy
}

func drainChatStream(t *testing.T, proxy *httptest.Server) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"model": "test-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
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
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
