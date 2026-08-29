package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"clustara/internal/store"
)

// A caller that hangs up mid-stream leaves exactly the same trace as an upstream that cut
// the stream: no finish_reason, a clean 200, and a partial completion. v0.9.217 started
// recording that shape as truncated_stream, which is right for the upstream case and wrong
// for this one — and this one is a button. Every "stop generating" in every chat UI produces
// it, so the misattribution is not a corner case; it could be most of the signal.
//
// It is not only a label. ModelQualityScores computes a success rate from the error column,
// and the response.completed evaluation reads the same field: a caller's disconnect was
// dragging down the model's measured quality.
func TestClientCancelIsNotBlamedOnTheUpstream(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"partial answer here\"}}]}\n\n"))
		f.Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()
	defer close(release)

	db, proxy := newTruncationProxy(t, upstream.URL)
	cancelChatStreamAfterFirstChunk(t, proxy)

	waitFor(t, 4*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
	if len(rows) != 1 {
		t.Fatalf("expected one logged request, got %d", len(rows))
	}
	if rows[0].Error == truncatedStreamError {
		t.Fatalf("the caller hung up and the upstream was blamed for it (error=%q); this counts "+
			"against the model in ModelQualityScores and response.completed", rows[0].Error)
	}
	if !store.IsCallerAttributedError(rows[0].Error) {
		t.Fatalf("a caller-cancelled stream must be attributed to the caller, got error=%q", rows[0].Error)
	}
}

// The upstream case must keep its own label — the fix must not disarm v0.9.217.
func TestGenuineTruncationIsStillBlamedOnTheUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"half an ans\"}}]}\n\n"))
		f.Flush()
	}))
	defer upstream.Close()

	db, proxy := newTruncationProxy(t, upstream.URL)
	drainChatStream(t, proxy)

	waitFor(t, 4*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
	if len(rows) != 1 || rows[0].Error != truncatedStreamError {
		t.Fatalf("an upstream that cut the stream must still be recorded as truncated, got %q",
			rows[0].Error)
	}
}

// The quality score must not count an abandoned request on either side of the ratio.
func TestModelQualityIgnoresAbandonedRequests(t *testing.T) {
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()

	insert := func(id, errText string) {
		t.Helper()
		if err := db.InsertLogRecord(ctx, store.LogRecord{Request: store.RequestLog{
			ID: id, Model: "test-model", Provider: "test", StatusCode: 200,
			Error: errText, CreatedAt: now,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	insert("r_ok", "")
	insert("r_cancelled", store.ClientDisconnectError)

	scores, err := db.ModelQualityScores(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var got *store.ModelQualityScore
	for i := range scores {
		if scores[i].Model == "test-model" {
			got = &scores[i]
		}
	}
	if got == nil {
		t.Fatalf("no score for test-model: %+v", scores)
	}
	if got.Requests != 2 {
		t.Fatalf("volume must still count the abandoned request, got %d", got.Requests)
	}
	if got.SuccessRate != 1 {
		t.Fatalf("success rate = %v; one clean request and one the caller abandoned must read "+
			"as 100%%, not 50%% — the model did nothing wrong", got.SuccessRate)
	}
}

func cancelChatStreamAfterFirstChunk(t *testing.T, proxy *httptest.Server) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"model": "test-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxy.URL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer proxy-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, _ = resp.Body.Read(buf)
	cancel()
	resp.Body.Close()
}
