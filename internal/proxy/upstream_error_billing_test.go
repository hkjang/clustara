package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"clustara/internal/store"
)

// The usage estimate keyed only on "there was a prompt", which is true whatever the upstream
// answered. So a 429 the provider never admitted, a 400 it refused, and a 5xx it failed all
// recorded a real estimated cost — and that column is summed with no status filter by the
// cost-centre invoice, the anomaly detector, the AI credit score and the analytics rollups.
// Teams were invoiced for provider outages, and the worse the outage the bigger the bill,
// because clients retry.
func TestUpstreamRejectionsAreNotBilled(t *testing.T) {
	for _, status := range []int{400, 429, 500, 503} {
		upstream := errorUpstream(t, status)
		db, proxy := newTruncationProxy(t, upstream.URL)
		drainChatStream(t, proxy)

		waitFor(t, 4*time.Second, func() bool {
			rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
			return err == nil && len(rows) == 1
		})
		rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		if len(rows) != 1 {
			t.Fatalf("status %d: expected one logged request, got %d", status, len(rows))
		}
		if rows[0].EstimatedCost != 0 || rows[0].PromptTokens != 0 || rows[0].TotalTokens != 0 {
			t.Errorf("an upstream %d was billed: prompt=%d total=%d cost=%v — no provider charges "+
				"for a request it rejected, and this figure reaches invoices",
				status, rows[0].PromptTokens, rows[0].TotalTokens, rows[0].EstimatedCost)
		}
		// Explicitly not billed, which is a different fact from "we could not estimate".
		if rows[0].TokenSource != "not_billed" {
			t.Errorf("status %d: token source = %q, want not_billed so the zero is a statement "+
				"rather than a silence", status, rows[0].TokenSource)
		}
		upstream.Close()
	}
}

// A request the provider actually served must still be billed, including one whose stream was
// cut short: the tokens really were produced. The fix must not turn into "stop billing".
func TestServedRequestsAreStillBilled(t *testing.T) {
	upstream := sseUpstream(t, "data: {\"choices\":[{\"delta\":{\"content\":\"a whole answer here\"}}]}\n\n"+
		"data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	defer upstream.Close()

	db, proxy := newTruncationProxy(t, upstream.URL)
	drainChatStream(t, proxy)

	waitFor(t, 4*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
	if len(rows) != 1 || rows[0].TotalTokens == 0 {
		t.Fatalf("a served completion recorded no tokens: %+v", rows)
	}
	if rows[0].TokenSource == "not_billed" {
		t.Fatalf("a 2xx completion was marked not_billed")
	}
}

// A stream the caller abandoned was still produced up to that point, so it stays billable —
// v0.9.246 changed who is blamed for it, not who pays for it.
func TestCallerCancelledStreamIsStillBilled(t *testing.T) {
	release := make(chan struct{})
	upstream := blockingSSEUpstream(t, "data: {\"choices\":[{\"delta\":{\"content\":\"partial answer here\"}}]}\n\n", release)
	defer upstream.Close()
	defer close(release)

	db, proxy := newTruncationProxy(t, upstream.URL)
	cancelChatStreamAfterFirstChunk(t, proxy)

	waitFor(t, 4*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
	if len(rows) != 1 || rows[0].TotalTokens == 0 {
		t.Fatalf("a partially delivered completion recorded no tokens: %+v", rows)
	}
}

func errorUpstream(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"message":"rejected"}}`))
	}))
}

func sseUpstream(t *testing.T, payload string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(payload))
		w.(http.Flusher).Flush()
	}))
}

func blockingSSEUpstream(t *testing.T, payload string, release <-chan struct{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(payload))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
}
