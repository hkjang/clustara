package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// The semantic cache embeds the prompt on every eligible chat request — hit or miss — by
// calling the upstream /v1/embeddings directly with s.client.Do, outside the pipeline. That
// call is paid for, and it produced no request row, no usage and no cost: the identical call
// made by a client against /v1/embeddings produces all three.
//
// So the cache's savings were reported while its running cost was not. A semantic cache can
// cost more than it saves, and no report could show it.
func TestSemanticCacheEmbeddingSpendIsRecorded(t *testing.T) {
	embeds := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/embeddings" {
			embeds++
			_, _ = w.Write([]byte(`{"data":[{"embedding":[1,0,0]}],"usage":{"prompt_tokens":11,"total_tokens":11}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello there"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	defer upstream.Close()

	db, proxy := newSemanticCacheProxy(t, upstream.URL)
	postSemanticChat(t, proxy, "what is the capital of France")

	waitFor(t, 4*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 20})
		return err == nil && len(rows) >= 2
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 20})
	if embeds != 1 {
		t.Fatalf("expected exactly one embedding call, got %d", embeds)
	}
	var embedRow *store.RecentRequest
	for i := range rows {
		if rows[i].Endpoint == "/v1/embeddings" {
			embedRow = &rows[i]
		}
	}
	if embedRow == nil {
		t.Fatalf("the semantic cache spent an embedding call and recorded nothing; %d rows: %+v",
			len(rows), rows)
	}
	if embedRow.Model != "embed-model" {
		t.Fatalf("embedding spend recorded against model %q", embedRow.Model)
	}
	if embedRow.TotalTokens != 11 {
		t.Fatalf("embedding tokens = %d, want the 11 the upstream reported", embedRow.TotalTokens)
	}
	if embedRow.EstimatedCost <= 0 {
		t.Fatalf("a priced embedding model recorded zero cost: %+v", embedRow)
	}
	// The spend must land on whoever caused it, not on "(unset)", or the cost-centre
	// invoice moves the cache's cost onto nobody.
	inv, err := db.CostCenterInvoiceData(context.Background(), "cc-alpha", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	billedEmbed := false
	for _, li := range inv.LineItems {
		if li.Model == "embed-model" && li.CostKRW > 0 {
			billedEmbed = true
		}
	}
	if !billedEmbed {
		t.Fatalf("the embedding spend never reached the triggering cost centre's invoice: %+v",
			inv.LineItems)
	}
}

// A failing embedding endpoint still costs a round trip, and a semantic cache silently
// failing every lookup is exactly the thing an operator needs to see.
func TestFailedSemanticEmbedIsRecordedAndNotBilled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/embeddings" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	defer upstream.Close()

	db, proxy := newSemanticCacheProxy(t, upstream.URL)
	postSemanticChat(t, proxy, "anything at all")

	waitFor(t, 4*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 20})
		return err == nil && len(rows) >= 2
	})
	rows, _ := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 20})
	var embedRow *store.RecentRequest
	for i := range rows {
		if rows[i].Endpoint == "/v1/embeddings" {
			embedRow = &rows[i]
		}
	}
	if embedRow == nil {
		t.Fatalf("a failing embedding call left no trace; the cache fails silently: %+v", rows)
	}
	if embedRow.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("embed row status = %d, want 429", embedRow.StatusCode)
	}
	if embedRow.EstimatedCost != 0 || embedRow.TokenSource != "not_billed" {
		t.Fatalf("a rejected embedding call was billed: cost=%v source=%q",
			embedRow.EstimatedCost, embedRow.TokenSource)
	}
	// The chat request itself must still have gone upstream normally.
	served := false
	for _, row := range rows {
		if row.Endpoint == "/v1/chat/completions" && row.StatusCode == http.StatusOK {
			served = true
		}
	}
	if !served {
		t.Fatal("a failed semantic lookup must not stop the request from being served")
	}
}

func newSemanticCacheProxy(t *testing.T, upstreamURL string) (*store.SQLStore, *httptest.Server) {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "semantic.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	cfg := testConfig(upstreamURL, "upstream-secret")
	cfg.Cache = config.CacheConfig{
		ChatEnabled: true, ChatSemanticEnabled: true, ChatSemanticModel: "embed-model",
		ChatSemanticThreshold: 0.9, ChatSemanticMaxCandidates: 50,
		// These tests are about what the cache SPENDS, not who it is shared with. The
		// harness has no authenticated caller, and the default "team" scope excludes an
		// unidentified one, so ask for the shared pool explicitly.
		ChatSemanticScope: "global",
	}
	cfg.Pricing["embed-model"] = config.ModelPrice{InputKRWPer1M: 1000}
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)
	return db, proxy
}

func postSemanticChat(t *testing.T, proxy *httptest.Server, prompt string) {
	t.Helper()
	body := []byte(`{"model":"test-model","temperature":0,"messages":[{"role":"user","content":"` + prompt + `"}]}`)
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer proxy-secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vibe-Cost-Center", "cc-alpha")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
