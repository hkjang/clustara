package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"clustara/internal/config"
	"clustara/internal/store"
)

func limitsBodyServer(t *testing.T, maxRequestBytes int) *Server {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.Limits = config.LimitsConfig{MaxRequestBytes: maxRequestBytes}
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return server
}

// stepLimits rejects an oversized body, but it runs after the body has been
// read. Buffering the whole thing first meant the limit rejected the request
// without ever bounding the memory it cost.
//
// The read now stops one byte past the limit, which is observable: the rejection
// reports that bounded size rather than the true body size.
func TestOversizedBodyReadIsBounded(t *testing.T) {
	const limit = 2048
	server := limitsBodyServer(t, limit)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	huge := strings.Repeat("x", 5*1024*1024)
	payload := chatPayload(huge)

	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request returned %d: %s", resp.StatusCode, body)
	}
	// The reported size is the bounded read, not the true body size.
	if !strings.Contains(string(body), strconv.Itoa(limit+1)) {
		t.Fatalf("rejection should report the bounded read size %d, got: %s", limit+1, body)
	}
	if strings.Contains(string(body), strconv.Itoa(len(payload))) {
		t.Fatalf("rejection reported the full body size, so the whole body was buffered: %s", body)
	}
	if got := resp.Header.Get("X-Request-Bytes"); got != strconv.Itoa(limit+1) {
		t.Fatalf("X-Request-Bytes = %q, want the bounded read size %d", got, limit+1)
	}
}

// chatPayload builds a chat request whose content is the given filler.
func chatPayload(content string) string {
	return `{"model":"test-model","messages":[{"role":"user","content":"` + content + `"}]}`
}

// A body within the limit still has to arrive intact — the bounded read must not
// truncate legitimate requests.
func TestBodyWithinLimitIsReadWhole(t *testing.T) {
	const limit = 64 * 1024
	server := limitsBodyServer(t, limit)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	content := strings.Repeat("y", 8*1024)
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatPayload(content)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The upstream is unreachable in this fixture, so the request must fail past
	// the limits step rather than being rejected as too large or malformed.
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatalf("a body within the limit was rejected as too large: %s", body)
	}
	if strings.Contains(string(body), "invalid_body") {
		t.Fatalf("a body within the limit was truncated: %s", body)
	}
}

// With no limit configured the read stays unbounded, exactly as before.
func TestBodyReadUnboundedWhenNoLimitConfigured(t *testing.T) {
	server := limitsBodyServer(t, 0)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	content := strings.Repeat("z", 256*1024)
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatPayload(content)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatalf("request rejected as too large with no limit configured: %s", body)
	}
}
