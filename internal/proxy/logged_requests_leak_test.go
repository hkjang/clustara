package proxy

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

func countLoggedRequestMarkers(s *Server) int {
	n := 0
	s.loggedRequests.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}

// loggedRequests is a dedupe marker that only handleOpenAI's deferred fallback
// consumes, and it matches on the request ID that handler is tracking. An MCP
// tool call mints its own ID, so a marker stored for it can never be read — it
// just accumulates for the lifetime of the process.
func TestMCPCallLoggingDoesNotAccumulateDedupeMarkers(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 256, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	req := httptest.NewRequest("POST", "/mcp", nil)
	for i := 0; i < 50; i++ {
		server.logMCPCall(req, "key-1", "files", "read", json.RawMessage(`{}`), false, 200, 5)
	}

	if leaked := countLoggedRequestMarkers(server); leaked != 0 {
		t.Fatalf("MCP tool calls left %d dedupe markers behind; they are never read or deleted", leaked)
	}
}

// The /v1 path still needs the marker: it is what stops handleOpenAI's deferred
// fallback from logging a request the pipeline already recorded.
func TestPipelineEnqueueStillMarksRequestsAsLogged(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 256, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	server.enqueue(store.LogRecord{Request: store.RequestLog{ID: "req-1"}})
	if _, marked := server.loggedRequests.Load("req-1"); !marked {
		t.Fatal("enqueue must mark a tracked /v1 request as logged")
	}
	if _, loaded := server.loggedRequests.LoadAndDelete("req-1"); !loaded {
		t.Fatal("the marker must be consumable exactly once")
	}
	if got := countLoggedRequestMarkers(server); got != 0 {
		t.Fatalf("markers remaining after consumption = %d, want 0", got)
	}
}
