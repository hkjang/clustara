package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/config"
	"clustara/internal/store"
)

// The replay queue is drained oldest-first with a bounded window. A batch
// ClickHouse rejects permanently used to be retried forever and, being the
// oldest entry, kept its place at the head of every window — so once enough of
// them accumulated the backlog could never be drained at all.
func TestFactRetryAbandonsPermanentlyRejectedBatch(t *testing.T) {
	ctx := context.Background()
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	// ClickHouse rejects the payload every time, the way it would for schema drift.
	clickhouse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown column", http.StatusBadRequest)
	}))
	defer clickhouse.Close()

	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.ClickHouse = config.ClickHouseConfig{URL: clickhouse.URL, Database: "dw", RequestFactTable: "ai_request_fact"}
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	if err := db.RecordClickHouseFactRetry(ctx, "ai_request_fact", `{"request_id":"r1"}`, 1, "initial failure"); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	replay := func() map[string]any {
		t.Helper()
		resp, err := http.Post(ts.URL+"/admin/dw/clickhouse/fact-retry", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("replay returned %d: %s", resp.StatusCode, body)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// The batch starts at one attempt, so it survives the replays that take it
	// up to the cap and is abandoned on the one that reaches it.
	for i := 1; i < clickHouseFactRetryMaxAttempts-1; i++ {
		out := replay()
		if out["still_failing"].(float64) != 1 {
			t.Fatalf("replay %d: still_failing = %v, want the batch retained", i, out["still_failing"])
		}
		if out["abandoned_batches"].(float64) != 0 {
			t.Fatalf("replay %d abandoned the batch before the cap", i)
		}
		n, err := db.CountClickHouseFactRetries(ctx)
		if err != nil || n != 1 {
			t.Fatalf("replay %d: backlog = %d err=%v, want the batch kept", i, n, err)
		}
	}

	out := replay()
	if out["abandoned_batches"].(float64) != 1 {
		t.Fatalf("the batch was never abandoned: %v", out)
	}
	n, err := db.CountClickHouseFactRetries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("backlog = %d after abandoning, want it drained", n)
	}
}

// A batch that fails once and then succeeds must not be abandoned, and the
// attempt counter has to actually move so the cap can ever be reached.
func TestFactRetryAttemptCounterAdvances(t *testing.T) {
	ctx := context.Background()
	db := openTestStore(t)
	defer db.Close()

	if err := db.RecordClickHouseFactRetry(ctx, "ai_request_fact", `{"request_id":"r1"}`, 1, "initial failure"); err != nil {
		t.Fatal(err)
	}
	batches, err := db.ListClickHouseFactRetries(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 || batches[0].Attempts != 1 {
		t.Fatalf("recorded batch = %+v, want a single batch at attempt 1", batches)
	}

	attempts, err := db.MarkClickHouseFactRetryAttempt(ctx, batches[0].ID, "ClickHouse returned status 400")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	after, err := db.ListClickHouseFactRetries(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if after[0].Attempts != 2 {
		t.Fatalf("persisted attempts = %d, want 2", after[0].Attempts)
	}
	if after[0].Error != "ClickHouse returned status 400" {
		t.Fatalf("persisted error = %q, want the latest rejection", after[0].Error)
	}

	if _, err := db.MarkClickHouseFactRetryAttempt(ctx, "chfr_missing", "gone"); err == nil {
		t.Fatal("marking an attempt on a removed batch should report it is gone")
	}
}
