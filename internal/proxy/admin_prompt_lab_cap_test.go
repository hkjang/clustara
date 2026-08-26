package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func promptLabRunFixture(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	ctx := context.Background()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	tc := store.PromptTestCase{
		ID: "tc-1", Name: "cap", MessagesJSON: `[{"role":"user","content":"hi"}]`,
		ModelsJSON: `["test-model"]`,
	}
	if err := db.CreatePromptTestCase(ctx, tc); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)
	return ts, tc.ID
}

func runPromptLabCase(t *testing.T, ts *httptest.Server, tcID string, models []string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"models": models})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/admin/prompt-lab/test-cases/"+tcID+"/run", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("run returned %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

// The fan-out is capped, which is correct — but silently returning fewer results
// than asked for is indistinguishable from models that failed, and the extras
// are dropped by list order rather than by any judgement. The response has to
// say what it dropped.
func TestPromptLabRunReportsDroppedModels(t *testing.T) {
	ts, tcID := promptLabRunFixture(t)

	models := []string{}
	for _, m := range []string{"m1", "m2", "m3", "m4", "m5", "m6", "m7"} {
		models = append(models, m)
	}
	out := runPromptLabCase(t, ts, tcID, models)

	if got := out["model_count"]; got != float64(maxMultiRunModels) {
		t.Fatalf("model_count = %v, want the cap %d", got, maxMultiRunModels)
	}
	if got := out["model_limit"]; got != float64(maxMultiRunModels) {
		t.Fatalf("model_limit = %v, want %d", got, maxMultiRunModels)
	}
	dropped, ok := out["dropped_models"].([]any)
	if !ok {
		t.Fatalf("dropped_models missing from the response: %v", out)
	}
	if len(dropped) != len(models)-maxMultiRunModels {
		t.Fatalf("dropped_models = %v, want the %d models past the cap", dropped, len(models)-maxMultiRunModels)
	}
	if dropped[0] != "m6" || dropped[1] != "m7" {
		t.Fatalf("dropped_models = %v, want the trailing models named", dropped)
	}
}

// Within the cap nothing is dropped, and the field is present and empty rather
// than absent — a caller should not have to distinguish "no key" from "none".
func TestPromptLabRunDropsNothingWithinTheCap(t *testing.T) {
	ts, tcID := promptLabRunFixture(t)
	out := runPromptLabCase(t, ts, tcID, []string{"m1", "m2"})

	if got := out["model_count"]; got != float64(2) {
		t.Fatalf("model_count = %v, want 2", got)
	}
	dropped, ok := out["dropped_models"].([]any)
	if !ok {
		t.Fatalf("dropped_models missing from the response: %v", out)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped_models = %v, want empty", dropped)
	}
}
