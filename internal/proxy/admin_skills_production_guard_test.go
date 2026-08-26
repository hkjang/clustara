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

func skillUpsertServer(t *testing.T) *httptest.Server {
	t.Helper()
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
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)
	return ts
}

func upsertSkill(t *testing.T, ts *httptest.Server, body map[string]any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/admin/skills", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// productionPolicyChecks documents that a skill "can never be published without
// explicit model/tool/team scoping and a daily cap". The promotion gate enforced
// that, but the upsert endpoint accepted status=production directly. Enforcement
// reads an unset guardrail as unrestricted, so such a skill ran with any model,
// any tool, any team and no cap.
func TestSkillUpsertCannotPublishWithoutGuardrails(t *testing.T) {
	ts := skillUpsertServer(t)

	status, body := upsertSkill(t, ts, map[string]any{
		"name":   "unguarded",
		"status": "production",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("unguarded production upsert returned %d: %s", status, body)
	}
	for _, want := range []string{"허용 모델", "허용 도구", "허용 팀", "일일 한도", "지침"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rejection should name the missing guardrail %q: %s", want, body)
		}
	}
}

// A partially-scoped skill is still rejected, and the response names only what
// is actually missing.
func TestSkillUpsertRejectsPartialGuardrails(t *testing.T) {
	ts := skillUpsertServer(t)

	status, body := upsertSkill(t, ts, map[string]any{
		"name":           "partial",
		"status":         "production",
		"instructions":   "do the thing",
		"allowed_models": "gpt-4.1",
		"allowed_tools":  "search",
		"allowed_teams":  "platform",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("partially-scoped production upsert returned %d: %s", status, body)
	}
	if !strings.Contains(body, "일일 한도") {
		t.Fatalf("rejection should name the missing daily cap: %s", body)
	}
	if strings.Contains(body, "허용 모델") {
		t.Fatalf("rejection should not name guardrails that are set: %s", body)
	}
}

// A fully-scoped production skill still saves, and non-production statuses are
// untouched — draft and staging are where a skill is built up.
func TestSkillUpsertAllowsScopedProductionAndDrafts(t *testing.T) {
	ts := skillUpsertServer(t)

	status, body := upsertSkill(t, ts, map[string]any{
		"name":           "scoped",
		"status":         "production",
		"instructions":   "do the thing",
		"allowed_models": "gpt-4.1",
		"allowed_tools":  "search",
		"allowed_teams":  "platform",
		"daily_limit":    100,
	})
	if status != http.StatusCreated {
		t.Fatalf("fully scoped production upsert returned %d: %s", status, body)
	}

	if status, body := upsertSkill(t, ts, map[string]any{"name": "wip", "status": "draft"}); status != http.StatusCreated {
		t.Fatalf("draft upsert returned %d: %s", status, body)
	}
	if status, body := upsertSkill(t, ts, map[string]any{"name": "wip2", "status": "staging"}); status != http.StatusCreated {
		t.Fatalf("staging upsert returned %d: %s", status, body)
	}
	if status, body := upsertSkill(t, ts, map[string]any{"name": "wip3"}); status != http.StatusCreated {
		t.Fatalf("status-less upsert returned %d: %s", status, body)
	}
}
