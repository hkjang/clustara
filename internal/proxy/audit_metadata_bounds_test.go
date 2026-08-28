package proxy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"

	_ "modernc.org/sqlite"
)

// Every request writes a request_logs row carrying ten client-controlled values:
// the repo/branch/project/service/cost-center hints, the replay id, the
// user-agent, the forwarded-for chain, and the prompt and session identifiers —
// the last of which can come from the request body.
//
// None were bounded. Headers are capped only by MaxHeaderBytes (1 MiB) in
// aggregate, so a single request could write hundreds of kilobytes of arbitrary
// text into one row, at request rate. That is one row per request, unlike the
// external-key registration bounded in v0.9.239, which was one row per distinct
// token.
func TestAuditMetadataFromClientIsBounded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	_, db, proxy, dbPath := newLeakTestProxyAt(t, upstream.URL)

	huge := strings.Repeat("z", 40000)
	body, _ := json.Marshal(map[string]any{
		"model":      "test-model",
		"session_id": huge,
		"messages":   []map[string]string{{"role": "user", "content": "hi"}},
	})
	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", huge)
	req.Header.Set("X-Forwarded-For", huge)
	for _, h := range []string{"X-Vibe-Repo", "X-Vibe-Branch", "X-Vibe-Project", "X-Vibe-Service", "X-Vibe-Cost-Center", "X-Proxy-Replay-Of"} {
		req.Header.Set(h, huge)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	waitFor(t, 3*time.Second, func() bool {
		rows, err := db.RecentRequests(context.Background(), store.RequestFilter{Limit: 1})
		return err == nil && len(rows) == 1
	})

	// These columns are not projected by any store accessor, so read the row.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var repo, branch, project, service, costCenter, replayOf, sessionID, userAgent, forwardedFor string
	if err := raw.QueryRow(`SELECT COALESCE(repo,''), COALESCE(branch,''), COALESCE(project,''),
			COALESCE(service,''), COALESCE(cost_center,''), COALESCE(replay_of,''),
			COALESCE(session_id,''), COALESCE(user_agent,''), COALESCE(forwarded_for,'')
		FROM request_logs LIMIT 1`).Scan(&repo, &branch, &project, &service, &costCenter,
		&replayOf, &sessionID, &userAgent, &forwardedFor); err != nil {
		t.Fatal(err)
	}

	for _, f := range []struct {
		name  string
		value string
		max   int
	}{
		{"repo", repo, auditIdentifierMax},
		{"branch", branch, auditIdentifierMax},
		{"project", project, auditIdentifierMax},
		{"service", service, auditIdentifierMax},
		{"cost_center", costCenter, auditIdentifierMax},
		{"replay_of", replayOf, auditIdentifierMax},
		{"session_id", sessionID, auditSessionIDMax},
		{"user_agent", userAgent, auditUserAgentMax},
		{"forwarded_for", forwardedFor, auditForwardedMax},
	} {
		if len([]rune(f.value)) > f.max {
			t.Errorf("%s stored %d runes, above its %d bound: a client header or body field became an "+
				"oversized column, once per request", f.name, len([]rune(f.value)), f.max)
		}
	}
}

// Ordinary values must survive untouched, or the clamp would corrupt real
// telemetry rather than bound abuse.
func TestClampLabelLeavesNormalValuesAlone(t *testing.T) {
	for _, v := range []string{"main", "acme/payments", "Mozilla/5.0 (X11; Linux x86_64) Gateway/1.0", ""} {
		if got := clampLabel(v, auditUserAgentMax); got != strings.TrimSpace(v) {
			t.Fatalf("clampLabel altered %q to %q", v, got)
		}
	}
	// A non-positive bound means "no bound", used where a limit is not configured.
	long := strings.Repeat("x", 1000)
	if got := clampLabel(long, 0); got != long {
		t.Fatal("a non-positive bound must not truncate")
	}
	// Multi-byte input is cut on a rune boundary.
	multi := strings.Repeat("한", 500)
	got := clampLabel(multi, auditIdentifierMax)
	if len([]rune(got)) != auditIdentifierMax {
		t.Fatalf("clamped to %d runes, want %d", len([]rune(got)), auditIdentifierMax)
	}
}
