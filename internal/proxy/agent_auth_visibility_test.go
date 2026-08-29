package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

const testAgentAdminToken = "admin-token-for-agent-auth-tests"

// newAgentAuthServer builds a server whose admin gate is actually closed. The shared test
// config sets no admin token, and with none configured authorizeAdmin allows everything —
// which the agent ingest handler accepts as a fallback, so an invalid agent token would be
// waved through and this whole surface would be untestable.
func newAgentAuthServer(t *testing.T) (*store.SQLStore, *httptest.Server, *Server) {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "agentauth.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.Auth.AdminToken = testAgentAdminToken
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	t.Cleanup(srv.Close)
	return db, srv, server
}

func adminGetJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testAgentAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d body=%s", url, resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v body=%s", url, err, raw)
	}
	return out
}

func adminPost(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testAgentAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func postAgentBatch(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/ingest/k8s/agent/events", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// A rejected agent retries forever and the only symptom is that its cluster's data stops
// moving. The freshness score reports that as stale (v0.9.241) without ever naming a cause,
// and stale from a rejected token looks exactly like stale from a crashed agent, a network
// partition, or a cluster that genuinely has not changed. Three completely different repairs.
//
// After v0.9.244 gave operators a revoke button, this is also how you find out the revocation
// took effect.
func TestRejectedAgentLeavesAStatedCause(t *testing.T) {
	db, srv, server := newAgentAuthServer(t)
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", Status: "registered"}); err != nil {
		t.Fatal(err)
	}
	good := server.issueAgentToken(ctx, "c1", time.Now().Add(time.Hour))
	expired := server.issueAgentToken(ctx, "c1", time.Now().Add(-time.Second))

	resp := postAgentBatch(t, srv.URL, expired, `{"cluster_id":"c1","agent_id":"a1"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired token accepted: %d", resp.StatusCode)
	}

	rejections := agentRejections(t, srv.URL+"/admin/k8s/agent/status?cluster_id=c1")
	if len(rejections) != 1 {
		t.Fatalf("a rejected agent left no trace; the operator sees only a stale feed: %v", rejections)
	}
	if detail, _ := rejections[0]["last_error"].(string); !strings.Contains(detail, "만료") {
		t.Fatalf("the recorded cause must say the token expired, got %q", detail)
	}

	// Once the agent authenticates again the rejection must clear, or the warning becomes
	// permanent noise that outlives the problem.
	resp = postAgentBatch(t, srv.URL, good, `{"cluster_id":"c1","agent_id":"a1"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token rejected: %d", resp.StatusCode)
	}
	if got := agentRejections(t, srv.URL+"/admin/k8s/agent/status?cluster_id=c1"); len(got) != 0 {
		t.Fatalf("the rejection survived a successful authentication: %v", got)
	}
}

// A revoked token must say it was revoked, not merely that it failed. That is the difference
// between "regenerate the manifest" and "go debug the network".
func TestRevokedAgentTokenSaysItWasRevoked(t *testing.T) {
	db, srv, server := newAgentAuthServer(t)
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", Status: "registered"}); err != nil {
		t.Fatal(err)
	}
	token := server.issueAgentToken(ctx, "c1", time.Now().Add(time.Hour))

	adminPost(t, srv.URL+"/admin/k8s/agent/revoke-tokens?cluster_id=c1").Body.Close()

	var resp *http.Response

	resp = postAgentBatch(t, srv.URL, token, `{"cluster_id":"c1","agent_id":"a1"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token accepted: %d", resp.StatusCode)
	}
	rejections := agentRejections(t, srv.URL+"/admin/k8s/agent/status?cluster_id=c1")
	if len(rejections) != 1 {
		t.Fatalf("revocation left no visible trace: %v", rejections)
	}
	if detail, _ := rejections[0]["last_error"].(string); !strings.Contains(detail, "폐기") {
		t.Fatalf("a revoked token must be reported as revoked, got %q", detail)
	}
}

// The rejection is recorded before the caller is authenticated, so it must never be a way to
// create rows. Only clusters an admin actually registered can be written to.
func TestRejectedAgentForUnknownClusterWritesNothing(t *testing.T) {
	db, srv, _ := newAgentAuthServer(t)
	for _, id := range []string{"ghost-1", "ghost-2", "ghost-3"} {
		resp := postAgentBatch(t, srv.URL, "clustara_agent_v1.aaaa.bbbb", `{"cluster_id":"`+id+`","agent_id":"a"}`)
		resp.Body.Close()
	}
	rows, err := db.ListK8sCollectorStatus(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range rows {
		if strings.HasPrefix(st.ClusterID, "ghost-") {
			t.Fatalf("an unauthenticated request created a collector row for an unregistered "+
				"cluster: %+v", st)
		}
	}
}

func agentRejections(t *testing.T, url string) []map[string]any {
	t.Helper()
	body := adminGetJSON(t, url)
	raw, _ := body["auth_rejections"].([]any)
	out := []map[string]any{}
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	if _, present := body["auth_rejections"]; !present {
		b, _ := json.Marshal(body)
		t.Fatalf("agent status carries no auth_rejections field: %s", b)
	}
	return out
}
