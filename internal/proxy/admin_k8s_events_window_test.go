package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func newK8sEventsServer(t *testing.T) (*store.SQLStore, *httptest.Server) {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.Auth.AdminToken = "test-admin"
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)
	return db, proxy
}

func k8sEventsRequest(t *testing.T, proxy *httptest.Server, method, query, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, proxy.URL+"/admin/k8s/events"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestK8sEventsReportsEffectiveWindow(t *testing.T) {
	db, proxy := newK8sEventsServer(t)
	insertEvents(t, db, "c1", 501)
	insertEvents(t, db, "exact", 500)
	// Newer events in another cluster must not spend c1's window budget.
	for i := 0; i < 3; i++ {
		seen := time.Date(2026, 10, 1, 0, i, 0, 0, time.UTC)
		if err := db.InsertK8sEvent(context.Background(), warningEvent("c2", fmt.Sprintf("pod-%d", i), seen)); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name       string
		cluster    string
		query      string
		storeLimit int
		limit      int
		count      int
		full       bool
	}{
		{"over_cap", "c1", "&limit=1000", 1000, 500, 500, true},
		{"just_over_cap", "c1", "&limit=501", 501, 500, 500, true},
		{"at_cap_with_more_rows", "c1", "&limit=500", 500, 500, 500, true},
		{"exactly_cap_rows", "exact", "&limit=500", 500, 500, 500, true},
		{"below_cap", "c1", "&limit=499", 499, 499, 499, true},
		{"smallest_window", "c1", "&limit=1", 1, 1, 1, true},
		{"trimmed_number", "c1", "&limit=" + url.QueryEscape(" 2 "), 2, 2, 2, true},
		{"exactly_small_window", "c2", "&limit=3", 3, 3, 3, true},
		{"under_window", "c2", "&limit=500", 500, 500, 3, false},
		{"empty", "missing", "&limit=500", 500, 500, 0, false},
		{"omitted", "c1", "", 0, 100, 100, true},
		{"empty_limit", "c1", "&limit=", 0, 100, 100, true},
		{"whitespace", "c1", "&limit=" + url.QueryEscape(" \t "), 0, 100, 100, true},
		{"text", "c1", "&limit=abc", 0, 100, 100, true},
		{"zero", "c1", "&limit=0", 0, 100, 100, true},
		{"negative", "c1", "&limit=-1", -1, 100, 100, true},
		{"default_empty", "missing", "", 0, 100, 0, false},
		{"all_clusters", "", "&limit=1000", 1000, 500, 500, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := k8sEventsRequest(t, proxy, http.MethodGet, "?cluster_id="+tc.cluster+tc.query, "test-admin")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d, want 200", resp.StatusCode)
			}
			var out struct {
				Events       []store.K8sEvent `json:"events"`
				Limit        *int             `json:"limit"`
				WindowFull   *bool            `json:"window_full"`
				WindowNotice *string          `json:"window_notice"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if out.Events == nil || len(out.Events) != tc.count {
				t.Fatalf("events must be an array with %d rows, got %d (nil=%v)", tc.count, len(out.Events), out.Events == nil)
			}
			// Compare the HTTP result to the real store using the original request's
			// numeric limit, so the API's normalization cannot hide a store mismatch.
			rows, err := db.ListK8sEvents(context.Background(), tc.cluster, tc.storeLimit)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out.Events, rows) {
				t.Fatal("HTTP events differ from the real store's query window")
			}
			for i, event := range out.Events {
				if tc.cluster != "" && event.ClusterID != tc.cluster {
					t.Fatalf("event %s belongs to cluster %s, want %s", event.ID, event.ClusterID, tc.cluster)
				}
				if i > 0 && out.Events[i-1].LastSeen < event.LastSeen {
					t.Fatal("events are not ordered by last_seen DESC")
				}
			}
			if tc.count > 0 {
				cluster, newest := tc.cluster, 500
				switch cluster {
				case "exact":
					newest = 499
				case "c2", "":
					cluster, newest = "c2", 2
				}
				if want := fmt.Sprintf("ev_%s_pod-%d", cluster, newest); out.Events[0].ID != want {
					t.Fatalf("newest event=%s, want %s", out.Events[0].ID, want)
				}
			}
			if out.Limit == nil {
				t.Fatalf("response is missing effective limit; requested %q, store returned %d rows", tc.query, len(rows))
			}
			if *out.Limit != tc.limit {
				t.Fatalf("limit=%d, want %d", *out.Limit, tc.limit)
			}
			if out.WindowFull == nil || *out.WindowFull != tc.full || *out.WindowFull != (len(rows) >= *out.Limit) {
				t.Fatalf("window_full=%v, want %v for %d rows and limit %d", out.WindowFull, tc.full, len(rows), *out.Limit)
			}
			if tc.full {
				if out.WindowNotice == nil || strings.TrimSpace(*out.WindowNotice) == "" {
					t.Fatal("a full window must include a non-empty window_notice")
				}
			} else if out.WindowNotice != nil {
				t.Fatalf("a window below its limit must omit window_notice, got %q", *out.WindowNotice)
			}
		})
	}
}

func TestK8sEventsPreservesErrorResponses(t *testing.T) {
	db, proxy := newK8sEventsServer(t)
	for _, tc := range []struct {
		name, method, token string
		status              int
		code                string
	}{
		{"unauthorized", http.MethodGet, "", http.StatusUnauthorized, "authentication_required"},
		{"wrong_method", http.MethodPost, "test-admin", http.StatusMethodNotAllowed, "method_not_allowed"},
		{"database_error", http.MethodGet, "test-admin", http.StatusInternalServerError, "k8s_events_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "database_error" {
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			resp := k8sEventsRequest(t, proxy, tc.method, "?limit=1000", tc.token)
			var out struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status || out.Error.Code != tc.code {
				t.Fatalf("status=%d code=%q, want status=%d code=%q", resp.StatusCode, out.Error.Code, tc.status, tc.code)
			}
		})
	}
}
