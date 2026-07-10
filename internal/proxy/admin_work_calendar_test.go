package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestAdminWorkCalendarIncludesAllActorsAndFilters(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "admin-work-calendar.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, item := range []store.K8sActionRequest{
		{ID: "calendar-a", ClusterID: "cluster-a", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "api", Action: "restart", Status: "pending_approval", RequestedBy: "alice", CreatedAt: now, UpdatedAt: now},
		{ID: "calendar-b", ClusterID: "cluster-b", Namespace: "dev", ResourceKind: "Pod", ResourceName: "worker", Action: "delete", Status: "pending_approval", RequestedBy: "bob", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.InsertK8sActionRequest(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.Get(proxy.URL + "/admin/work-calendar?window_days=7&cluster_id=cluster-a&actor=alice")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/work-calendar = %d", resp.StatusCode)
	}
	var out struct {
		Events  []adminCalendarEvent `json:"events"`
		Summary map[string]int       `json:"summary"`
		Options map[string][]string  `json:"options"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 || out.Events[0].ID != "calendar-a" || out.Events[0].Actors["requested"] != "alice" {
		t.Fatalf("unexpected filtered events: %+v", out.Events)
	}
	if out.Summary["total"] != 1 {
		t.Fatalf("summary total = %d", out.Summary["total"])
	}
	if len(out.Options["clusters"]) != 2 || len(out.Options["actors"]) != 2 {
		t.Fatalf("filter options must describe the unfiltered data set: %+v", out.Options)
	}
}

func TestAdminWorkCalendarMenuRequiresAdminRead(t *testing.T) {
	features := map[string]bool{}
	if tabSet(roleScopes["developer"], features)["work-calendar"] {
		t.Fatal("developer must not see admin work calendar")
	}
	if !tabSet(roleScopes["admin"], features)["work-calendar"] {
		t.Fatal("admin must see admin work calendar")
	}
}
