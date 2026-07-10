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

func TestMeWorkCalendarIncludesCallerActionRequests(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "me-work-calendar.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	caller := "admin_" + hashProxyKey("personal-secret")[:12]
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := db.InsertK8sActionRequest(context.Background(), store.K8sActionRequest{
		ID: "k8sact_me_calendar", ClusterID: "cluster-a", Namespace: "default", ResourceKind: "Deployment", ResourceName: "api",
		Action: "rollout_restart", RiskLevel: "medium", Status: "pending_approval", RequestedBy: caller,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, proxy.URL+"/me/work-calendar?window_days=7", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer personal-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /me/work-calendar = %d", resp.StatusCode)
	}
	var out struct {
		UserID  string                  `json:"user_id"`
		Events  []personalCalendarEvent `json:"events"`
		Summary map[string]int          `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.UserID != caller {
		t.Fatalf("user_id = %q, want %q", out.UserID, caller)
	}
	found := false
	for _, ev := range out.Events {
		if ev.ID == "k8sact_me_calendar" && ev.Kind == "action" && len(ev.Roles) > 0 && ev.Roles[0] == "requested" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("calendar did not include caller action: %+v", out.Events)
	}
	if out.Summary["total"] == 0 {
		t.Fatalf("summary total = 0")
	}
}
