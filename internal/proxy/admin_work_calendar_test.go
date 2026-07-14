package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	for _, rev := range []store.K8sResourceRevision{
		{ID: "rev-old", ClusterID: "cluster-a", Namespace: "prod", Kind: "Pod", Name: "api-abc", Spec: calendarPodSpec("registry/api:1.0", "info"), ImageSet: "registry/api:1.0", ObservedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)},
		{ID: "rev-image", ClusterID: "cluster-a", Namespace: "prod", Kind: "Pod", Name: "api-abc", Spec: calendarPodSpec("registry/api:1.1", "info"), ImageSet: "registry/api:1.1", ObservedAt: time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339Nano)},
		{ID: "rev-env", ClusterID: "cluster-a", Namespace: "prod", Kind: "Pod", Name: "api-abc", Spec: calendarPodSpec("registry/api:1.1", "secret-new-value"), ImageSet: "registry/api:1.1", ObservedAt: now},
	} {
		if _, err := db.RecordK8sRevision(context.Background(), rev); err != nil {
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
		Events       []adminCalendarEvent         `json:"events"`
		Summary      map[string]int               `json:"summary"`
		Options      map[string][]string          `json:"options"`
		ActorOptions []adminCalendarActorOption   `json:"actor_options"`
		Timeline     []adminCalendarTimelineEvent `json:"timeline_events"`
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
	if len(out.ActorOptions) != 2 {
		t.Fatalf("actor options = %+v", out.ActorOptions)
	}
	foundImageChange, foundEnvChange := false, false
	for _, event := range out.Timeline {
		if event.Category == "image_changed" && event.ImageSet == "registry/api:1.1" && event.Previous == "registry/api:1.0" {
			foundImageChange = true
		}
		if event.Category == "env_changed" && event.ChangeCount > 0 && !strings.Contains(event.Description, "secret-new-value") {
			foundEnvChange = true
		}
	}
	if !foundImageChange {
		t.Fatalf("calendar must include Pod image transition: %+v", out.Timeline)
	}
	if !foundEnvChange {
		t.Fatalf("calendar must classify env change without leaking its value: %+v", out.Timeline)
	}
}

func calendarPodSpec(image, logLevel string) map[string]any {
	return map[string]any{"containers": []any{map[string]any{"name": "api", "image": image, "env": []any{map[string]any{"name": "LOG_LEVEL", "value": logLevel}}}}}
}

func TestAdminCalendarMajorK8sEventNoiseFilter(t *testing.T) {
	if adminCalendarMajorK8sEvent(store.K8sEvent{Type: "Normal", Reason: "Pulled"}) {
		t.Fatal("routine image pull must not flood calendar")
	}
	if !adminCalendarMajorK8sEvent(store.K8sEvent{Type: "Warning", Reason: "ImagePullBackOff"}) {
		t.Fatal("warning must be included")
	}
	if !adminCalendarMajorK8sEvent(store.K8sEvent{Type: "Normal", Reason: "ScalingReplicaSet"}) {
		t.Fatal("major scaling event must be included")
	}
}

func TestAdminWorkCalendarTimelineUXContract(t *testing.T) {
	for _, marker := range []string{"주요 운영 이벤트 타임라인", "timeline_events", "이미지 변경", "환경변수 변경", "Spec 변경", "새 리소스", "K8s 이벤트"} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("admin calendar timeline UI missing %q", marker)
		}
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

func TestAdminCalendarActorNameKeepsIDSeparateFromDisplayName(t *testing.T) {
	directory := map[string]string{"usr_123": "홍길동"}
	if got := adminCalendarActorName("usr_123", directory); got != "홍길동" {
		t.Fatalf("display name = %q", got)
	}
	options := adminCalendarActorOptions(map[string]bool{"usr_123": true}, directory)
	if len(options) != 1 || options[0].Value != "usr_123" || options[0].Label != "홍길동" {
		t.Fatalf("actor options = %+v", options)
	}
}
