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
	"time"

	"clustara/internal/kube"
	"clustara/internal/store"
)

// TestK8sNotifyScanRoutesEachFindingToItsOwnCluster runs the notify scan without a cluster_id
// (every cluster at once) over two clusters that each run a privileged Pod of the same
// namespace/name, with the Mattermost webhook received by an httptest server. Each finding must be
// deduplicated, owner-routed and deep-linked by the cluster it was found in — not by the request's
// (empty) cluster_id, which collapsed both into one notification pointing at no cluster.
func TestK8sNotifyScanRoutesEachFindingToItsOwnCluster(t *testing.T) {
	type delivery struct {
		Text    string `json:"text"`
		Channel string `json:"channel"`
	}
	received := make(chan delivery, 8)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var d delivery
		_ = json.Unmarshal(b, &d)
		received <- d
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()
	ctx := context.Background()

	for k, v := range map[string]string{
		"mattermost_enabled":       "true",
		"mattermost_webhook_url":   hook.URL,
		"mattermost_team_channels": `{"core":"#core-alerts","dr-ops":"#dr-alerts"}`,
	} {
		if err := db.SetFlag(ctx, store.RuntimeFlag{Key: k, Value: v, UpdatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	server.invalidateMattermostCache()

	createCluster := func(name string) string {
		t.Helper()
		resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
			"name": name, "server_url": "https://" + name + ".example.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1\nclusters: []",
		})
		defer resp.Body.Close()
		var created struct {
			Cluster store.K8sCluster `json:"cluster"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
			t.Fatal(err)
		}
		return created.Cluster.ID
	}
	clusters := map[string]string{createCluster("prod"): "core", createCluster("dr"): "dr-ops"}
	channelByCluster := map[string]string{}
	i := 0
	for clusterID, team := range clusters {
		// The same privileged workload exists in both clusters (an active/standby pair).
		item := kube.InventoryFromObject("Pod", "v1", map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"namespace": "edge", "name": "agent", "uid": "uid-" + clusterID},
			"spec": map[string]any{
				"hostNetwork": true,
				"containers":  []any{map[string]any{"name": "agent", "image": "agent:1", "securityContext": map[string]any{"privileged": true}}},
			},
			"status": map[string]any{"phase": "Running"},
		})
		item.ID, item.ClusterID = "k8sres_notify_"+string(rune('a'+i)), clusterID
		i++
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			t.Fatal(err)
		}
		if err := db.UpsertK8sNamespaceOwnership(ctx, store.K8sNamespaceOwnership{ID: "own-" + clusterID, ClusterID: clusterID, Namespace: "edge", Team: team}); err != nil {
			t.Fatal(err)
		}
		channelByCluster[clusterID] = map[string]string{"core": "#core-alerts", "dr-ops": "#dr-alerts"}[team]
	}

	resp := postJSON(t, proxy.URL+"/admin/k8s/notify/scan", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("scan status=%d body=%s", resp.StatusCode, raw)
	}
	var out struct {
		Sent int `json:"sent"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Sent != len(clusters) {
		t.Fatalf("both clusters' privileged workloads must be notified (dedup is per cluster), sent=%d", out.Sent)
	}

	seen := map[string]bool{}
	for range clusters {
		select {
		case d := <-received:
			if !strings.Contains(d.Text, "Privileged 워크로드") || !strings.Contains(d.Text, "edge/Pod/agent") {
				t.Fatalf("unexpected notification: %+v", d)
			}
			matched := ""
			for clusterID := range clusters {
				if strings.Contains(d.Text, "cluster_id="+clusterID) {
					matched = clusterID
				}
			}
			if matched == "" {
				t.Fatalf("deep link must carry the finding's own cluster_id, got %+v", d)
			}
			if d.Channel != channelByCluster[matched] {
				t.Fatalf("owner routing must use the finding's cluster (%s → %s), got %+v", matched, channelByCluster[matched], d)
			}
			seen[matched] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("expected a notification per cluster, got %d", len(seen))
		}
	}
	if len(seen) != len(clusters) {
		t.Fatalf("each cluster must receive its own notification, got %v", seen)
	}
}

// notifyScanFixture is a single-cluster notify scan wired end to end: a real SQLite store, the real
// routes, an httptest Mattermost webhook and one privileged workload that produces exactly one
// Pod Security finding per scan.
type notifyScanFixture struct {
	server    *Server
	proxy     *httptest.Server
	db        *store.SQLStore
	hookURL   string
	received  chan notifyDelivery
	clusterID string
}

type notifyDelivery struct {
	Text    string `json:"text"`
	Channel string `json:"channel"`
}

func newNotifyScanFixture(t *testing.T) *notifyScanFixture {
	t.Helper()
	received := make(chan notifyDelivery, 8)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var d notifyDelivery
		_ = json.Unmarshal(b, &d)
		received <- d
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hook.Close)

	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)
	ctx := context.Background()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "prod", "server_url": "https://prod.example.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1\nclusters: []",
	})
	defer resp.Body.Close()
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	item := kube.InventoryFromObject("Pod", "v1", map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"namespace": "edge", "name": "agent", "uid": "uid-1"},
		"spec": map[string]any{
			"hostNetwork": true,
			"containers":  []any{map[string]any{"name": "agent", "image": "agent:1", "securityContext": map[string]any{"privileged": true}}},
		},
		"status": map[string]any{"phase": "Running"},
	})
	item.ID, item.ClusterID = "k8sres_notify_gate", created.Cluster.ID
	if err := db.UpsertK8sInventory(ctx, item); err != nil {
		t.Fatal(err)
	}
	return &notifyScanFixture{server: server, proxy: proxy, db: db, hookURL: hook.URL, received: received, clusterID: created.Cluster.ID}
}

// setFlags writes runtime flags and invalidates the 15s Mattermost snapshot cache so the next scan
// observes them.
func (f *notifyScanFixture) setFlags(t *testing.T, flags map[string]string) {
	t.Helper()
	for k, v := range flags {
		if err := f.db.SetFlag(context.Background(), store.RuntimeFlag{Key: k, Value: v, UpdatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	f.server.invalidateMattermostCache()
}

// scan runs one notify scan and returns its reported sent/undeliverable counts.
func (f *notifyScanFixture) scan(t *testing.T) (sent, undeliverable int) {
	t.Helper()
	resp := postJSON(t, f.proxy.URL+"/admin/k8s/notify/scan", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("scan status=%d body=%s", resp.StatusCode, raw)
	}
	var out struct {
		Sent          int `json:"sent"`
		Undeliverable int `json:"undeliverable"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Sent, out.Undeliverable
}

// A scan that runs while Mattermost is switched off must not spend the 6h dedup window: the
// operator who schedules the scan first and configures the webhook afterwards (the order
// docs/ADMIN_GUIDE.md describes) would otherwise get silence until every window expired.
func TestK8sNotifyScanKeepsDedupWindowWhileNotificationsDisabled(t *testing.T) {
	f := newNotifyScanFixture(t)
	f.setFlags(t, map[string]string{"mattermost_enabled": "false", "mattermost_webhook_url": f.hookURL})

	if sent, undeliverable := f.scan(t); sent != 0 || undeliverable != 1 {
		t.Fatalf("disabled scan must report nothing sent and the finding as undeliverable, sent=%d undeliverable=%d", sent, undeliverable)
	}
	select {
	case d := <-f.received:
		t.Fatalf("notifications are disabled, webhook must not be called: %+v", d)
	default:
	}

	f.setFlags(t, map[string]string{"mattermost_enabled": "true"})
	if sent, _ := f.scan(t); sent != 1 {
		t.Fatalf("the still-privileged workload must notify once Mattermost is enabled, sent=%d", sent)
	}
	select {
	case d := <-f.received:
		if !strings.Contains(d.Text, "Privileged 워크로드") || !strings.Contains(d.Text, "edge/Pod/agent") {
			t.Fatalf("unexpected notification: %+v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected the finding to be delivered after enabling Mattermost")
	}
}

// Same guarantee for a muted category: k8s_security findings evaluated while the category is off
// must still notify when the operator turns that category back on.
func TestK8sNotifyScanKeepsDedupWindowWhileCategoryMuted(t *testing.T) {
	f := newNotifyScanFixture(t)
	f.setFlags(t, map[string]string{
		"mattermost_enabled":     "true",
		"mattermost_webhook_url": f.hookURL,
		"mattermost_events":      "cost,approval", // k8s_security muted
	})

	if sent, undeliverable := f.scan(t); sent != 0 || undeliverable != 1 {
		t.Fatalf("muted category must report nothing sent and the finding as undeliverable, sent=%d undeliverable=%d", sent, undeliverable)
	}
	select {
	case d := <-f.received:
		t.Fatalf("k8s_security is muted, webhook must not be called: %+v", d)
	default:
	}

	f.setFlags(t, map[string]string{"mattermost_events": "cost,approval,k8s_security"})
	if sent, _ := f.scan(t); sent != 1 {
		t.Fatalf("unmuting k8s_security must deliver the finding, sent=%d", sent)
	}
	select {
	case d := <-f.received:
		if !strings.Contains(d.Text, "Privileged 워크로드") {
			t.Fatalf("unexpected notification: %+v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected the finding to be delivered after unmuting the category")
	}
}

// Event-only reproduction avoids unrelated Pod Security findings.
func TestK8sNotifyScanRoutesRCAProbeFindingsToEachCluster(t *testing.T) {
	type delivery struct {
		Text    string `json:"text"`
		Channel string `json:"channel"`
	}
	received := make(chan delivery, 8)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var d delivery
		_ = json.Unmarshal(b, &d)
		received <- d
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()
	ctx := context.Background()

	for k, v := range map[string]string{
		"mattermost_enabled":       "true",
		"mattermost_webhook_url":   hook.URL,
		"mattermost_team_channels": `{"core":"#core-alerts","dr-ops":"#dr-alerts"}`,
	} {
		if err := db.SetFlag(ctx, store.RuntimeFlag{Key: k, Value: v, UpdatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	server.invalidateMattermostCache()

	createCluster := func(name string) string {
		t.Helper()
		resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
			"name": name, "server_url": "https://" + name + ".example.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1\nclusters: []",
		})
		defer resp.Body.Close()
		var created struct {
			Cluster store.K8sCluster `json:"cluster"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
			t.Fatal(err)
		}
		return created.Cluster.ID
	}
	clusters := map[string]string{createCluster("prod"): "core", createCluster("dr"): "dr-ops"}
	channelByCluster := map[string]string{}
	for clusterID, team := range clusters {
		for _, suffix := range []string{"first", "repeat"} {
			if err := db.InsertK8sEvent(ctx, store.K8sEvent{
				ID: "probe-" + clusterID + "-" + suffix, ClusterID: clusterID, Namespace: "edge",
				InvolvedKind: "Pod", InvolvedName: "agent", Type: "Warning",
				Reason: "Unhealthy", Message: "Liveness probe failed: HTTP 503",
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.UpsertK8sNamespaceOwnership(ctx, store.K8sNamespaceOwnership{ID: "own-" + clusterID, ClusterID: clusterID, Namespace: "edge", Team: team}); err != nil {
			t.Fatal(err)
		}
		channelByCluster[clusterID] = map[string]string{"core": "#core-alerts", "dr-ops": "#dr-alerts"}[team]
	}

	resp := postJSON(t, proxy.URL+"/admin/k8s/notify/scan", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("scan status=%d body=%s", resp.StatusCode, raw)
	}
	var out struct {
		Sent int `json:"sent"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Sent != len(clusters) {
		t.Fatalf("both clusters' probe failures must be notified (dedup is per cluster), sent=%d", out.Sent)
	}

	seen := map[string]bool{}
	for range clusters {
		select {
		case d := <-received:
			if !strings.Contains(d.Text, "LivenessProbeFailed") || !strings.Contains(d.Text, "edge/Pod/agent") {
				t.Fatalf("unexpected notification: %+v", d)
			}
			matched := ""
			for clusterID := range clusters {
				if strings.Contains(d.Text, "cluster_id="+clusterID) {
					matched = clusterID
				}
			}
			if matched == "" {
				t.Fatalf("deep link must carry the finding's own cluster_id, got %+v", d)
			}
			if d.Channel != channelByCluster[matched] {
				t.Fatalf("owner routing must use the finding's cluster (%s → %s), got %+v", matched, channelByCluster[matched], d)
			}
			seen[matched] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("expected a notification per cluster, got %d", len(seen))
		}
	}
	if len(seen) != len(clusters) {
		t.Fatalf("each cluster must receive its own notification, got %v", seen)
	}

	// Persisted notification dedup still suppresses a second scan in both clusters.
	second := postJSON(t, proxy.URL+"/admin/k8s/notify/scan", "", map[string]any{})
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second scan status=%d", second.StatusCode)
	}
	if err := json.NewDecoder(second.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Sent != 0 {
		t.Fatalf("repeat scan sent %d notifications", out.Sent)
	}
	select {
	case d := <-received:
		t.Fatalf("unexpected extra notification: %+v", d)
	default:
	}
}
