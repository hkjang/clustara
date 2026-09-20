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
