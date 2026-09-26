package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/kube"
	"clustara/internal/store"
)

// newNotifyScanServer wires the notify scan the way it runs in production: a real SQLite store, a
// real Server.Routes mux and a Mattermost webhook Mattermost actually posts to.
func newNotifyScanServer(t *testing.T) (*store.SQLStore, *Server, *httptest.Server, chan string) {
	t.Helper()
	received := make(chan string, 16)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var d struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(b, &d)
		received <- d.Text
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
	for k, v := range map[string]string{
		"mattermost_enabled":     "true",
		"mattermost_webhook_url": hook.URL,
	} {
		if err := db.SetFlag(ctx, store.RuntimeFlag{Key: k, Value: v, UpdatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	server.invalidateMattermostCache()
	return db, server, proxy, received
}

// privilegedPod builds a real Pod object through the production converter, so the test exercises
// the same spec shape classifyPodSecurity reads at runtime.
func privilegedPod(t *testing.T, clusterID, namespace, name, updatedAt string) store.K8sInventoryItem {
	t.Helper()
	item := kube.InventoryFromObject("Pod", "v1", map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"namespace": namespace, "name": name, "uid": "uid-" + clusterID + "-" + name},
		"spec": map[string]any{
			"hostNetwork": true,
			"containers":  []any{map[string]any{"name": "c", "image": "app:1", "securityContext": map[string]any{"privileged": true}}},
		},
		"status": map[string]any{"phase": "Running"},
	})
	item.ID, item.ClusterID, item.UpdatedAt, item.ObservedAt = "inv_"+clusterID+"_"+namespace+"_"+name, clusterID, updatedAt, updatedAt
	return item
}

func notifyScan(t *testing.T, proxyURL, query string) map[string]any {
	t.Helper()
	resp := postJSON(t, proxyURL+"/admin/k8s/notify/scan"+query, "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("scan status=%d body=%s", resp.StatusCode, raw)
	}
	out := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The kinds the notify scan fetches must cover everything AnalyzeRCA and AnalyzeSecurity read.
// A kind left out is not reported as missing — the finding simply never fires, and nobody is paged.
func TestNotifyScanKindsCoverWhatIsAnalysed(t *testing.T) {
	kinds := notifyScanKinds()
	for _, want := range []string{"Pod", "Deployment", "StatefulSet", "DaemonSet", "Node", "Job", "CronJob", "Role", "ClusterRole"} {
		if !containsString(kinds, want) {
			t.Fatalf("%s is read by AnalyzeRCA/AnalyzeSecurity but the notify scan does not fetch it: %v", want, kinds)
		}
	}
	for _, ignored := range []string{"ConfigMap", "Service", "Endpoints", "Ingress"} {
		if containsString(kinds, ignored) {
			t.Fatalf("%s is read by neither analysis and must not consume the scan budget: %v", ignored, kinds)
		}
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		if seen[k] {
			t.Fatalf("%s is fetched twice, wasting a bind parameter on every scan: %v", k, kinds)
		}
		seen[k] = true
	}
}

// The scan fetched inventory rows of any kind ordered by updated_at, so on a cluster whose churn is
// dominated by kinds neither analysis reads (ConfigMaps rewritten by a controller, for example) the
// window filled with those rows and the privileged workload fell out of it — the alert path went
// quiet while the workload was still running.
func TestNotifyScanDoesNotLoseWorkloadsToChurningKinds(t *testing.T) {
	db, _, proxy, received := newNotifyScanServer(t)
	ctx := context.Background()

	original := notifyScanBudget
	notifyScanBudget = 3
	t.Cleanup(func() { notifyScanBudget = original })

	// The privileged Pod was observed first; the noise churns afterwards.
	if err := db.UpsertK8sInventory(ctx, privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cm-a", "cm-b", "cm-c", "cm-d", "cm-e"} {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID: "inv_" + name, ClusterID: "c1", Kind: "ConfigMap", Namespace: "edge", Name: name,
			UpdatedAt: "2026-09-20T00:00:00Z", ObservedAt: "2026-09-20T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["sent"] != float64(1) {
		t.Fatalf("the privileged workload must still be notified when unread kinds churn ahead of it: %v", out)
	}
	select {
	case text := <-received:
		if text == "" {
			t.Fatal("the Mattermost delivery carried no text")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no Mattermost delivery arrived for the privileged workload")
	}
}

// Even fetching only the analysed kinds, a large cluster can overflow the budget. The scan reported
// `sent: 0` for that case exactly as it does for a clean cluster, so an operator reading the
// response could not tell "nothing is wrong" from "we did not look at all of it".
func TestNotifyScanReportsTruncation(t *testing.T) {
	db, _, proxy, _ := newNotifyScanServer(t)
	ctx := context.Background()

	original := notifyScanBudget
	notifyScanBudget = 1
	t.Cleanup(func() { notifyScanBudget = original })

	for _, ns := range []string{"edge", "core"} {
		if err := db.UpsertK8sInventory(ctx, privilegedPod(t, "c1", ns, "agent", "2026-09-01T00:00:00Z")); err != nil {
			t.Fatal(err)
		}
	}

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["truncated"] != true {
		t.Fatalf("2 analysed resources over a budget of 1 must report truncation, not read as a complete scan: %v", out)
	}
	if out["resources"] != float64(1) {
		t.Fatalf("the scan must report how many resources it actually evaluated: %v", out)
	}
}

// A scan that fits must stay clean, or the flag means nothing.
func TestNotifyScanReportsCompleteWhenItFits(t *testing.T) {
	db, _, proxy, _ := newNotifyScanServer(t)
	if err := db.UpsertK8sInventory(context.Background(), privilegedPod(t, "c1", "edge", "agent", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["truncated"] != false {
		t.Fatalf("a scan inside the budget must not report truncation: %v", out)
	}
}
