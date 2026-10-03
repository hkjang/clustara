package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

// registerClusters records clusters the way the admin API does, which is what makes a fleet-wide
// scan addressable per cluster instead of as one anonymous window.
func registerClusters(t *testing.T, db *store.SQLStore, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := db.UpsertK8sCluster(context.Background(), store.K8sCluster{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
}

// A scan with no cluster_id is the fleet-wide form — the one docs/ADMIN_GUIDE.md tells operators to
// put on a cron so a single job covers every cluster. It used to read inventory, events and
// revisions through one window per scan, ordered newest-first, with the budget shared by every
// cluster at once. A cluster whose controllers rewrite rows constantly therefore filled that window
// on its own and the quiet clusters were never evaluated: no privileged workload of theirs could
// page, and the response said only `truncated: true` — never which cluster had lost its turn.
//
// Here c-busy holds two privileged pods updated after c-quiet's, and the budget is one row. Under
// the shared window c-busy takes it and c-quiet's pod is dropped before the analysis runs.
func TestNotifyScanGivesEachRegisteredClusterItsOwnBudget(t *testing.T) {
	db, _, proxy, received := newNotifyScanServer(t)
	ctx := context.Background()
	registerClusters(t, db, "c-busy", "c-quiet")

	for i, name := range []string{"busy-a", "busy-b"} {
		ts := time.Date(2026, 9, 3, 0, i, 0, 0, time.UTC).Format(time.RFC3339Nano)
		if err := db.UpsertK8sInventory(ctx, privilegedPod(t, "c-busy", "edge", name, ts)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertK8sInventory(ctx, privilegedPod(t, "c-quiet", "edge", "quiet-a", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}

	original := notifyScanBudget
	notifyScanBudget = 1
	t.Cleanup(func() { notifyScanBudget = original })

	out := notifyScan(t, proxy.URL, "")
	if out["sent"] != float64(2) {
		t.Fatalf("the churning cluster must not spend the quiet cluster's query budget: %v", out)
	}
	if out["clusters_scanned"] != float64(2) {
		t.Fatalf("the scan must report how many clusters each got a budget: %v", out)
	}
	truncatedIn := map[string]bool{}
	list, ok := out["clusters_truncated"].([]any)
	if !ok {
		t.Fatalf("the scan must name the clusters whose windows filled: %v", out)
	}
	for _, v := range list {
		id, _ := v.(string)
		truncatedIn[id] = true
	}
	if !truncatedIn["c-busy"] {
		t.Fatalf("c-busy's inventory window filled and the response must say so: %v", out)
	}
	if truncatedIn["c-quiet"] {
		t.Fatalf("c-quiet's single row fits its own window, so it is not truncated: %v", out)
	}

	paged := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case text := <-received:
			for _, name := range []string{"busy-a", "busy-b", "quiet-a"} {
				if strings.Contains(text, name) {
					paged[name] = true
				}
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("expected a delivery for each cluster, got %v", paged)
		}
	}
	if !paged["quiet-a"] {
		t.Fatalf("the quiet cluster's privileged pod must page: %v", paged)
	}
}

// The counterpart contract: with nothing registered in k8s_clusters there is no fleet to fan out
// over, so the scan keeps doing exactly what it did before — one shared window, one query per
// source — rather than inventing targets out of the cluster_id column of inventory rows. A scan
// that named a cluster was always a single target and stays one.
func TestNotifyScanFallsBackToASingleWindowWithoutRegisteredClusters(t *testing.T) {
	db, _, proxy, _ := newNotifyScanServer(t)
	ctx := context.Background()

	for i, name := range []string{"busy-a", "busy-b"} {
		ts := time.Date(2026, 9, 3, 0, i, 0, 0, time.UTC).Format(time.RFC3339Nano)
		if err := db.UpsertK8sInventory(ctx, privilegedPod(t, "c-busy", "edge", name, ts)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertK8sInventory(ctx, privilegedPod(t, "c-quiet", "edge", "quiet-a", "2026-09-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}

	original := notifyScanBudget
	notifyScanBudget = 1
	t.Cleanup(func() { notifyScanBudget = original })

	out := notifyScan(t, proxy.URL, "")
	if out["clusters_scanned"] != float64(1) {
		t.Fatalf("an empty cluster registry means one shared window, as before: %v", out)
	}
	if out["resources"] != float64(1) || out["truncated"] != true {
		t.Fatalf("the shared window must still report its own budget and truncation: %v", out)
	}
}
