package proxy

import (
	"context"
	"testing"

	"clustara/internal/kube"
	"clustara/internal/store"
)

// putCapacityInventory seeds one inventory row with an explicit updated_at, which
// is what decides who makes it into the capacity window: ListK8sInventory orders
// by updated_at DESC and UpsertK8sInventory only substitutes "now" when the field
// is empty.
func putCapacityInventory(t *testing.T, db *store.SQLStore, cluster, kind, name, updatedAt string, spec, status map[string]any) {
	t.Helper()
	item := kube.InventoryFromObject(kind, "v1", map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "default"},
		"spec":     spec, "status": status,
	})
	item.ClusterID = cluster
	item.ID = cluster + "/" + kind + "/" + name
	item.UpdatedAt = updatedAt
	if err := db.UpsertK8sInventory(context.Background(), item); err != nil {
		t.Fatal(err)
	}
}

// The capacity report took its inventory rows without a kind filter, ordered by
// updated_at. AnalyzeCapacity only reads HorizontalPodAutoscaler, Pod and Node,
// so churning rows of any other kind — ConfigMaps, Secrets, Events — crowd the
// Nodes and Pods out of the window and the report answers with empty
// node_packing, gpu and projections as though the cluster ran nothing.
func TestCapacityScanSpendsItsWindowOnAnalysedKinds(t *testing.T) {
	db, srv := newPolicyStatusServer(t)

	original := capacityScanBudget
	capacityScanBudget = 2
	t.Cleanup(func() { capacityScanBudget = original })

	// Non-analysed rows are the freshest, so an unfiltered window holds only these.
	for _, name := range []string{"app-config", "feature-flags"} {
		putCapacityInventory(t, db, "c1", "ConfigMap", name, "2026-01-02T00:00:00Z", nil, nil)
	}
	putCapacityInventory(t, db, "c1", "Node", "worker-1", "2026-01-01T00:00:00Z", nil, map[string]any{
		"allocatable": map[string]any{"cpu": "4", "nvidia.com/gpu": "8"},
	})
	putCapacityInventory(t, db, "c1", "Pod", "trainer", "2026-01-01T00:00:00Z", map[string]any{
		"nodeName": "worker-1",
		"containers": []any{map[string]any{"name": "trainer", "resources": map[string]any{
			"requests": map[string]any{"cpu": "1", "nvidia.com/gpu": "2"},
		}}},
	}, nil)

	body := getJSON(t, srv.URL+"/admin/k8s/capacity?cluster_id=c1")
	report, _ := body["report"].(map[string]any)
	if report == nil {
		t.Fatalf("capacity response carries no report: %v", body)
	}
	if _, ok := body["note"].(string); !ok {
		t.Errorf("the note key the UI renders disappeared: %v", body)
	}
	packing, _ := report["node_packing"].([]any)
	if len(packing) != 1 {
		t.Errorf("node_packing = %v, want the one node worker-1: churning ConfigMaps must not "+
			"evict the Nodes the capacity analysis reads", report["node_packing"])
	}
	gpu, _ := report["gpu"].([]any)
	if len(gpu) != 1 {
		t.Errorf("gpu = %v, want the one GPU node worker-1", report["gpu"])
	}
	scan, _ := body["scan"].(map[string]any)
	if scan == nil {
		t.Fatalf("the capacity report carries no scan block: %v", body)
	}
	if scan["status"] != "checked" {
		t.Errorf("status = %v for two analysed rows inside a budget of 2: nothing was dropped, so "+
			"the report must not warn: %v", scan["status"], scan)
	}
}

// Once the analysed kinds alone overflow the budget, the response has to say so:
// a silently partial capacity report reads the same as a cluster with spare room.
func TestCapacityScanReportsTruncation(t *testing.T) {
	db, srv := newPolicyStatusServer(t)

	original := capacityScanBudget
	capacityScanBudget = 2
	t.Cleanup(func() { capacityScanBudget = original })

	putCapacityInventory(t, db, "c1", "HorizontalPodAutoscaler", "api", "2026-01-03T00:00:00Z",
		map[string]any{"minReplicas": 2, "maxReplicas": 10}, map[string]any{"currentReplicas": 3, "desiredReplicas": 3})
	putCapacityInventory(t, db, "c1", "Node", "worker-1", "2026-01-02T00:00:00Z", nil, map[string]any{
		"allocatable": map[string]any{"cpu": "4"},
	})
	putCapacityInventory(t, db, "c1", "Pod", "trainer", "2026-01-01T00:00:00Z", map[string]any{
		"nodeName":   "worker-1",
		"containers": []any{map[string]any{"name": "trainer", "resources": map[string]any{"requests": map[string]any{"cpu": "1"}}}},
	}, nil)

	body := getJSON(t, srv.URL+"/admin/k8s/capacity?cluster_id=c1")
	scan, _ := body["scan"].(map[string]any)
	if scan == nil {
		t.Fatalf("the capacity report carries no scan block: %v", body)
	}
	if scan["status"] != "partial" {
		t.Fatalf("status = %v with 3 analysed resources over a budget of 2: a capacity report from a "+
			"partial window understates packing and GPU demand and must not read as complete: %v", scan["status"], scan)
	}
	if reason, _ := scan["reason"].(string); reason == "" {
		t.Errorf("a partial capacity scan must explain itself to the operator: %v", scan)
	}
	if report, _ := body["report"].(map[string]any); report == nil {
		t.Errorf("a truncated scan must still answer with a report: %v", body)
	}
}
