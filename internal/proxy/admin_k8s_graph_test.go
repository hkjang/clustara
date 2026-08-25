package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

func TestK8sResourceGraphKeepsPodMetricsScopedToCluster(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	for _, cluster := range []store.K8sCluster{
		{ID: "c1", Name: "cluster-one", Status: "ready"},
		{ID: "c2", Name: "cluster-two", Status: "ready"},
	} {
		if err := db.UpsertK8sCluster(ctx, cluster); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []store.K8sInventoryItem{
		{ID: "pod-c1", ClusterID: "c1", Kind: "Pod", Namespace: "default", Name: "api", Status: "Running"},
		{ID: "pod-c2", ClusterID: "c2", Kind: "Pod", Namespace: "default", Name: "api", Status: "Running"},
	} {
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	for _, metric := range []store.K8sMetricSample{
		{ID: "metric-c1", ClusterID: "c1", Namespace: "default", ResourceKind: "Pod", ResourceName: "api", CPUMillicores: 100, MemoryBytes: 1024, ObservedAt: "2026-07-28T01:00:00Z"},
		{ID: "metric-c2", ClusterID: "c2", Namespace: "default", ResourceKind: "Pod", ResourceName: "api", CPUMillicores: 900, MemoryBytes: 2048, ObservedAt: "2026-07-28T01:00:00Z"},
	} {
		if err := db.InsertK8sMetricSample(ctx, metric); err != nil {
			t.Fatal(err)
		}
	}

	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "graph.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/k8s/resource-graph")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload struct {
		Graph struct {
			Nodes []struct {
				ClusterID     string  `json:"cluster_id"`
				Kind          string  `json:"kind"`
				Name          string  `json:"name"`
				CPUMillicores float64 `json:"cpu_millicores"`
				MemoryBytes   float64 `json:"memory_bytes"`
			} `json:"nodes"`
		} `json:"graph"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resource graph status = %d", resp.StatusCode)
	}
	got := map[string][2]float64{}
	for _, node := range payload.Graph.Nodes {
		if node.Kind == "Pod" && node.Name == "api" {
			got[node.ClusterID] = [2]float64{node.CPUMillicores, node.MemoryBytes}
		}
	}
	if got["c1"] != [2]float64{100, 1024} || got["c2"] != [2]float64{900, 2048} {
		t.Fatalf("Pod metrics crossed cluster boundaries: %+v", got)
	}
}
