package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

func TestK8sCapacityGPUProvidersThroughRoutes(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	put := func(cluster, kind, name string, spec, status map[string]any) {
		t.Helper()
		item := kube.InventoryFromObject(kind, "v1", map[string]any{
			"metadata": map[string]any{"name": name, "namespace": "default"},
			"spec":     spec, "status": status,
		})
		item.ClusterID = cluster
		item.ID = cluster + "/" + kind + "/" + name
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	podSpec := func(node, key string, quantity any) map[string]any {
		return map[string]any{"nodeName": node, "containers": []any{
			map[string]any{"name": "trainer", "resources": map[string]any{
				"requests": map[string]any{"cpu": "1", key: quantity},
			}},
		}}
	}
	// Identical node and Pod names must remain distinct across providers/clusters.
	for _, fixture := range []struct {
		cluster, key string
		alloc, req   any
	}{
		{"nvidia", "nvidia.com/gpu", "8", "2"},
		{"intel", "intel.com/gpu", float64(2), float64(1)},
		{"amd", "amd.com/gpu", "4", "1"},
	} {
		if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: fixture.cluster, Name: fixture.cluster, Status: "ready"}); err != nil {
			t.Fatal(err)
		}
		put(fixture.cluster, "Node", "worker-1", nil, map[string]any{
			"allocatable": map[string]any{"cpu": "4", fixture.key: fixture.alloc},
		})
		put(fixture.cluster, "Pod", "trainer", podSpec("worker-1", fixture.key, fixture.req), nil)
		put(fixture.cluster, "Pod", "pending", podSpec("", fixture.key, "20"), nil)
		put(fixture.cluster, "Pod", "orphan", podSpec("missing-node", fixture.key, "20"), nil)
	}
	// A Pod in a cluster with no matching Node must not charge another cluster.
	put("pods-only", "Pod", "trainer", podSpec("worker-1", "amd.com/gpu", "20"), nil)
	// Exercise node-name sorting and preserve negative Idle in the HTTP result.
	put("nvidia", "Node", "worker-0", nil, map[string]any{
		"allocatable": map[string]any{"cpu": "4", "nvidia.com/gpu": "1"},
	})
	put("nvidia", "Pod", "overcommitted", podSpec("worker-0", "nvidia.com/gpu", "2"), nil)

	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(ctx)
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()
	get := func(t *testing.T, path string, out any) {
		t.Helper()
		resp, err := http.Get(proxy.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status=%d, want 200", path, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	wantFleet := []analyzer.GPUSummary{
		{ClusterID: "amd", Node: "worker-1", Allocatable: 4, Requested: 1, Idle: 3},
		{ClusterID: "intel", Node: "worker-1", Allocatable: 2, Requested: 1, Idle: 1},
		{ClusterID: "nvidia", Node: "worker-0", Allocatable: 1, Requested: 2, Idle: -1},
		{ClusterID: "nvidia", Node: "worker-1", Allocatable: 8, Requested: 2, Idle: 6},
	}
	for _, cluster := range []string{"", "amd", "intel", "nvidia", "pods-only", "unknown"} {
		name := cluster
		if name == "" {
			name = "fleet"
		}
		t.Run(name, func(t *testing.T) {
			want := []analyzer.GPUSummary{}
			for _, row := range wantFleet {
				if cluster == "" || row.ClusterID == cluster {
					want = append(want, row)
				}
			}
			var capacity struct {
				Report analyzer.CapacityReport `json:"report"`
			}
			get(t, "/admin/k8s/capacity?cluster_id="+cluster, &capacity)
			if !reflect.DeepEqual(capacity.Report.GPU, want) {
				t.Errorf("capacity GPU rows = %+v, want %+v", capacity.Report.GPU, want)
			}
			wantPacking := []analyzer.NodePacking{}
			for _, row := range want {
				wantPacking = append(wantPacking, analyzer.NodePacking{
					ClusterID: row.ClusterID, Node: row.Node, Pods: 1, AllocCPU: 4000, ReqCPU: 1000, CPUPct: 25,
				})
			}
			if !reflect.DeepEqual(capacity.Report.NodePacking, wantPacking) {
				t.Errorf("capacity CPU packing = %+v, want %+v", capacity.Report.NodePacking, wantPacking)
			}
			var monitoring struct {
				Report analyzer.NodeMonitoringReport `json:"report"`
			}
			get(t, "/admin/k8s/nodes/monitoring?cluster_id="+cluster, &monitoring)
			byNode := map[string]analyzer.NodeGPUUsage{}
			for _, node := range monitoring.Report.Nodes {
				byNode[node.ClusterID+"/"+node.Name] = node.GPU
			}
			if len(byNode) != len(want) {
				t.Fatalf("monitoring returned %d nodes, want %d", len(byNode), len(want))
			}
			for _, row := range want {
				gpu, ok := byNode[row.ClusterID+"/"+row.Node]
				if !ok || gpu.Allocatable != row.Allocatable || gpu.Requested != row.Requested {
					t.Errorf("monitoring allocation = %+v, want capacity allocation %+v", gpu, row)
				}
				// Monitoring clamps Available; capacity deliberately retains negative Idle.
				if row.Idle < 0 && gpu.Available != 0 {
					t.Errorf("overcommitted monitoring GPU available = %d, want 0", gpu.Available)
				}
			}
		})
	}
}
