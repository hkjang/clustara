package analyzer

import (
	"testing"

	"clustara/internal/store"
)

// The capacity endpoint takes cluster_id as an optional filter, so the whole-fleet view feeds
// AnalyzeCapacity inventory and metrics from every registered cluster at once. Node names
// (worker-1, ...) and namespace/name pairs repeat across clusters, so every cross-reference in
// this report has to carry the cluster too.

func capNode(cluster, name, cpu string) store.K8sInventoryItem {
	return store.K8sInventoryItem{ClusterID: cluster, Kind: "Node", Name: name,
		StatusObject: map[string]any{"allocatable": map[string]any{"cpu": cpu}}}
}

func capPod(cluster, ns, name, node, reqCPU string) store.K8sInventoryItem {
	return store.K8sInventoryItem{ClusterID: cluster, Kind: "Pod", Namespace: ns, Name: name,
		Spec: map[string]any{"nodeName": node, "containers": []any{
			map[string]any{"name": "c", "resources": map[string]any{"requests": map[string]any{"cpu": reqCPU}}}}}}
}

func packingFor(t *testing.T, rows []NodePacking, cluster, node string) NodePacking {
	t.Helper()
	for _, p := range rows {
		if p.ClusterID == cluster && p.Node == node {
			return p
		}
	}
	t.Fatalf("no node_packing row for %s/%s: %+v", cluster, node, rows)
	return NodePacking{}
}

// SCALE-07: a Pod runs on the node of its own cluster. Matching .spec.nodeName by name alone
// charged prod's worker-1 with dr's Pods (and collapsed both nodes into one row).
func TestNodePackingDoesNotMixClusters(t *testing.T) {
	items := []store.K8sInventoryItem{
		capNode("prod", "worker-1", "4"), // 4000m
		capNode("dr", "worker-1", "8"),   // 8000m
		capPod("prod", "default", "api", "worker-1", "1000m"),
		capPod("dr", "default", "api", "worker-1", "3000m"),
		capPod("dr", "default", "batch", "worker-1", "2000m"),
	}
	rep := AnalyzeCapacity(items, nil)
	if len(rep.NodePacking) != 2 {
		t.Fatalf("expected one row per cluster node, got %+v", rep.NodePacking)
	}
	prod := packingFor(t, rep.NodePacking, "prod", "worker-1")
	if prod.Pods != 1 || prod.ReqCPU != 1000 || prod.AllocCPU != 4000 || prod.CPUPct != 25 {
		t.Errorf("prod worker-1 should only hold its own Pod: %+v", prod)
	}
	dr := packingFor(t, rep.NodePacking, "dr", "worker-1")
	if dr.Pods != 2 || dr.ReqCPU != 5000 || dr.AllocCPU != 8000 {
		t.Errorf("dr worker-1 wrong: %+v", dr)
	}
}

// SCALE-08: same join, GPU column.
func TestGPUSummaryDoesNotMixClusters(t *testing.T) {
	gpuNode := func(cluster, name string, gpus float64) store.K8sInventoryItem {
		it := capNode(cluster, name, "4")
		asAnyMap(it.StatusObject["allocatable"])["nvidia.com/gpu"] = gpus
		return it
	}
	gpuPod := func(cluster, name string, gpus float64) store.K8sInventoryItem {
		return store.K8sInventoryItem{ClusterID: cluster, Kind: "Pod", Namespace: "ml", Name: name,
			Spec: map[string]any{"nodeName": "gpu-1", "containers": []any{
				map[string]any{"name": "c", "resources": map[string]any{"requests": map[string]any{"nvidia.com/gpu": gpus}}}}}}
	}
	items := []store.K8sInventoryItem{
		gpuNode("prod", "gpu-1", 2),
		gpuNode("dr", "gpu-1", 2),
		gpuPod("dr", "train-a", 2),
	}
	rep := AnalyzeCapacity(items, nil)
	byCluster := map[string]GPUSummary{}
	for _, g := range rep.GPU {
		byCluster[g.ClusterID] = g
	}
	if got := byCluster["prod"]; got.Requested != 0 || got.Idle != 2 {
		t.Errorf("prod GPU node is idle; dr's Pod must not consume it: %+v", got)
	}
	if got := byCluster["dr"]; got.Requested != 2 || got.Idle != 0 {
		t.Errorf("dr GPU node should be fully requested: %+v", got)
	}
}

// SCALE-03/04: the metric feed spans clusters, so keying the latest sample by namespace/name
// alone kept one cluster's reading and compared it against every same-named Pod's requests.
func TestAllocationUsesSameClusterMetric(t *testing.T) {
	items := []store.K8sInventoryItem{
		capPod("prod", "default", "api", "worker-1", "1000m"),
		capPod("dr", "default", "api", "worker-1", "100m"),
	}
	// dr's Pod is hot (250m > 100m); prod's is comfortably inside its request.
	metrics := []store.K8sMetricSample{
		{ClusterID: "dr", ResourceKind: "Pod", Namespace: "default", ResourceName: "api", CPUMillicores: 250, ObservedAt: "2026-06-24T03:00:00Z"},
		{ClusterID: "prod", ResourceKind: "Pod", Namespace: "default", ResourceName: "api", CPUMillicores: 600, ObservedAt: "2026-06-24T03:00:00Z"},
	}
	rep := AnalyzeCapacity(items, metrics)
	byCluster := map[string]AllocFinding{}
	for _, a := range rep.Allocation {
		byCluster[a.ClusterID] = a
	}
	if _, flagged := byCluster["prod"]; flagged {
		t.Errorf("prod/api uses 600m of a 1000m request — not a finding: %+v", byCluster["prod"])
	}
	dr, ok := byCluster["dr"]
	if !ok {
		t.Fatalf("dr/api should be flagged, got %+v", rep.Allocation)
	}
	if dr.Issue != "under_provisioned" || dr.CPUUsageM != 250 || dr.CPUReqM != 100 {
		t.Errorf("dr/api should be under_provisioned from its own metric: %+v", dr)
	}
}

// SCALE-05: two clusters' samples for a same-named node were interleaved into one trend line,
// so oldest→newest could span two different machines.
func TestProjectNodeCapacityPerCluster(t *testing.T) {
	items := []store.K8sInventoryItem{
		capNode("prod", "worker-1", "4"), // 4000m
		capNode("dr", "worker-1", "8"),   // 8000m
	}
	metrics := []store.K8sMetricSample{
		// prod: flat at 1000m over 2 days → no growth.
		{ClusterID: "prod", ResourceKind: "Node", ResourceName: "worker-1", CPUMillicores: 1000, ObservedAt: "2026-06-20T00:00:00Z"},
		{ClusterID: "prod", ResourceKind: "Node", ResourceName: "worker-1", CPUMillicores: 1000, ObservedAt: "2026-06-22T00:00:00Z"},
		// dr: 1000m → 2000m over 2 days = 500m/day, 6000m headroom → 12 days.
		{ClusterID: "dr", ResourceKind: "Node", ResourceName: "worker-1", CPUMillicores: 1000, ObservedAt: "2026-06-20T00:00:00Z"},
		{ClusterID: "dr", ResourceKind: "Node", ResourceName: "worker-1", CPUMillicores: 2000, ObservedAt: "2026-06-22T00:00:00Z"},
	}
	proj := ProjectNodeCapacity(items, metrics)
	if len(proj) != 2 {
		t.Fatalf("expected one projection per cluster node, got %+v", proj)
	}
	byCluster := map[string]NodeProjection{}
	for _, p := range proj {
		byCluster[p.ClusterID] = p
	}
	if got := byCluster["prod"]; got.DailyGrowthCPUm != 0 || got.AllocCPUm != 4000 || got.DaysToFull != -1 {
		t.Errorf("prod worker-1 is flat with its own allocatable: %+v", got)
	}
	if got := byCluster["dr"]; got.DailyGrowthCPUm != 500 || got.AllocCPUm != 8000 || got.DaysToFull != 12 {
		t.Errorf("dr worker-1 projection wrong: %+v", got)
	}
}

// Both node tables are built from a map, so their order changed on every request.
func TestNodePackingOrderIsStable(t *testing.T) {
	items := []store.K8sInventoryItem{
		capNode("prod", "worker-2", "4"),
		capNode("prod", "worker-1", "4"),
		capNode("dr", "worker-1", "4"),
	}
	first := AnalyzeCapacity(items, nil).NodePacking
	want := []string{"dr/worker-1", "prod/worker-1", "prod/worker-2"}
	for i := 0; i < 20; i++ {
		got := []string{}
		for _, p := range AnalyzeCapacity(items, nil).NodePacking {
			got = append(got, p.ClusterID+"/"+p.Node)
		}
		if len(got) != len(want) {
			t.Fatalf("row count changed: %+v", got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("node_packing order is not stable: %+v (first run %+v)", got, first)
			}
		}
	}
}
