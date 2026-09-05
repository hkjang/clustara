package analyzer

import (
	"testing"

	"clustara/internal/store"
)

// container builds one container declaring a single request section.
func reqContainer(name string, req map[string]any) map[string]any {
	return map[string]any{"name": name, "resources": map[string]any{"requests": req}}
}

// Kubernetes runs init containers to completion, one at a time, before the app containers
// start, so the pod's effective request is max(sum(regular), largest init) — the two never
// hold the node at the same time. Summing them books a pod for more than the scheduler
// reserved: every node packing percentage, cost line and rightsizing recommendation
// derived from it is inflated by the init container.
func TestPodRequestUsesEffectiveRequestNotTheSumOfInitAndApp(t *testing.T) {
	spec := map[string]any{
		"initContainers": []any{
			reqContainer("load-dataset", map[string]any{"cpu": "2", "memory": "4Gi"}),
			reqContainer("chown", map[string]any{"cpu": "100m", "memory": "64Mi"}),
		},
		"containers": []any{reqContainer("app", map[string]any{"cpu": "500m", "memory": "256Mi"})},
	}
	// max(500m, 2000m) = 2000m and max(256Mi, 4Gi) = 4Gi — not 2600m / 4.3Gi.
	if got := podRequestCPU(spec); got != 2000 {
		t.Errorf("cpu request = %dm, want 2000m (largest init, not init+app)", got)
	}
	if got, want := podRequestMemBytes(spec), int64(4)<<30; got != want {
		t.Errorf("mem request = %d, want %d (largest init, not init+app)", got, want)
	}

	// When the app containers together outweigh every init container, they win.
	spec["containers"] = []any{
		reqContainer("app", map[string]any{"cpu": "1500m", "memory": "3Gi"}),
		reqContainer("sidecar", map[string]any{"cpu": "1", "memory": "2Gi"}),
	}
	if got := podRequestCPU(spec); got != 2500 {
		t.Errorf("cpu request = %dm, want 2500m (sum of the app containers)", got)
	}
	if got, want := podRequestMemBytes(spec), int64(5)<<30; got != want {
		t.Errorf("mem request = %d, want %d (sum of the app containers)", got, want)
	}
}

// A native sidecar is an initContainer with restartPolicy: Always — it starts before the
// app containers and stays up for the pod's whole life, so its request is held alongside
// them and belongs in the sum, not in the init max.
func TestNativeSidecarRequestIsAddedNotMaxed(t *testing.T) {
	sidecar := reqContainer("log-shipper", map[string]any{"cpu": "200m"})
	sidecar["restartPolicy"] = "Always"
	spec := map[string]any{
		"initContainers": []any{sidecar},
		"containers":     []any{reqContainer("app", map[string]any{"cpu": "500m"})},
	}
	if got := podRequestCPU(spec); got != 700 {
		t.Errorf("cpu request = %dm, want 700m (sidecar runs alongside the app container)", got)
	}
}

// The display summary read only .spec.containers, so a pod whose init container is the
// biggest consumer showed less than it actually holds — the operator triaging an OOMKill
// was shown a memory limit the pod does not have.
func TestSummarizePodResourcesCountsInitContainers(t *testing.T) {
	spec := map[string]any{
		"initContainers": []any{map[string]any{"name": "warm", "resources": map[string]any{
			"limits": map[string]any{"cpu": "2", "memory": "2Gi"}}}},
		"containers": []any{map[string]any{"name": "app", "resources": map[string]any{
			"limits": map[string]any{"cpu": "500m", "memory": "512Mi"}}}},
	}
	tags := SummarizePodResources(spec)
	if !tags.HasLim || tags.LimCPU != "2" || tags.LimMem != "2Gi" {
		t.Errorf("limits = %+v, want the init container's 2 / 2Gi", tags)
	}

	// A pod that declares resources only on its init container must not read as unset.
	initOnly := map[string]any{
		"initContainers": []any{reqContainer("warm", map[string]any{"cpu": "250m"})},
		"containers":     []any{map[string]any{"name": "app"}},
	}
	if q := PodResourceNumbers(initOnly); !q.HasReq || q.ReqCPUm != 250 {
		t.Errorf("init-only requests = %+v, want HasReq with 250m", q)
	}
}

// A pod in a terminal phase has released its node reservation: the scheduler stops
// counting it and the kubelet frees the cgroup. The API server keeps the object (a
// CronJob namespace accumulates hundreds of Completed pods, an evicted node a pile of
// Failed ones) and the collector stores every one, so counting their requests packs the
// node past 100% and reports idle GPUs as busy.
func TestNodePackingIgnoresTerminatedPods(t *testing.T) {
	pod := func(name, phase string) store.K8sInventoryItem {
		it := store.K8sInventoryItem{Kind: "Pod", Namespace: "batch", Name: name, Status: phase,
			Spec: map[string]any{"nodeName": "node-1", "containers": []any{
				reqContainer("c", map[string]any{"cpu": "1", "nvidia.com/gpu": "1"})}}}
		if phase != "" {
			it.StatusObject = map[string]any{"phase": phase}
		}
		return it
	}
	items := []store.K8sInventoryItem{
		{Kind: "Node", Name: "node-1", StatusObject: map[string]any{"allocatable": map[string]any{"cpu": "4", "nvidia.com/gpu": "2"}}},
		pod("live", "Running"),
		pod("job-1", "Succeeded"),
		pod("job-2", "Succeeded"),
		pod("evicted", "Failed"),
		pod("crashing", "CrashLoopBackOff"), // still scheduled: it holds its request
	}
	rep := AnalyzeCapacity(items, nil)
	if len(rep.NodePacking) != 1 {
		t.Fatalf("expected 1 node, got %d", len(rep.NodePacking))
	}
	n := rep.NodePacking[0]
	if n.Pods != 2 || n.ReqCPU != 2000 || n.CPUPct != 50 {
		t.Errorf("node packing = %+v, want 2 pods / 2000m / 50%% (finished pods excluded)", n)
	}
	if len(rep.GPU) != 1 || rep.GPU[0].Requested != 2 || rep.GPU[0].Idle != 0 {
		t.Errorf("gpu summary = %+v, want 2 requested by the two live pods", rep.GPU)
	}
}

// The same reservation rule decides what a pod costs: a Completed Job pod is billed at
// full request price for as long as the API server keeps it, which on a CronJob-heavy
// cluster is a permanent overstatement of the namespace's spend.
func TestCostSkipsTerminatedPods(t *testing.T) {
	pod := func(name, phase string) store.K8sInventoryItem {
		return store.K8sInventoryItem{Kind: "Pod", Namespace: "batch", Name: name, Status: phase,
			StatusObject: map[string]any{"phase": phase},
			Spec: map[string]any{"containers": []any{
				reqContainer("c", map[string]any{"cpu": "1", "memory": "1Gi"})}}}
	}
	items := []store.K8sInventoryItem{pod("live", "Running"), pod("done", "Succeeded")}
	forecast := BuildCostForecast(items, nil, CostPrices{})
	if forecast.TotalPods != 1 || forecast.CostedPods != 1 {
		t.Errorf("forecast counted %d pods (%d costed), want only the running one", forecast.TotalPods, forecast.CostedPods)
	}
	single := BuildCostForecast(items[:1], nil, CostPrices{})
	if forecast.BaselineMonthlyKRW != single.BaselineMonthlyKRW {
		t.Errorf("baseline %v with a finished pod vs %v without — a finished pod costs nothing",
			forecast.BaselineMonthlyKRW, single.BaselineMonthlyKRW)
	}

	report := EstimateCost(items, CostPrices{}, nil, nil, nil)
	if len(report.ByNamespace) != 1 || report.ByNamespace[0].Pods != 1 {
		t.Errorf("namespace rollup = %+v, want 1 billed pod", report.ByNamespace)
	}
}

// qtyMem's suffix table decides how much memory a workload is booked for. Kubernetes'
// decimal set is `k M G T P E` (lowercase k is the only accepted spelling) plus the binary
// Ki..Ei; anything the table misses silently reads as zero bytes, i.e. free.
func TestMemoryQuantitySuffixes(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"512Mi", 512 << 20},
		{"1Gi", 1 << 30},
		{"2Ti", int64(2) << 40},
		{"1Pi", int64(1) << 50},
		{"1Ei", int64(1) << 60},
		{"500k", 500 * 1000},
		{"512K", 512 * 1000}, // tolerated alias
		{"1T", int64(1e12)},
		{"3P", int64(3e15)},
		{"1E", int64(1e18)},
		{"1e9", int64(1e9)}, // decimal exponent, not a suffix
		{"1048576", 1048576},
	}
	for _, tc := range cases {
		if got := qtyMem(tc.in); got != tc.want {
			t.Errorf("qtyMem(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
