package analyzer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"clustara/internal/store"
)

// HPAStatus is one HorizontalPodAutoscaler snapshot (SCALE-01 / SCALE-02).
type HPAStatus struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	TargetKind string `json:"target_kind"`
	TargetName string `json:"target_name"`
	Min        int    `json:"min_replicas"`
	Max        int    `json:"max_replicas"`
	Current    int    `json:"current_replicas"`
	Desired    int    `json:"desired_replicas"`
	AtMax      bool   `json:"at_max"`
}

// AllocFinding flags under- or over-provisioned workloads (SCALE-03 / SCALE-04).
type AllocFinding struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Issue     string `json:"issue"` // under_provisioned | over_provisioned
	Severity  string `json:"severity"`
	CPUUsageM int    `json:"cpu_usage_m"`
	CPUReqM   int    `json:"cpu_request_m"`
	Message   string `json:"message"`
}

// NodePacking summarizes per-node request packing vs allocatable (SCALE-07).
type NodePacking struct {
	Node     string `json:"node"`
	Pods     int    `json:"pods"`
	AllocCPU int    `json:"allocatable_cpu_m"`
	ReqCPU   int    `json:"requested_cpu_m"`
	CPUPct   int    `json:"cpu_request_pct"`
}

// GPUSummary is per-node GPU allocation (SCALE-08).
type GPUSummary struct {
	Node        string `json:"node"`
	Allocatable int    `json:"allocatable_gpu"`
	Requested   int    `json:"requested_gpu"`
	Idle        int    `json:"idle_gpu"`
}

// NodeProjection is a linear capacity forecast for a node from its metric history (SCALE-05).
type NodeProjection struct {
	Node            string  `json:"node"`
	CurrentCPUm     int     `json:"current_cpu_m"`
	AllocCPUm       int     `json:"allocatable_cpu_m"`
	DailyGrowthCPUm int     `json:"daily_growth_cpu_m"`
	DaysToFull      float64 `json:"days_to_full"` // -1 = not growing / unbounded
}

type CapacityReport struct {
	HPAs        []HPAStatus      `json:"hpas"`
	Allocation  []AllocFinding   `json:"allocation"`
	NodePacking []NodePacking    `json:"node_packing"`
	GPU         []GPUSummary     `json:"gpu"`
	Projections []NodeProjection `json:"projections"`
}

// ProjectNodeCapacity fits a simple two-point linear trend (oldest→newest sample) to each node's
// CPU usage and projects days until allocatable is exhausted (SCALE-05). Pure over its inputs.
func ProjectNodeCapacity(items []store.K8sInventoryItem, metrics []store.K8sMetricSample) []NodeProjection {
	allocByNode := map[string]int{}
	for _, it := range items {
		if it.Kind == "Node" {
			allocByNode[it.Name] = qtyCPU(asAnyMap(it.StatusObject["allocatable"])["cpu"])
		}
	}
	byNode := map[string][]store.K8sMetricSample{}
	for _, m := range metrics {
		if m.ResourceKind == "Node" {
			byNode[m.ResourceName] = append(byNode[m.ResourceName], m)
		}
	}
	out := []NodeProjection{}
	for node, samples := range byNode {
		if len(samples) < 2 {
			continue
		}
		sort.SliceStable(samples, func(i, j int) bool { return samples[i].ObservedAt < samples[j].ObservedAt })
		oldest, newest := samples[0], samples[len(samples)-1]
		t0, e0 := time.Parse(time.RFC3339Nano, oldest.ObservedAt)
		t1, e1 := time.Parse(time.RFC3339Nano, newest.ObservedAt)
		if e0 != nil || e1 != nil {
			continue
		}
		days := t1.Sub(t0).Hours() / 24
		proj := NodeProjection{Node: node, CurrentCPUm: int(newest.CPUMillicores), AllocCPUm: allocByNode[node], DaysToFull: -1}
		if days > 0 {
			growth := (newest.CPUMillicores - oldest.CPUMillicores) / days
			proj.DailyGrowthCPUm = int(growth)
			if growth > 0 && proj.AllocCPUm > 0 {
				remaining := float64(proj.AllocCPUm) - newest.CPUMillicores
				if remaining > 0 {
					proj.DaysToFull = round2cap(remaining / growth)
				} else {
					proj.DaysToFull = 0
				}
			}
		}
		out = append(out, proj)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// AnalyzeCapacity computes HPA status, allocation efficiency, node packing and GPU usage from
// the stored inventory (spec + status) and the latest metric samples.
func AnalyzeCapacity(items []store.K8sInventoryItem, metrics []store.K8sMetricSample) CapacityReport {
	rep := CapacityReport{HPAs: []HPAStatus{}, Allocation: []AllocFinding{}, NodePacking: []NodePacking{}, GPU: []GPUSummary{}}

	// Latest metric per Pod (samples arrive newest-first).
	latestPodCPU := map[string]int{}
	seen := map[string]bool{}
	for _, m := range metrics {
		if m.ResourceKind != "Pod" {
			continue
		}
		key := m.Namespace + "/" + m.ResourceName
		if seen[key] {
			continue
		}
		seen[key] = true
		latestPodCPU[key] = int(m.CPUMillicores)
	}

	for _, it := range items {
		switch it.Kind {
		case "HorizontalPodAutoscaler":
			rep.HPAs = append(rep.HPAs, hpaStatus(it))
		case "Pod":
			if f, ok := allocFinding(it, latestPodCPU); ok {
				rep.Allocation = append(rep.Allocation, f)
			}
		}
	}

	rep.NodePacking, rep.GPU = nodePackingAndGPU(items)
	rep.Projections = ProjectNodeCapacity(items, metrics)
	return rep
}

func hpaStatus(it store.K8sInventoryItem) HPAStatus {
	ref := asAnyMap(it.Spec["scaleTargetRef"])
	h := HPAStatus{
		Namespace: it.Namespace, Name: it.Name,
		TargetKind: str(ref["kind"]), TargetName: str(ref["name"]),
		Min:     numVal(it.Spec["minReplicas"]),
		Max:     numVal(it.Spec["maxReplicas"]),
		Current: numVal(it.StatusObject["currentReplicas"]),
		Desired: numVal(it.StatusObject["desiredReplicas"]),
	}
	if h.Max > 0 && h.Desired >= h.Max {
		h.AtMax = true // SCALE-02: sustained ceiling
	}
	return h
}

func allocFinding(pod store.K8sInventoryItem, usageByPod map[string]int) (AllocFinding, bool) {
	reqCPU := podRequestCPU(pod.Spec)
	if reqCPU == 0 {
		return AllocFinding{}, false // no requests set → nothing to compare
	}
	usage, ok := usageByPod[pod.Namespace+"/"+pod.Name]
	if !ok {
		return AllocFinding{}, false
	}
	f := AllocFinding{Namespace: pod.Namespace, Name: pod.Name, Kind: "Pod", CPUUsageM: usage, CPUReqM: reqCPU}
	switch {
	case usage > reqCPU:
		f.Issue, f.Severity = "under_provisioned", "high"
		f.Message = fmt.Sprintf("CPU 사용(%dm)이 request(%dm)를 초과 — request 증설 권고", usage, reqCPU)
		return f, true
	case usage*100 < reqCPU*30: // using <30% of request
		f.Issue, f.Severity = "over_provisioned", "low"
		f.Message = fmt.Sprintf("CPU 사용(%dm)이 request(%dm)의 30%% 미만 — 비용 절감 후보", usage, reqCPU)
		return f, true
	}
	return AllocFinding{}, false
}

func nodePackingAndGPU(items []store.K8sInventoryItem) ([]NodePacking, []GPUSummary) {
	type nodeAgg struct {
		allocCPU, reqCPU int
		allocGPU, reqGPU int
		pods             int
	}
	nodes := map[string]*nodeAgg{}
	for _, it := range items {
		if it.Kind != "Node" {
			continue
		}
		alloc := asAnyMap(it.StatusObject["allocatable"])
		nodes[it.Name] = &nodeAgg{
			allocCPU: qtyCPU(alloc["cpu"]),
			allocGPU: qtyInt(alloc["nvidia.com/gpu"]),
		}
	}
	for _, it := range items {
		if it.Kind != "Pod" {
			continue
		}
		node := str(it.Spec["nodeName"])
		agg := nodes[node]
		if agg == nil {
			continue
		}
		agg.pods++
		agg.reqCPU += podRequestCPU(it.Spec)
		agg.reqGPU += podRequestGPU(it.Spec)
	}
	packing := []NodePacking{}
	gpu := []GPUSummary{}
	for name, agg := range nodes {
		pct := 0
		if agg.allocCPU > 0 {
			pct = agg.reqCPU * 100 / agg.allocCPU
		}
		packing = append(packing, NodePacking{Node: name, Pods: agg.pods, AllocCPU: agg.allocCPU, ReqCPU: agg.reqCPU, CPUPct: pct})
		if agg.allocGPU > 0 || agg.reqGPU > 0 {
			gpu = append(gpu, GPUSummary{Node: name, Allocatable: agg.allocGPU, Requested: agg.reqGPU, Idle: agg.allocGPU - agg.reqGPU})
		}
	}
	return packing, gpu
}

// --- pod request extraction ---

func podContainers(spec map[string]any) []any {
	ps := spec
	if tmpl := asAnyMap(spec["template"]); tmpl != nil {
		if inner := asAnyMap(tmpl["spec"]); inner != nil {
			ps = inner
		}
	}
	return append(asAnySlice(ps["containers"]), asAnySlice(ps["initContainers"])...)
}

func podRequestCPU(spec map[string]any) int {
	total := 0
	for _, raw := range podContainers(spec) {
		req := asAnyMap(asAnyMap(asAnyMap(raw)["resources"])["requests"])
		total += qtyCPU(req["cpu"])
	}
	return total
}

func podRequestMemBytes(spec map[string]any) int64 {
	var total int64
	for _, raw := range podContainers(spec) {
		req := asAnyMap(asAnyMap(asAnyMap(raw)["resources"])["requests"])
		total += qtyMem(req["memory"])
	}
	return total
}

// qtyMem parses a Kubernetes memory quantity (e.g. "256Mi", "1Gi", 1048576) into bytes.
func qtyMem(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		units := []struct {
			suf string
			mul int64
		}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}}
		for _, u := range units {
			if strings.HasSuffix(s, u.suf) {
				f, _ := strconv.ParseFloat(strings.TrimSuffix(s, u.suf), 64)
				return int64(f * float64(u.mul))
			}
		}
		f, _ := strconv.ParseFloat(s, 64)
		return int64(f)
	}
	return 0
}

func podRequestGPU(spec map[string]any) int {
	total := 0
	for _, raw := range podContainers(spec) {
		req := asAnyMap(asAnyMap(asAnyMap(raw)["resources"])["requests"])
		total += qtyInt(req["nvidia.com/gpu"])
	}
	return total
}

// ScaleSimulation is the projected resource request total for a target replica count (SCALE-06).
type ScaleSimulation struct {
	CurrentReplicas int     `json:"current_replicas"`
	TargetReplicas  int     `json:"target_replicas"`
	PerReplicaCPUm  int     `json:"per_replica_cpu_m"`
	PerReplicaMemGB float64 `json:"per_replica_mem_gb"`
	TotalCPUm       int     `json:"total_cpu_m"`
	TotalMemGB      float64 `json:"total_mem_gb"`
	DeltaCPUm       int     `json:"delta_cpu_m"`
	DeltaMemGB      float64 `json:"delta_mem_gb"`
}

// SimulateScale computes the request totals if a workload is scaled to targetReplicas, from its
// per-pod requests (SCALE-06). spec is the workload spec (with .template.spec).
func SimulateScale(spec map[string]any, current, target int) ScaleSimulation {
	perCPU := podRequestCPU(spec)
	perMemBytes := podRequestMemBytes(spec)
	perMemGB := float64(perMemBytes) / float64(1<<30)
	if current < 0 {
		current = 0
	}
	if target < 0 {
		target = 0
	}
	return ScaleSimulation{
		CurrentReplicas: current,
		TargetReplicas:  target,
		PerReplicaCPUm:  perCPU,
		PerReplicaMemGB: round2cap(perMemGB),
		TotalCPUm:       perCPU * target,
		TotalMemGB:      round2cap(perMemGB * float64(target)),
		DeltaCPUm:       perCPU * (target - current),
		DeltaMemGB:      round2cap(perMemGB * float64(target-current)),
	}
}

func round2cap(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// qtyCPU parses a Kubernetes CPU quantity (e.g. "100m", "1", 1) into millicores.
func qtyCPU(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t * 1000)
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		if strings.HasSuffix(s, "m") {
			n, _ := strconv.Atoi(strings.TrimSuffix(s, "m"))
			return n
		}
		f, _ := strconv.ParseFloat(s, 64)
		return int(f * 1000)
	}
	return 0
}

// qtyInt parses an integer-ish quantity (e.g. GPU count "1" or 1).
func qtyInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	}
	return 0
}
