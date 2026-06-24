package analyzer

import (
	"sort"

	"clustara/internal/store"
)

// RightsizingRec recommends a right-sized CPU/memory request for a workload based on actual
// usage vs the configured request, plus the monthly KRW saving when downsizing (FinOps).
type RightsizingRec struct {
	Namespace         string  `json:"namespace"`
	Name              string  `json:"name"`
	Direction         string  `json:"direction"` // down (절감) | up (안정성)
	CurrentCPUm       int     `json:"current_cpu_m"`
	UsageCPUm         int     `json:"usage_cpu_m"`
	RecommendedCPUm   int     `json:"recommended_cpu_m"`
	CurrentMemMB      int64   `json:"current_mem_mb"`
	UsageMemMB        int64   `json:"usage_mem_mb"`
	RecommendedMemMB  int64   `json:"recommended_mem_mb"`
	MonthlySavingsKRW float64 `json:"monthly_savings_krw"`
}

const rightsizeHeadroom = 1.3 // recommend usage + 30% headroom

// RecommendRightsizing compares each Pod's request to its latest CPU/memory usage and recommends
// a right-sized request (usage × 1.3), with the monthly saving for downsizes. Pure over inputs.
func RecommendRightsizing(items []store.K8sInventoryItem, metrics []store.K8sMetricSample, prices CostPrices) []RightsizingRec {
	if prices.CPUCoreMonthlyKRW == 0 && prices.MemGBMonthlyKRW == 0 {
		prices = DefaultCostPrices
	}
	type usage struct {
		cpu float64 // millicores
		mem float64 // bytes
	}
	latest := map[string]usage{}
	seen := map[string]bool{}
	for _, m := range metrics { // samples are newest-first
		if m.ResourceKind != "Pod" {
			continue
		}
		k := m.Namespace + "/" + m.ResourceName
		if seen[k] {
			continue
		}
		seen[k] = true
		latest[k] = usage{cpu: m.CPUMillicores, mem: m.MemoryBytes}
	}

	const mib = 1 << 20
	out := []RightsizingRec{}
	for _, it := range items {
		if it.Kind != "Pod" {
			continue
		}
		reqCPU := podRequestCPU(it.Spec)
		reqMem := podRequestMemBytes(it.Spec)
		if reqCPU == 0 && reqMem == 0 {
			continue
		}
		u, ok := latest[it.Namespace+"/"+it.Name]
		if !ok {
			continue
		}
		recCPU := int(u.cpu * rightsizeHeadroom)
		recMem := int64(u.mem * rightsizeHeadroom)

		cpuCut := reqCPU - recCPU
		memCut := reqMem - recMem
		savings := 0.0
		if reqCPU > 0 && cpuCut > 0 {
			savings += float64(cpuCut) / 1000.0 * prices.CPUCoreMonthlyKRW
		}
		if reqMem > 0 && memCut > 0 {
			savings += float64(memCut) / float64(1<<30) * prices.MemGBMonthlyKRW
		}

		// Reliability first: if usage exceeds request on ANY resource it is under-provisioned
		// (upsize) — never recommend a downsize/saving when something is starved. Otherwise, if
		// the cut is meaningful (>=10% on a set resource) recommend a downsize.
		meaningfulDown := (reqCPU > 0 && cpuCut*10 >= reqCPU) || (reqMem > 0 && memCut*10 >= reqMem)
		direction := ""
		switch {
		case (reqCPU > 0 && int(u.cpu) > reqCPU) || (reqMem > 0 && int64(u.mem) > reqMem):
			direction = "up"
			savings = 0
		case savings > 0 && meaningfulDown:
			direction = "down"
		default:
			continue // well-sized
		}
		out = append(out, RightsizingRec{
			Namespace: it.Namespace, Name: it.Name, Direction: direction,
			CurrentCPUm: reqCPU, UsageCPUm: int(u.cpu), RecommendedCPUm: recCPU,
			CurrentMemMB: reqMem / mib, UsageMemMB: int64(u.mem) / mib, RecommendedMemMB: recMem / mib,
			MonthlySavingsKRW: round2(savings),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].MonthlySavingsKRW > out[j].MonthlySavingsKRW })
	return out
}
