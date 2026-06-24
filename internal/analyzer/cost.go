package analyzer

import (
	"sort"

	"clustara/internal/store"
)

// CostPrices are the unit prices used to estimate workload cost from resource requests
// (DW-08 / 비용 대시보드). Kubernetes has no native cost, so this is a request-based model.
type CostPrices struct {
	CPUCoreMonthlyKRW float64 `json:"cpu_core_monthly_krw"`
	MemGBMonthlyKRW   float64 `json:"mem_gb_monthly_krw"`
}

// DefaultCostPrices is a conservative starting point; operators override via config.
var DefaultCostPrices = CostPrices{CPUCoreMonthlyKRW: 30000, MemGBMonthlyKRW: 4000}

type CostLine struct {
	Key        string  `json:"key"`
	CPUCores   float64 `json:"cpu_cores"`
	MemGB      float64 `json:"mem_gb"`
	Pods       int     `json:"pods"`
	MonthlyKRW float64 `json:"monthly_krw"`
}

type CostReport struct {
	TotalMonthlyKRW float64    `json:"total_monthly_krw"`
	ByNamespace     []CostLine `json:"by_namespace"`
	ByTeam          []CostLine `json:"by_team"`
	ByGroup         []CostLine `json:"by_group"`
	ByCostCenter    []CostLine `json:"by_cost_center"`
	Prices          CostPrices `json:"prices"`
}

// EstimateCost estimates monthly cost per Pod from CPU/memory requests and rolls it up by
// namespace, owning team, cluster group and cost center. The lookup maps are keyed:
//   nsTeam / nsCostCenter: "<clusterID>|<namespace>" -> value
//   clusterGroup:          "<clusterID>"            -> group name
func EstimateCost(items []store.K8sInventoryItem, prices CostPrices, nsTeam, nsCostCenter, clusterGroup map[string]string) CostReport {
	if prices.CPUCoreMonthlyKRW == 0 && prices.MemGBMonthlyKRW == 0 {
		prices = DefaultCostPrices
	}
	type agg struct {
		cpu, mem, krw float64
		pods          int
	}
	ns := map[string]*agg{}
	team := map[string]*agg{}
	group := map[string]*agg{}
	cc := map[string]*agg{}
	add := func(m map[string]*agg, key string, cores, memGB, krw float64) {
		if key == "" {
			key = "(미지정)"
		}
		a := m[key]
		if a == nil {
			a = &agg{}
			m[key] = a
		}
		a.cpu += cores
		a.mem += memGB
		a.krw += krw
		a.pods++
	}

	total := 0.0
	for _, it := range items {
		if it.Kind != "Pod" {
			continue
		}
		cores := float64(podRequestCPU(it.Spec)) / 1000.0
		memGB := float64(podRequestMemBytes(it.Spec)) / float64(1<<30)
		krw := cores*prices.CPUCoreMonthlyKRW + memGB*prices.MemGBMonthlyKRW
		if krw == 0 {
			continue // no requests → not costed
		}
		total += krw
		add(ns, it.Namespace, cores, memGB, krw)
		add(team, nsTeam[it.ClusterID+"|"+it.Namespace], cores, memGB, krw)
		add(group, clusterGroup[it.ClusterID], cores, memGB, krw)
		add(cc, nsCostCenter[it.ClusterID+"|"+it.Namespace], cores, memGB, krw)
	}

	toLines := func(m map[string]*agg) []CostLine {
		out := []CostLine{}
		for k, a := range m {
			out = append(out, CostLine{Key: k, CPUCores: round2(a.cpu), MemGB: round2(a.mem), Pods: a.pods, MonthlyKRW: round2(a.krw)})
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].MonthlyKRW > out[j].MonthlyKRW })
		return out
	}

	return CostReport{
		TotalMonthlyKRW: round2(total),
		ByNamespace:     toLines(ns),
		ByTeam:          toLines(team),
		ByGroup:         toLines(group),
		ByCostCenter:    toLines(cc),
		Prices:          prices,
	}
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
