package analyzer

import (
	"math"
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
//
//	nsTeam / nsCostCenter: "<clusterID>|<namespace>" -> value
//	clusterGroup:          "<clusterID>"            -> group name
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
	return math.Round(f*100) / 100
}

// CostTrendLine is the day-over-day change for one cost dimension key (DW-08 비용 증가).
type CostTrendLine struct {
	Key       string  `json:"key"`
	Current   float64 `json:"current_krw"`
	Previous  float64 `json:"previous_krw"`
	Delta     float64 `json:"delta_krw"`
	PctChange float64 `json:"pct_change"`
}

// ComputeCostTrend turns daily cost snapshots into per-key day-over-day deltas, sorted by the
// largest increase first. Input may be in any order; the two most recent distinct days per key
// are compared. Pure + testable.
func ComputeCostTrend(snapshots []store.K8sCostSnapshot) []CostTrendLine {
	type dayVal struct {
		day string
		krw float64
	}
	byKey := map[string][]dayVal{}
	for _, s := range snapshots {
		byKey[s.Key] = append(byKey[s.Key], dayVal{s.Day, s.MonthlyKRW})
	}
	out := []CostTrendLine{}
	for key, vals := range byKey {
		sort.SliceStable(vals, func(i, j int) bool { return vals[i].day > vals[j].day }) // newest day first
		cur := vals[0]
		var prev dayVal
		hasPrev := false
		for _, v := range vals[1:] {
			if v.day != cur.day {
				prev = v
				hasPrev = true
				break
			}
		}
		line := CostTrendLine{Key: key, Current: round2(cur.krw)}
		if hasPrev {
			line.Previous = round2(prev.krw)
			line.Delta = round2(cur.krw - prev.krw)
			if prev.krw > 0 {
				line.PctChange = round2((cur.krw - prev.krw) / prev.krw * 100)
			} else if cur.krw > 0 {
				line.PctChange = 100
			}
		}
		out = append(out, line)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Delta > out[j].Delta })
	return out
}
