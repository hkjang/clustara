package analyzer

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"clustara/internal/store"
)

// CostPrices are the unit prices used to estimate workload cost from resource requests
// (DW-08 / 비용 대시보드). Kubernetes has no native cost, so this is a request-based model.
type CostPrices struct {
	CPUCoreMonthlyKRW   float64            `json:"cpu_core_monthly_krw"`
	MemGBMonthlyKRW     float64            `json:"mem_gb_monthly_krw"`
	StorageGBMonthlyKRW float64            `json:"storage_gb_monthly_krw"`
	GPUUnitMonthlyKRW   float64            `json:"gpu_unit_monthly_krw"`
	USDKRW              float64            `json:"usd_krw"`
	GPUModelHourlyUSD   map[string]float64 `json:"gpu_model_hourly_usd"`
}

// DefaultCostPrices is a conservative starting point; operators override via config.
var DefaultGPUModelHourlyUSD = map[string]float64{"l40s": 1.75, "h100": 4.55, "h200": 5.93, "b200": 8.64, "b300": 9.98}
var DefaultCostPrices = CostPrices{CPUCoreMonthlyKRW: 30000, MemGBMonthlyKRW: 4000, StorageGBMonthlyKRW: 150, GPUUnitMonthlyKRW: 700000, USDKRW: 1400, GPUModelHourlyUSD: DefaultGPUModelHourlyUSD}

type CostLine struct {
	Key        string  `json:"key"`
	CPUCores   float64 `json:"cpu_cores"`
	MemGB      float64 `json:"mem_gb"`
	StorageGB  float64 `json:"storage_gb"`
	GPUUnits   float64 `json:"gpu_units"`
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

// CostForecast separates the request-based allocation baseline from a usage-adjusted scenario.
// UsageAdjustedMonthlyKRW uses the latest observed Pod usage with 30% reliability headroom for
// covered Pods and keeps request cost for uncovered Pods. It is an operational forecast, not a bill.
type CostForecast struct {
	BaselineMonthlyKRW      float64                 `json:"baseline_monthly_krw"`
	UsageAdjustedMonthlyKRW float64                 `json:"usage_adjusted_monthly_krw"`
	CPUCostMonthlyKRW       float64                 `json:"cpu_cost_monthly_krw"`
	MemoryCostMonthlyKRW    float64                 `json:"memory_cost_monthly_krw"`
	StorageCostMonthlyKRW   float64                 `json:"storage_cost_monthly_krw"`
	GPUCostMonthlyKRW       float64                 `json:"gpu_cost_monthly_krw"`
	GPUModels               map[string]GPUModelCost `json:"gpu_models"`
	MetricCoveragePct       float64                 `json:"metric_coverage_pct"`
	RequestCoveragePct      float64                 `json:"request_coverage_pct"`
	ConfidenceScore         int                     `json:"confidence_score"`
	ConfidenceLevel         string                  `json:"confidence_level"`
	TotalPods               int                     `json:"total_pods"`
	CostedPods              int                     `json:"costed_pods"`
	MetricCoveredPods       int                     `json:"metric_covered_pods"`
	UncostedPods            int                     `json:"uncosted_pods"`
	HeadroomPct             int                     `json:"headroom_pct"`
	Method                  string                  `json:"method"`
}

type GPUModelCost struct {
	Model      string  `json:"model"`
	Units      float64 `json:"units"`
	HourlyUSD  float64 `json:"hourly_usd"`
	MonthlyKRW float64 `json:"monthly_krw"`
}

func BuildCostForecast(items []store.K8sInventoryItem, metrics []store.K8sMetricSample, prices CostPrices) CostForecast {
	prices = normalizedCostPrices(prices)
	latest := map[string]store.K8sMetricSample{}
	for _, sample := range metrics { // store returns newest first
		if sample.ResourceKind != "Pod" {
			continue
		}
		key := sample.ClusterID + "|" + sample.Namespace + "|" + sample.ResourceName
		if _, exists := latest[key]; !exists {
			latest[key] = sample
		}
	}
	forecast := CostForecast{HeadroomPct: 30, Method: "CPU/Memory requests + model-aware GPU hourly price × 730 + PVC storage; CPU/Memory latest usage with 30% reliability headroom", GPUModels: map[string]GPUModelCost{}}
	nodeModels := gpuNodeModels(items)
	adjusted := 0.0
	for _, item := range items {
		if item.Kind == "PersistentVolumeClaim" {
			storageGB := pvcStorageBytes(item.Spec) / float64(1<<30)
			cost := storageGB * prices.StorageGBMonthlyKRW
			forecast.StorageCostMonthlyKRW += cost
			adjusted += cost
			continue
		}
		if item.Kind != "Pod" {
			continue
		}
		forecast.TotalPods++
		reqCPU := float64(podRequestCPU(item.Spec)) / 1000
		reqMem := float64(podRequestMemBytes(item.Spec)) / float64(1<<30)
		cpuCost, memCost := reqCPU*prices.CPUCoreMonthlyKRW, reqMem*prices.MemGBMonthlyKRW
		gpuUnits := float64(podRequestGPU(item.Spec))
		gpuModel := podGPUModel(item, nodeModels)
		gpuHourly, gpuMonthlyUnit := gpuModelPrice(prices, gpuModel)
		gpuCost := gpuUnits * gpuMonthlyUnit
		requestCost := cpuCost + memCost + gpuCost
		if requestCost <= 0 {
			forecast.UncostedPods++
			continue
		}
		forecast.CostedPods++
		forecast.CPUCostMonthlyKRW += cpuCost
		forecast.MemoryCostMonthlyKRW += memCost
		forecast.GPUCostMonthlyKRW += gpuCost
		if gpuUnits > 0 {
			row := forecast.GPUModels[gpuModel]
			row.Model, row.Units, row.HourlyUSD, row.MonthlyKRW = gpuModel, row.Units+gpuUnits, gpuHourly, row.MonthlyKRW+gpuCost
			forecast.GPUModels[gpuModel] = row
		}
		key := item.ClusterID + "|" + item.Namespace + "|" + item.Name
		if usage, ok := latest[key]; ok {
			forecast.MetricCoveredPods++
			adjusted += usage.CPUMillicores/1000*1.3*prices.CPUCoreMonthlyKRW + usage.MemoryBytes/float64(1<<30)*1.3*prices.MemGBMonthlyKRW + gpuCost
		} else {
			adjusted += requestCost
		}
	}
	forecast.BaselineMonthlyKRW = round2(forecast.CPUCostMonthlyKRW + forecast.MemoryCostMonthlyKRW + forecast.StorageCostMonthlyKRW + forecast.GPUCostMonthlyKRW)
	forecast.UsageAdjustedMonthlyKRW = round2(adjusted)
	forecast.CPUCostMonthlyKRW = round2(forecast.CPUCostMonthlyKRW)
	forecast.MemoryCostMonthlyKRW = round2(forecast.MemoryCostMonthlyKRW)
	forecast.StorageCostMonthlyKRW = round2(forecast.StorageCostMonthlyKRW)
	forecast.GPUCostMonthlyKRW = round2(forecast.GPUCostMonthlyKRW)
	for key, row := range forecast.GPUModels {
		row.Units, row.MonthlyKRW = round2(row.Units), round2(row.MonthlyKRW)
		forecast.GPUModels[key] = row
	}
	if forecast.CostedPods > 0 {
		forecast.MetricCoveragePct = round2(float64(forecast.MetricCoveredPods) / float64(forecast.CostedPods) * 100)
	}
	if forecast.TotalPods > 0 {
		forecast.RequestCoveragePct = round2(float64(forecast.CostedPods) / float64(forecast.TotalPods) * 100)
	}
	forecast.ConfidenceScore = int(math.Round(forecast.MetricCoveragePct*0.7 + forecast.RequestCoveragePct*0.3))
	switch {
	case forecast.ConfidenceScore >= 80:
		forecast.ConfidenceLevel = "high"
	case forecast.ConfidenceScore >= 50:
		forecast.ConfidenceLevel = "medium"
	default:
		forecast.ConfidenceLevel = "low"
	}
	return forecast
}

// EstimateCost estimates monthly cost per Pod from CPU/memory requests and rolls it up by
// namespace, owning team, cluster group and cost center. The lookup maps are keyed:
//
//	nsTeam / nsCostCenter: "<clusterID>|<namespace>" -> value
//	clusterGroup:          "<clusterID>"            -> group name
func EstimateCost(items []store.K8sInventoryItem, prices CostPrices, nsTeam, nsCostCenter, clusterGroup map[string]string) CostReport {
	prices = normalizedCostPrices(prices)
	type agg struct {
		cpu, mem, storage, gpu, krw float64
		pods                        int
	}
	ns := map[string]*agg{}
	team := map[string]*agg{}
	group := map[string]*agg{}
	cc := map[string]*agg{}
	add := func(m map[string]*agg, key string, cores, memGB, storageGB, gpu, krw float64, pods int) {
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
		a.storage += storageGB
		a.gpu += gpu
		a.krw += krw
		a.pods += pods
	}

	total := 0.0
	nodeModels := gpuNodeModels(items)
	for _, it := range items {
		cores, memGB, storageGB, gpu, pods := 0.0, 0.0, 0.0, 0.0, 0
		switch it.Kind {
		case "Pod":
			cores = float64(podRequestCPU(it.Spec)) / 1000.0
			memGB = float64(podRequestMemBytes(it.Spec)) / float64(1<<30)
			gpu = float64(podRequestGPU(it.Spec))
			pods = 1
		case "PersistentVolumeClaim":
			storageGB = pvcStorageBytes(it.Spec) / float64(1<<30)
		default:
			continue
		}
		_, gpuMonthlyUnit := gpuModelPrice(prices, podGPUModel(it, nodeModels))
		krw := cores*prices.CPUCoreMonthlyKRW + memGB*prices.MemGBMonthlyKRW + storageGB*prices.StorageGBMonthlyKRW + gpu*gpuMonthlyUnit
		if krw == 0 {
			continue // no requests → not costed
		}
		total += krw
		add(ns, it.Namespace, cores, memGB, storageGB, gpu, krw, pods)
		add(team, nsTeam[it.ClusterID+"|"+it.Namespace], cores, memGB, storageGB, gpu, krw, pods)
		add(group, clusterGroup[it.ClusterID], cores, memGB, storageGB, gpu, krw, pods)
		add(cc, nsCostCenter[it.ClusterID+"|"+it.Namespace], cores, memGB, storageGB, gpu, krw, pods)
	}

	toLines := func(m map[string]*agg) []CostLine {
		out := []CostLine{}
		for k, a := range m {
			out = append(out, CostLine{Key: k, CPUCores: round2(a.cpu), MemGB: round2(a.mem), StorageGB: round2(a.storage), GPUUnits: round2(a.gpu), Pods: a.pods, MonthlyKRW: round2(a.krw)})
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

func normalizedCostPrices(prices CostPrices) CostPrices {
	if prices.CPUCoreMonthlyKRW <= 0 {
		prices.CPUCoreMonthlyKRW = DefaultCostPrices.CPUCoreMonthlyKRW
	}
	if prices.MemGBMonthlyKRW <= 0 {
		prices.MemGBMonthlyKRW = DefaultCostPrices.MemGBMonthlyKRW
	}
	if prices.StorageGBMonthlyKRW <= 0 {
		prices.StorageGBMonthlyKRW = DefaultCostPrices.StorageGBMonthlyKRW
	}
	if prices.GPUUnitMonthlyKRW <= 0 {
		prices.GPUUnitMonthlyKRW = DefaultCostPrices.GPUUnitMonthlyKRW
	}
	if prices.USDKRW <= 0 {
		prices.USDKRW = DefaultCostPrices.USDKRW
	}
	if len(prices.GPUModelHourlyUSD) == 0 {
		prices.GPUModelHourlyUSD = map[string]float64{}
		for key, value := range DefaultGPUModelHourlyUSD {
			prices.GPUModelHourlyUSD[key] = value
		}
	}
	return prices
}

func gpuModelPrice(prices CostPrices, model string) (float64, float64) {
	model = normalizeGPUModel(model)
	if hourly := prices.GPUModelHourlyUSD[model]; hourly > 0 {
		return hourly, hourly * 730 * prices.USDKRW
	}
	return 0, prices.GPUUnitMonthlyKRW
}

func gpuNodeModels(items []store.K8sInventoryItem) map[string]string {
	out := map[string]string{}
	for _, item := range items {
		if item.Kind != "Node" {
			continue
		}
		for _, key := range []string{"nvidia.com/gpu.product", "gpu.nvidia.com/model", "accelerator"} {
			if value := normalizeGPUModel(item.Labels[key]); value != "unknown" {
				out[item.ClusterID+"|"+item.Name] = value
				break
			}
		}
	}
	return out
}

func podGPUModel(item store.K8sInventoryItem, nodeModels map[string]string) string {
	for _, key := range []string{"nvidia.com/gpu.product", "gpu.nvidia.com/model", "accelerator"} {
		if value := normalizeGPUModel(item.Labels[key]); value != "unknown" {
			return value
		}
	}
	if selector, ok := item.Spec["nodeSelector"].(map[string]any); ok {
		for _, key := range []string{"nvidia.com/gpu.product", "gpu.nvidia.com/model", "accelerator"} {
			if value := normalizeGPUModel(fmt.Sprint(selector[key])); value != "unknown" {
				return value
			}
		}
	}
	if node := strings.TrimSpace(fmt.Sprint(item.Spec["nodeName"])); node != "" {
		if model := nodeModels[item.ClusterID+"|"+node]; model != "" {
			return model
		}
	}
	return "unknown"
}

func normalizeGPUModel(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(v, "b300"):
		return "b300"
	case strings.Contains(v, "b200"):
		return "b200"
	case strings.Contains(v, "h200"):
		return "h200"
	case strings.Contains(v, "h100"):
		return "h100"
	case strings.Contains(v, "l40s") || strings.Contains(v, "l40-s"):
		return "l40s"
	default:
		return "unknown"
	}
}

func pvcStorageBytes(spec map[string]any) float64 {
	resources, _ := spec["resources"].(map[string]any)
	requests, _ := resources["requests"].(map[string]any)
	return float64(qtyMem(requests["storage"]))
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
