package analyzer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

// NodeMonitoringReport is an operator-facing view of actual node usage, capacity allocation and
// explainable early-warning signals. Predictions estimate resource-threshold crossings; they are
// deliberately not presented as guarantees of a node failure time.
type NodeMonitoringReport struct {
	GeneratedAt string                `json:"generated_at"`
	Summary     NodeMonitoringSummary `json:"summary"`
	Nodes       []NodeMonitor         `json:"nodes"`
}

type NodeMonitoringSummary struct {
	Total             int     `json:"total"`
	Healthy           int     `json:"healthy"`
	Warning           int     `json:"warning"`
	High              int     `json:"high"`
	Critical          int     `json:"critical"`
	Unknown           int     `json:"unknown"`
	NotReady          int     `json:"not_ready"`
	MetricCoveragePct float64 `json:"metric_coverage_pct"`
	GPUNodeCount      int     `json:"gpu_node_count"`
	GPUObservedCount  int     `json:"gpu_observed_count"`
}

type NodeMonitor struct {
	ClusterID      string              `json:"cluster_id"`
	Name           string              `json:"name"`
	Role           string              `json:"role"`
	Ready          bool                `json:"ready"`
	ReadyStatus    string              `json:"ready_status"`
	Unschedulable  bool                `json:"unschedulable"`
	Pressure       []string            `json:"pressure"`
	CPU            NodeResourceUsage   `json:"cpu"`
	Memory         NodeResourceUsage   `json:"memory"`
	GPU            NodeGPUUsage        `json:"gpu"`
	Risk           NodeRiskAssessment  `json:"risk"`
	Prediction     *NodeRiskPrediction `json:"prediction,omitempty"`
	WarningEvents  int                 `json:"warning_events_24h"`
	LastWarningAt  string              `json:"last_warning_at,omitempty"`
	MetricAgeSec   int64               `json:"metric_age_seconds"`
	MetricsPresent bool                `json:"metrics_present"`
	Series         []NodeMetricPoint   `json:"series"`
}

type NodeResourceUsage struct {
	Used         float64 `json:"used"`
	Capacity     float64 `json:"capacity"`
	Percent      float64 `json:"percent"`
	PeakPercent  float64 `json:"peak_percent"`
	TrendPerHour float64 `json:"trend_per_hour"`
	ObservedAt   string  `json:"observed_at,omitempty"`
	Available    bool    `json:"available"`
}

type NodeGPUUsage struct {
	Capacity        int      `json:"capacity"`
	Allocatable     int      `json:"allocatable"`
	Requested       int      `json:"requested"`
	Available       int      `json:"available"`
	AllocationPct   float64  `json:"allocation_pct"`
	UtilizationPct  *float64 `json:"utilization_pct,omitempty"`
	MemoryUsedBytes *float64 `json:"memory_used_bytes,omitempty"`
	TemperatureC    *float64 `json:"temperature_c,omitempty"`
	ObservedAt      string   `json:"observed_at,omitempty"`
	Source          string   `json:"source"` // inventory_allocation | dcgm_exporter
}

type NodeMetricPoint struct {
	ObservedAt string   `json:"observed_at"`
	CPUPct     *float64 `json:"cpu_pct,omitempty"`
	MemoryPct  *float64 `json:"memory_pct,omitempty"`
	GPUPct     *float64 `json:"gpu_pct,omitempty"`
}

type NodeRiskAssessment struct {
	Score   int              `json:"score"`
	Level   string           `json:"level"` // healthy | warning | high | critical | unknown
	Summary string           `json:"summary"`
	Signals []NodeRiskSignal `json:"signals"`
}

type NodeRiskSignal struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type NodeRiskPrediction struct {
	Resource   string  `json:"resource"`
	Threshold  float64 `json:"threshold_pct"`
	ExpectedAt string  `json:"expected_at"`
	Hours      float64 `json:"hours_to_threshold"`
	Confidence string  `json:"confidence"`
	Basis      string  `json:"basis"`
}

type nodeMetricBucket struct {
	time time.Time
	cpu  *float64
	mem  *float64
	gpu  *float64
}

// AnalyzeNodeMonitoring builds per-node monitoring and risk views. metricBucket controls response
// density only; risk calculations remain based on every returned bucket.
func AnalyzeNodeMonitoring(items []store.K8sInventoryItem, metrics []store.K8sMetricSample, events []store.K8sEvent, now time.Time, metricBucket time.Duration) NodeMonitoringReport {
	if metricBucket <= 0 {
		metricBucket = 5 * time.Minute
	}
	report := NodeMonitoringReport{GeneratedAt: now.UTC().Format(time.RFC3339Nano), Nodes: []NodeMonitor{}}
	nodes := map[string]store.K8sInventoryItem{}
	gpuRequested := map[string]int{}
	for _, item := range items {
		key := nodeKey(item.ClusterID, item.Name)
		switch strings.ToLower(item.Kind) {
		case "node":
			nodes[key] = item
		case "pod":
			nodeName := strings.TrimSpace(str(item.Spec["nodeName"]))
			if nodeName != "" {
				gpuRequested[nodeKey(item.ClusterID, nodeName)] += podGPURequests(item.Spec)
			}
		}
	}
	metricsByNode := map[string][]store.K8sMetricSample{}
	for _, metric := range metrics {
		if !strings.EqualFold(metric.ResourceKind, "Node") {
			continue
		}
		metricsByNode[nodeKey(metric.ClusterID, metric.ResourceName)] = append(metricsByNode[nodeKey(metric.ClusterID, metric.ResourceName)], metric)
	}
	eventsByNode := map[string][]store.K8sEvent{}
	for _, event := range events {
		if strings.EqualFold(event.InvolvedKind, "Node") {
			eventsByNode[nodeKey(event.ClusterID, event.InvolvedName)] = append(eventsByNode[nodeKey(event.ClusterID, event.InvolvedName)], event)
		}
	}

	covered := 0
	for key, item := range nodes {
		monitor := buildNodeMonitor(item, gpuRequested[key], metricsByNode[key], eventsByNode[key], now.UTC(), metricBucket)
		if monitor.MetricsPresent {
			covered++
		}
		report.Nodes = append(report.Nodes, monitor)
		report.Summary.Total++
		if !monitor.Ready {
			report.Summary.NotReady++
		}
		if monitor.GPU.Allocatable > 0 {
			report.Summary.GPUNodeCount++
		}
		if monitor.GPU.UtilizationPct != nil {
			report.Summary.GPUObservedCount++
		}
		switch monitor.Risk.Level {
		case "critical":
			report.Summary.Critical++
		case "high":
			report.Summary.High++
		case "warning":
			report.Summary.Warning++
		case "unknown":
			report.Summary.Unknown++
		default:
			report.Summary.Healthy++
		}
	}
	if report.Summary.Total > 0 {
		report.Summary.MetricCoveragePct = roundNode(float64(covered) * 100 / float64(report.Summary.Total))
	}
	sort.SliceStable(report.Nodes, func(i, j int) bool {
		if report.Nodes[i].Risk.Score != report.Nodes[j].Risk.Score {
			return report.Nodes[i].Risk.Score > report.Nodes[j].Risk.Score
		}
		if report.Nodes[i].ClusterID != report.Nodes[j].ClusterID {
			return report.Nodes[i].ClusterID < report.Nodes[j].ClusterID
		}
		return report.Nodes[i].Name < report.Nodes[j].Name
	})
	return report
}

func buildNodeMonitor(item store.K8sInventoryItem, requestedGPU int, samples []store.K8sMetricSample, events []store.K8sEvent, now time.Time, bucketSize time.Duration) NodeMonitor {
	alloc := asAnyMap(item.StatusObject["allocatable"])
	capacity := asAnyMap(item.StatusObject["capacity"])
	cpuCapacity := float64(qtyCPU(alloc["cpu"]))
	memCapacity := float64(qtyMem(alloc["memory"]))
	readyStatus, pressures := nodeConditionState(item)
	monitor := NodeMonitor{
		ClusterID: item.ClusterID, Name: item.Name, Role: nodeRole(item.Labels),
		Ready: readyStatus == "Ready", ReadyStatus: readyStatus,
		Unschedulable: boolValue(item.Spec["unschedulable"]), Pressure: pressures,
		MetricAgeSec: -1, Series: []NodeMetricPoint{},
	}
	monitor.GPU = nodeGPUInventory(capacity, alloc, requestedGPU)

	sort.SliceStable(samples, func(i, j int) bool { return samples[i].ObservedAt < samples[j].ObservedAt })
	buckets := map[int64]*nodeMetricBucket{}
	var latestCore *store.K8sMetricSample
	var latestGPU *store.K8sMetricSample
	for i := range samples {
		sample := &samples[i]
		ts, err := time.Parse(time.RFC3339Nano, sample.ObservedAt)
		if err != nil {
			continue
		}
		bucketTS := ts.Truncate(bucketSize)
		bucket := buckets[bucketTS.UnixNano()]
		if bucket == nil {
			bucket = &nodeMetricBucket{time: bucketTS}
			buckets[bucketTS.UnixNano()] = bucket
		}
		if sample.GPUObserved {
			v := roundNode(sample.GPUUtilizationPct)
			bucket.gpu = &v
			latestGPU = sample
			continue
		}
		if cpuCapacity > 0 {
			v := roundNode(sample.CPUMillicores * 100 / cpuCapacity)
			bucket.cpu = &v
		}
		if memCapacity > 0 {
			v := roundNode(sample.MemoryBytes * 100 / memCapacity)
			bucket.mem = &v
		}
		latestCore = sample
	}
	ordered := make([]*nodeMetricBucket, 0, len(buckets))
	for _, bucket := range buckets {
		ordered = append(ordered, bucket)
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].time.Before(ordered[j].time) })
	for _, bucket := range ordered {
		monitor.Series = append(monitor.Series, NodeMetricPoint{
			ObservedAt: bucket.time.UTC().Format(time.RFC3339Nano), CPUPct: bucket.cpu, MemoryPct: bucket.mem, GPUPct: bucket.gpu,
		})
	}
	if latestCore != nil {
		monitor.MetricsPresent = true
		monitor.CPU = resourceUsage(latestCore.CPUMillicores, cpuCapacity, latestCore.ObservedAt, monitor.Series, "cpu")
		monitor.Memory = resourceUsage(latestCore.MemoryBytes, memCapacity, latestCore.ObservedAt, monitor.Series, "memory")
		if ts, err := time.Parse(time.RFC3339Nano, latestCore.ObservedAt); err == nil {
			monitor.MetricAgeSec = int64(math.Max(0, now.Sub(ts).Seconds()))
		}
	}
	if latestGPU != nil {
		util := roundNode(latestGPU.GPUUtilizationPct)
		monitor.GPU.UtilizationPct = &util
		if latestGPU.GPUMemoryUsedBytes > 0 {
			mem := latestGPU.GPUMemoryUsedBytes
			monitor.GPU.MemoryUsedBytes = &mem
		}
		if latestGPU.GPUTemperatureC > 0 {
			temp := roundNode(latestGPU.GPUTemperatureC)
			monitor.GPU.TemperatureC = &temp
		}
		monitor.GPU.ObservedAt = latestGPU.ObservedAt
		monitor.GPU.Source = "dcgm_exporter"
	}
	monitor.WarningEvents, monitor.LastWarningAt = recentNodeWarnings(events, now, 24*time.Hour)
	monitor.Risk, monitor.Prediction = assessNodeRisk(monitor, len(samples), seriesSpan(monitor.Series), events, now)
	return monitor
}

func resourceUsage(used, capacity float64, observedAt string, series []NodeMetricPoint, kind string) NodeResourceUsage {
	u := NodeResourceUsage{Used: used, Capacity: capacity, ObservedAt: observedAt, Available: capacity > 0}
	if capacity <= 0 {
		return u
	}
	u.Percent = roundNode(used * 100 / capacity)
	values := make([]timedNodeValue, 0, len(series))
	for _, point := range series {
		var value *float64
		if kind == "cpu" {
			value = point.CPUPct
		} else {
			value = point.MemoryPct
		}
		if value == nil {
			continue
		}
		if *value > u.PeakPercent {
			u.PeakPercent = *value
		}
		if ts, err := time.Parse(time.RFC3339Nano, point.ObservedAt); err == nil {
			values = append(values, timedNodeValue{at: ts, value: *value})
		}
	}
	u.TrendPerHour = roundNode(nodeLinearTrend(values))
	return u
}

type timedNodeValue struct {
	at    time.Time
	value float64
}

func nodeLinearTrend(values []timedNodeValue) float64 {
	if len(values) < 2 {
		return 0
	}
	base := values[0].at
	var sx, sy, sxy, sxx float64
	for _, value := range values {
		x := value.at.Sub(base).Hours()
		sx += x
		sy += value.value
		sxy += x * value.value
		sxx += x * x
	}
	n := float64(len(values))
	den := n*sxx - sx*sx
	if math.Abs(den) < 1e-9 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}

func assessNodeRisk(node NodeMonitor, sampleCount int, span time.Duration, events []store.K8sEvent, now time.Time) (NodeRiskAssessment, *NodeRiskPrediction) {
	risk := NodeRiskAssessment{Signals: []NodeRiskSignal{}}
	add := func(points int, code, severity, message string) {
		risk.Score += points
		risk.Signals = append(risk.Signals, NodeRiskSignal{Code: code, Severity: severity, Message: message})
	}
	if !node.Ready {
		add(80, "node_not_ready", "critical", "Node Ready 상태가 아닙니다.")
	}
	for _, pressure := range node.Pressure {
		add(35, strings.ToLower(pressure), "critical", pressure+" 조건이 활성화되었습니다.")
	}
	usageRisk := func(name string, usage NodeResourceUsage) {
		if !usage.Available {
			return
		}
		switch {
		case usage.Percent >= 95:
			add(40, name+"_critical", "critical", fmt.Sprintf("%s 실사용률이 %.1f%%입니다.", strings.ToUpper(name), usage.Percent))
		case usage.Percent >= 85:
			add(25, name+"_high", "high", fmt.Sprintf("%s 실사용률이 %.1f%%로 높습니다.", strings.ToUpper(name), usage.Percent))
		case usage.Percent >= 70:
			add(10, name+"_warning", "warning", fmt.Sprintf("%s 실사용률이 %.1f%%입니다.", strings.ToUpper(name), usage.Percent))
		}
		if usage.PeakPercent >= 95 && usage.Percent < 95 {
			add(8, name+"_peak", "warning", fmt.Sprintf("관측 구간 %s 피크가 %.1f%%였습니다.", strings.ToUpper(name), usage.PeakPercent))
		}
		if usage.TrendPerHour >= 5 {
			add(10, name+"_rising", "warning", fmt.Sprintf("%s 사용률이 시간당 %.1f%%p 증가 추세입니다.", strings.ToUpper(name), usage.TrendPerHour))
		}
	}
	usageRisk("cpu", node.CPU)
	usageRisk("memory", node.Memory)
	if node.GPU.Allocatable > 0 && node.GPU.AllocationPct >= 100 {
		add(12, "gpu_allocation_full", "warning", "GPU가 모두 Pod에 요청되어 신규 GPU 워크로드 여유가 없습니다.")
	}
	if node.GPU.UtilizationPct != nil && *node.GPU.UtilizationPct >= 95 {
		add(20, "gpu_utilization_high", "high", fmt.Sprintf("GPU 실사용률이 %.1f%%입니다.", *node.GPU.UtilizationPct))
	}
	if node.GPU.TemperatureC != nil && *node.GPU.TemperatureC >= 85 {
		add(30, "gpu_temperature_high", "critical", fmt.Sprintf("GPU 온도가 %.1f°C로 높습니다.", *node.GPU.TemperatureC))
	}
	if node.WarningEvents > 0 {
		points := node.WarningEvents * 4
		if points > 20 {
			points = 20
		}
		add(points, "warning_events", "warning", fmt.Sprintf("최근 24시간 Node Warning 이벤트 %d종이 관측되었습니다.", node.WarningEvents))
	}
	for _, event := range events {
		if !eventInNodeWindow(event, now, 24*time.Hour) {
			continue
		}
		reason := strings.ToLower(event.Reason)
		if strings.Contains(reason, "oom") || strings.Contains(reason, "deadlock") || strings.Contains(reason, "reboot") || strings.Contains(reason, "eviction") || strings.Contains(reason, "xid") || strings.Contains(reason, "ecc") || strings.Contains(reason, "nvlink") {
			add(20, "critical_event", "high", "시스템 장애 연관 이벤트가 있습니다: "+event.Reason)
			break
		}
	}
	if !node.MetricsPresent {
		add(25, "metrics_unavailable", "warning", "CPU/Memory 실사용 메트릭이 없어 자원 위험을 판정할 수 없습니다.")
	} else if node.MetricAgeSec > 900 {
		add(20, "metrics_stale", "high", fmt.Sprintf("마지막 노드 메트릭이 %d분 전으로 오래되었습니다.", node.MetricAgeSec/60))
	} else if node.MetricAgeSec > 300 {
		add(10, "metrics_delayed", "warning", fmt.Sprintf("마지막 노드 메트릭이 %d분 전입니다.", node.MetricAgeSec/60))
	}
	if risk.Score > 100 {
		risk.Score = 100
	}
	switch {
	case !node.MetricsPresent && node.Ready && len(node.Pressure) == 0 && node.WarningEvents == 0:
		risk.Level = "unknown"
	case risk.Score >= 80:
		risk.Level = "critical"
	case risk.Score >= 55:
		risk.Level = "high"
	case risk.Score >= 30:
		risk.Level = "warning"
	default:
		risk.Level = "healthy"
	}
	if len(risk.Signals) == 0 {
		risk.Summary = "현재 뚜렷한 장애 선행 신호가 없습니다."
	} else {
		risk.Summary = risk.Signals[0].Message
	}
	prediction := earliestNodePrediction(node, sampleCount, span, now)
	return risk, prediction
}

func earliestNodePrediction(node NodeMonitor, sampleCount int, span time.Duration, now time.Time) *NodeRiskPrediction {
	type candidate struct {
		resource string
		current  float64
		trend    float64
	}
	candidates := []candidate{{"cpu", node.CPU.Percent, node.CPU.TrendPerHour}, {"memory", node.Memory.Percent, node.Memory.TrendPerHour}}
	var best *NodeRiskPrediction
	for _, candidate := range candidates {
		if candidate.trend <= 0.25 || candidate.current <= 0 {
			continue
		}
		hours := (90 - candidate.current) / candidate.trend
		if candidate.current >= 90 {
			hours = 0
		}
		if hours < 0 || hours > 168 {
			continue
		}
		confidence := "low"
		if sampleCount >= 12 && span >= 3*time.Hour {
			confidence = "high"
		} else if sampleCount >= 6 && span >= time.Hour {
			confidence = "medium"
		}
		prediction := &NodeRiskPrediction{
			Resource: candidate.resource, Threshold: 90, Hours: roundNode(hours), Confidence: confidence,
			ExpectedAt: now.Add(time.Duration(hours * float64(time.Hour))).UTC().Format(time.RFC3339Nano),
			Basis:      fmt.Sprintf("최근 추세 %.1f%%p/h를 선형 연장한 운영 임계치 예상", candidate.trend),
		}
		if best == nil || prediction.Hours < best.Hours {
			best = prediction
		}
	}
	return best
}

func nodeConditionState(item store.K8sInventoryItem) (string, []string) {
	ready := "Unknown"
	pressures := []string{}
	for _, raw := range asAnySlice(item.StatusObject["conditions"]) {
		condition := asAnyMap(raw)
		typeName, status := str(condition["type"]), str(condition["status"])
		if typeName == "Ready" {
			if status == "True" {
				ready = "Ready"
			} else if status == "False" {
				ready = "NotReady"
			}
		}
		if status == "True" && (typeName == "MemoryPressure" || typeName == "DiskPressure" || typeName == "PIDPressure" || typeName == "NetworkUnavailable") {
			pressures = append(pressures, typeName)
		}
	}
	if ready == "Unknown" {
		if strings.EqualFold(item.Status, "Ready") {
			ready = "Ready"
		} else if strings.TrimSpace(item.Status) != "" {
			ready = item.Status
		}
	}
	return ready, pressures
}

func nodeGPUInventory(capacity, alloc map[string]any, requested int) NodeGPUUsage {
	keys := []string{"nvidia.com/gpu", "amd.com/gpu", "intel.com/gpu"}
	out := NodeGPUUsage{Requested: requested, Source: "inventory_allocation"}
	for _, key := range keys {
		out.Capacity += qtyInt(capacity[key])
		out.Allocatable += qtyInt(alloc[key])
	}
	out.Available = out.Allocatable - out.Requested
	if out.Available < 0 {
		out.Available = 0
	}
	if out.Allocatable > 0 {
		out.AllocationPct = roundNode(float64(out.Requested) * 100 / float64(out.Allocatable))
	}
	return out
}

func podGPURequests(spec map[string]any) int {
	total := 0
	for _, raw := range podContainers(spec) {
		requests := asAnyMap(asAnyMap(asAnyMap(raw)["resources"])["requests"])
		for _, key := range []string{"nvidia.com/gpu", "amd.com/gpu", "intel.com/gpu"} {
			total += qtyInt(requests[key])
		}
	}
	return total
}

func recentNodeWarnings(events []store.K8sEvent, now time.Time, window time.Duration) (int, string) {
	unique := map[string]bool{}
	latest := time.Time{}
	for _, event := range events {
		if !strings.EqualFold(event.Type, "Warning") || !eventInNodeWindow(event, now, window) {
			continue
		}
		unique[strings.ToLower(event.Reason)+"\x00"+event.Message] = true
		if ts, ok := nodeEventTime(event); ok && ts.After(latest) {
			latest = ts
		}
	}
	if latest.IsZero() {
		return len(unique), ""
	}
	return len(unique), latest.UTC().Format(time.RFC3339Nano)
}

func eventInNodeWindow(event store.K8sEvent, now time.Time, window time.Duration) bool {
	ts, ok := nodeEventTime(event)
	return ok && !ts.Before(now.Add(-window)) && !ts.After(now.Add(5*time.Minute))
}

func nodeEventTime(event store.K8sEvent) (time.Time, bool) {
	for _, raw := range []string{event.LastSeen, event.CreatedAt, event.FirstSeen} {
		if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func nodeRole(labels map[string]string) string {
	roles := []string{}
	for key := range labels {
		if strings.HasPrefix(key, "node-role.kubernetes.io/") {
			role := strings.TrimPrefix(key, "node-role.kubernetes.io/")
			if role == "" {
				role = "worker"
			}
			roles = append(roles, role)
		}
	}
	if len(roles) == 0 {
		return "worker"
	}
	sort.Strings(roles)
	return strings.Join(roles, ", ")
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func seriesSpan(series []NodeMetricPoint) time.Duration {
	if len(series) < 2 {
		return 0
	}
	first, err1 := time.Parse(time.RFC3339Nano, series[0].ObservedAt)
	last, err2 := time.Parse(time.RFC3339Nano, series[len(series)-1].ObservedAt)
	if err1 != nil || err2 != nil {
		return 0
	}
	return last.Sub(first)
}

func nodeKey(clusterID, node string) string { return clusterID + "\x00" + node }

func roundNode(value float64) float64 {
	return math.Round(value*10) / 10
}
