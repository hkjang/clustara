package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

// BuildMetricRiskIncidents converts explainable resource pressure and short-horizon forecasts into
// trackable preventive incidents. A predictive: key distinguishes these from observed failures and
// allows the scanner to auto-resolve them after the signal clears.
func BuildMetricRiskIncidents(items []store.K8sInventoryItem, metrics []store.K8sMetricSample, events []store.K8sEvent, now time.Time) []IncidentDraft {
	out := []IncidentDraft{}
	nodes := AnalyzeNodeMonitoring(items, metrics, events, now, 5*time.Minute)
	for _, node := range nodes.Nodes {
		if node.Risk.Level == "critical" || node.Risk.Level == "high" {
			severity := "high"
			if node.Risk.Level == "critical" {
				severity = "critical"
			}
			out = append(out, metricDraft(node.ClusterID, "", "Node", node.Name, "NodeResourceRisk", severity,
				"노드 장애 위험 상승", []string{node.Risk.Summary, fmt.Sprintf("위험 점수 %d", node.Risk.Score), nodeUsageEvidence(node)}))
		}
		if p := node.Prediction; p != nil && p.Hours <= 24 && p.Confidence != "low" {
			out = append(out, metricDraft(node.ClusterID, "", "Node", node.Name, "PredictedCapacityExhaustion", "medium",
				"24시간 내 노드 자원 임계치 예상", []string{fmt.Sprintf("%s %.1f시간 후 %.0f%% 예상", p.Resource, p.Hours, p.Threshold), "신뢰도: " + p.Confidence, p.Basis}))
		}
	}

	pods := map[string]store.K8sInventoryItem{}
	series := map[string][]store.K8sMetricSample{}
	for _, item := range items {
		if strings.EqualFold(item.Kind, "Pod") {
			pods[item.ClusterID+"\x00"+item.Namespace+"\x00"+item.Name] = item
		}
	}
	for _, metric := range metrics {
		if strings.EqualFold(metric.ResourceKind, "Pod") {
			series[metric.ClusterID+"\x00"+metric.Namespace+"\x00"+metric.ResourceName] = append(series[metric.ClusterID+"\x00"+metric.Namespace+"\x00"+metric.ResourceName], metric)
		}
	}
	for key, samples := range series {
		pod, ok := pods[key]
		if !ok || len(samples) == 0 {
			continue
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i].ObservedAt > samples[j].ObservedAt })
		q := PodResourceNumbers(pod.Spec)
		if q.LimCPUm > 0 && consecutiveRatio(samples, 3, func(m store.K8sMetricSample) float64 { return m.CPUMillicores / float64(q.LimCPUm) }) >= .9 {
			out = append(out, metricDraft(pod.ClusterID, pod.Namespace, "Pod", pod.Name, "PodCPUSaturation", "high", "Pod CPU 포화 지속",
				[]string{fmt.Sprintf("최근 연속 표본 CPU %.0fm / limit %dm", samples[0].CPUMillicores, q.LimCPUm), "throttling·latency 상승 및 readiness 실패 가능"}))
		} else if q.LimCPUm > 0 {
			if hours, ok := hoursToThreshold(samples, float64(q.LimCPUm), func(m store.K8sMetricSample) float64 { return m.CPUMillicores }); ok && hours <= 24 {
				out = append(out, metricDraft(pod.ClusterID, pod.Namespace, "Pod", pod.Name, "PredictedCPUExhaustion", "medium", "24시간 내 Pod CPU limit 도달 예상", []string{fmt.Sprintf("최근 추세 기준 %.1f시간 후 limit %dm", hours, q.LimCPUm)}))
			}
		}
		if q.LimMemB > 0 && consecutiveRatio(samples, 3, func(m store.K8sMetricSample) float64 { return m.MemoryBytes / float64(q.LimMemB) }) >= .9 {
			out = append(out, metricDraft(pod.ClusterID, pod.Namespace, "Pod", pod.Name, "PodMemorySaturation", "critical", "Pod 메모리 limit 임박",
				[]string{fmt.Sprintf("최근 연속 표본 메모리 %.0fMi / limit %.0fMi", samples[0].MemoryBytes/(1<<20), float64(q.LimMemB)/(1<<20)), "OOMKilled 가능성이 높아 사전 완화 필요"}))
		} else if q.LimMemB > 0 {
			if hours, ok := hoursToThreshold(samples, float64(q.LimMemB), func(m store.K8sMetricSample) float64 { return m.MemoryBytes }); ok && hours <= 24 {
				out = append(out, metricDraft(pod.ClusterID, pod.Namespace, "Pod", pod.Name, "PredictedMemoryExhaustion", "high", "24시간 내 Pod 메모리 limit 도달 예상", []string{fmt.Sprintf("최근 추세 기준 %.1f시간 후 limit %.0fMi", hours, float64(q.LimMemB)/(1<<20)), "메모리 누수·캐시 증가 여부 확인"}))
			}
		}
		if samples[0].GPUObserved && (samples[0].GPUTemperatureC >= 85 || samples[0].GPUUtilizationPct >= 98) {
			out = append(out, metricDraft(pod.ClusterID, pod.Namespace, "Pod", pod.Name, "PodGPURisk", "high", "Pod GPU 열·포화 위험",
				[]string{fmt.Sprintf("GPU %.1f%% · %.1f°C · VRAM %.0fMi", samples[0].GPUUtilizationPct, samples[0].GPUTemperatureC, samples[0].GPUMemoryUsedBytes/(1<<20)), "DCGM Pod 귀속 표본"}))
		}
	}
	return out
}

func metricDraft(cluster, namespace, kind, name, condition, severity, title string, evidence []string) IncidentDraft {
	return IncidentDraft{Key: "predictive:" + cluster + "|" + namespace + "|" + kind + "|" + name + "|" + condition, ClusterID: cluster, Namespace: namespace, Kind: kind, Name: name, Condition: condition, Severity: severity, Title: title + " — " + kind + "/" + name, Evidence: evidence}
}

func consecutiveRatio(samples []store.K8sMetricSample, count int, value func(store.K8sMetricSample) float64) float64 {
	if len(samples) < count {
		return 0
	}
	minimum := value(samples[0])
	for i := 1; i < count; i++ {
		if v := value(samples[i]); v < minimum {
			minimum = v
		}
	}
	return minimum
}

func hoursToThreshold(samples []store.K8sMetricSample, threshold float64, value func(store.K8sMetricSample) float64) (float64, bool) {
	if len(samples) < 6 || threshold <= 0 {
		return 0, false
	}
	latestTime, e1 := time.Parse(time.RFC3339Nano, samples[0].ObservedAt)
	oldestTime, e2 := time.Parse(time.RFC3339Nano, samples[len(samples)-1].ObservedAt)
	hours := latestTime.Sub(oldestTime).Hours()
	if e1 != nil || e2 != nil || hours < 1 {
		return 0, false
	}
	trend := (value(samples[0]) - value(samples[len(samples)-1])) / hours
	current := value(samples[0])
	if trend <= threshold*.01 || current <= 0 || current >= threshold {
		return 0, false
	}
	remaining := (threshold - current) / trend
	return remaining, remaining >= 0 && remaining <= 168
}

func nodeUsageEvidence(node NodeMonitor) string {
	return fmt.Sprintf("CPU %.1f%% · Memory %.1f%% · metric age %ds", node.CPU.Percent, node.Memory.Percent, node.MetricAgeSec)
}
