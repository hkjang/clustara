package analyzer

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestAnalyzeNodeMonitoringCombinesUsageGPUAndRiskSignals(t *testing.T) {
	now := time.Date(2026, 7, 10, 6, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{
		{
			ClusterID: "prod", Kind: "Node", Name: "gpu-1", Status: "Ready",
			Labels: map[string]string{"node-role.kubernetes.io/worker": "", "kubernetes.io/hostname": "gpu-1"},
			StatusObject: map[string]any{
				"allocatable": map[string]any{"cpu": "4", "memory": "8Gi", "nvidia.com/gpu": "2"},
				"capacity":    map[string]any{"cpu": "4", "memory": "8Gi", "nvidia.com/gpu": "2"},
				"conditions": []any{
					map[string]any{"type": "Ready", "status": "True"},
					map[string]any{"type": "MemoryPressure", "status": "False"},
				},
			},
		},
		{
			ClusterID: "prod", Kind: "Pod", Namespace: "ml", Name: "trainer", Spec: map[string]any{
				"nodeName": "gpu-1", "containers": []any{map[string]any{
					"resources": map[string]any{"requests": map[string]any{"nvidia.com/gpu": "2"}},
				}},
			},
		},
	}
	metrics := []store.K8sMetricSample{
		{ClusterID: "prod", ResourceKind: "Node", ResourceName: "gpu-1", CPUMillicores: 2800, MemoryBytes: 6 << 30, ObservedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)},
		{ClusterID: "prod", ResourceKind: "Node", ResourceName: "gpu-1", CPUMillicores: 3600, MemoryBytes: 7.5 * (1 << 30), ObservedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)},
		{ClusterID: "prod", ResourceKind: "Node", ResourceName: "gpu-1", GPUObserved: true, GPUUtilizationPct: 97, GPUMemoryUsedBytes: 20 << 30, GPUTemperatureC: 88, ObservedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)},
	}
	events := []store.K8sEvent{{
		ClusterID: "prod", InvolvedKind: "Node", InvolvedName: "gpu-1", Type: "Warning", Reason: "SystemOOM",
		Message: "system OOM", LastSeen: now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
	}}

	report := AnalyzeNodeMonitoring(items, metrics, events, now, 5*time.Minute)
	if len(report.Nodes) != 1 {
		t.Fatalf("expected one node, got %+v", report.Nodes)
	}
	node := report.Nodes[0]
	if !node.Ready || !node.MetricsPresent || node.CPU.Percent != 90 || node.Memory.Percent != 93.8 {
		t.Fatalf("unexpected current usage/status: %+v", node)
	}
	if node.GPU.Allocatable != 2 || node.GPU.Requested != 2 || node.GPU.UtilizationPct == nil || *node.GPU.UtilizationPct != 97 {
		t.Fatalf("unexpected GPU view: %+v", node.GPU)
	}
	if node.GPU.TemperatureC == nil || *node.GPU.TemperatureC != 88 || node.Risk.Level != "critical" || node.Risk.Score < 80 {
		t.Fatalf("expected critical explainable risk: %+v", node.Risk)
	}
	if report.Summary.GPUNodeCount != 1 || report.Summary.GPUObservedCount != 1 || report.Summary.MetricCoveragePct != 100 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
}

func TestAnalyzeNodeMonitoringPredictsThresholdAndIsolatesClusters(t *testing.T) {
	now := time.Date(2026, 7, 10, 6, 0, 0, 0, time.UTC)
	node := func(cluster string) store.K8sInventoryItem {
		return store.K8sInventoryItem{ClusterID: cluster, Kind: "Node", Name: "worker-1", Status: "Ready", StatusObject: map[string]any{
			"allocatable": map[string]any{"cpu": "4", "memory": "8Gi"},
			"conditions":  []any{map[string]any{"type": "Ready", "status": "True"}},
		}}
	}
	metrics := []store.K8sMetricSample{}
	for i := 0; i < 7; i++ {
		metrics = append(metrics, store.K8sMetricSample{
			ClusterID: "a", ResourceKind: "Node", ResourceName: "worker-1",
			CPUMillicores: float64(1000 + i*300), MemoryBytes: 2 << 30,
			ObservedAt: now.Add(time.Duration(i-6) * 30 * time.Minute).Format(time.RFC3339Nano),
		})
	}
	metrics = append(metrics, store.K8sMetricSample{
		ClusterID: "b", ResourceKind: "Node", ResourceName: "worker-1", CPUMillicores: 400,
		MemoryBytes: 1 << 30, ObservedAt: now.Format(time.RFC3339Nano),
	})

	report := AnalyzeNodeMonitoring([]store.K8sInventoryItem{node("a"), node("b")}, metrics, nil, now, 30*time.Minute)
	byCluster := map[string]NodeMonitor{}
	for _, result := range report.Nodes {
		byCluster[result.ClusterID] = result
	}
	if byCluster["a"].Prediction == nil || byCluster["a"].Prediction.Resource != "cpu" || byCluster["a"].Prediction.Confidence != "medium" {
		t.Fatalf("expected CPU threshold prediction from 3h trend: %+v", byCluster["a"].Prediction)
	}
	if byCluster["b"].CPU.Percent != 10 || byCluster["b"].Prediction != nil {
		t.Fatalf("cluster metrics should not bleed across same node name: %+v", byCluster["b"])
	}
}

func TestAnalyzeNodeMonitoringMarksMissingMetricsUnknownButPressureCritical(t *testing.T) {
	now := time.Now().UTC()
	ready := store.K8sInventoryItem{ClusterID: "c", Kind: "Node", Name: "ready", Status: "Ready", StatusObject: map[string]any{
		"conditions": []any{map[string]any{"type": "Ready", "status": "True"}},
	}}
	pressured := store.K8sInventoryItem{ClusterID: "c", Kind: "Node", Name: "pressure", Status: "Ready", StatusObject: map[string]any{
		"conditions": []any{map[string]any{"type": "Ready", "status": "True"}, map[string]any{"type": "DiskPressure", "status": "True"}},
	}}
	report := AnalyzeNodeMonitoring([]store.K8sInventoryItem{ready, pressured}, nil, nil, now, time.Minute)
	levels := map[string]string{}
	for _, node := range report.Nodes {
		levels[node.Name] = node.Risk.Level
	}
	if levels["ready"] != "unknown" || levels["pressure"] != "high" {
		t.Fatalf("unexpected missing metric/pressure levels: %+v", levels)
	}
}
