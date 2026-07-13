package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func (s *Server) runK8sMonitoringGatewayTool(ctx context.Context, name string, args json.RawMessage) (map[string]any, error) {
	var input struct {
		ClusterID string `json:"cluster_id"`
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
		Window    string `json:"window"`
		Limit     int    `json:"limit"`
	}
	_ = json.Unmarshal(args, &input)
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	if input.ClusterID == "" {
		return nil, errGateway("cluster_id is required (use k8s_list_clusters first)")
	}
	switch name {
	case "k8s_node_metrics":
		windowName, window, bucket := nodeMonitoringWindow(input.Window)
		now := time.Now().UTC()
		items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: input.ClusterID, Limit: 10000})
		if err != nil {
			return nil, err
		}
		metrics, err := s.db.ListK8sMetricSamplesFiltered(ctx, store.K8sMetricSampleFilter{
			ClusterID: input.ClusterID, ResourceKind: "Node", Since: now.Add(-window).Format(time.RFC3339Nano), Limit: 100000,
		})
		if err != nil {
			return nil, err
		}
		events, err := s.db.ListK8sEvents(ctx, input.ClusterID, 500)
		if err != nil {
			return nil, err
		}
		report := analyzer.AnalyzeNodeMonitoring(items, metrics, events, now, bucket)
		promURL, _ := s.monitoringPrometheusConfig(ctx)
		return gatewayToolJSON(map[string]any{
			"cluster_id": input.ClusterID, "window": windowName, "report": report,
			"collection": map[string]any{
				"metrics_source":                  "metrics.k8s.io → Prometheus/Thanos fallback",
				"prometheus_or_thanos_configured": promURL != "", "gpu_source": "DCGM Exporter via Prometheus/Thanos",
			},
			"interpretation": "CPU·memory는 사용량 추세이고 GPU는 gpu_observed=true인 DCGM 표본만 실제 관측값입니다. 장애 예상 시각은 선형 추세 기반 선행 경보이며 보장값이 아닙니다.",
		}), nil

	case "k8s_pod_metrics":
		limit := input.Limit
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		metrics, err := s.db.ListK8sMetricSamplesFiltered(ctx, store.K8sMetricSampleFilter{
			ClusterID: input.ClusterID, ResourceKind: "Pod", ResourceName: strings.TrimSpace(input.Pod), Limit: 100000,
		})
		if err != nil {
			return nil, err
		}
		latest := make([]store.K8sMetricSample, 0, limit)
		seen := map[string]bool{}
		for _, metric := range metrics {
			if input.Namespace != "" && metric.Namespace != strings.TrimSpace(input.Namespace) {
				continue
			}
			key := metric.Namespace + "\x00" + metric.ResourceName
			if seen[key] {
				continue
			}
			seen[key] = true
			latest = append(latest, metric)
			if len(latest) >= limit {
				break
			}
		}
		return gatewayToolJSON(map[string]any{
			"cluster_id": input.ClusterID, "namespace": strings.TrimSpace(input.Namespace), "pod": strings.TrimSpace(input.Pod),
			"pods": latest, "count": len(latest),
			"units":          map[string]string{"cpu_millicores": "mCPU", "memory_bytes": "bytes", "gpu_utilization_pct": "percent", "gpu_memory_used_bytes": "bytes"},
			"interpretation": "gpu_observed=false는 GPU 0%가 아니라 DCGM Pod 귀속 지표 미수집을 뜻합니다. observed_at으로 지표 신선도를 확인하세요.",
		}), nil
	}
	return nil, errGateway("unknown monitoring tool: " + name)
}
