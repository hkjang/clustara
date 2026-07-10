package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/prometheus"
	"clustara/internal/store"
)

const (
	k8sNodeMetricTickInterval = 20 * time.Second
	k8sNodeMetricsEnabledFlag = "k8s_node_metrics_enabled"
	k8sNodeMetricsSecsFlag    = "k8s_node_metrics_interval_secs"
	k8sNodeMetricsDefaultSecs = 60

	k8sGPUNodeLabelFlag = "k8s_gpu_node_label"
	k8sGPUMetricsPromQL = "k8s_gpu_metrics_promql"
)

type k8sNodeMetricCollectResult struct {
	ClusterID      string `json:"cluster_id"`
	Metrics        int    `json:"metrics"`
	GPUMetrics     int    `json:"gpu_metrics"`
	ObservedAt     string `json:"observed_at"`
	MetricsError   string `json:"metrics_error,omitempty"`
	GPUCollectNote string `json:"gpu_collect_note,omitempty"`
}

// k8sNodeMetricScheduler collects only metrics.k8s.io/nodes at a stable cadence. Keeping it
// separate from the adaptive full-inventory poll prevents live-agent clusters from receiving node
// usage only at the 30-minute reconcile interval.
func (s *Server) k8sNodeMetricScheduler() {
	lastAttempt := map[string]time.Time{}
	ticker := time.NewTicker(k8sNodeMetricTickInterval)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		s.runK8sNodeMetricTick(ctx, lastAttempt, time.Now().UTC())
		cancel()
	}
}

func (s *Server) runK8sNodeMetricTick(ctx context.Context, lastAttempt map[string]time.Time, now time.Time) {
	if !s.k8sPollFlagBool(ctx, k8sNodeMetricsEnabledFlag, true) {
		return
	}
	intervalSecs := s.k8sPollFlagInt(ctx, k8sNodeMetricsSecsFlag, k8sNodeMetricsDefaultSecs)
	if intervalSecs < int(k8sNodeMetricTickInterval.Seconds()) {
		intervalSecs = int(k8sNodeMetricTickInterval.Seconds())
	}
	interval := time.Duration(intervalSecs) * time.Second
	clusters, err := s.db.ListK8sClusters(ctx)
	if err != nil {
		slog.Warn("k8s node metric scheduler: list clusters failed", "error", err)
		return
	}
	for _, cluster := range clusters {
		last := lastAttempt[cluster.ID]
		// The DB check reduces duplicate polling after restarts and across multiple Clustara pods.
		if recent, err := s.db.ListK8sMetricSamplesFiltered(ctx, store.K8sMetricSampleFilter{
			ClusterID: cluster.ID, ResourceKind: "Node", Limit: 50,
		}); err == nil {
			for _, sample := range recent {
				if sample.GPUObserved {
					continue
				}
				if ts, parseErr := time.Parse(time.RFC3339Nano, sample.ObservedAt); parseErr == nil && ts.After(last) {
					last = ts
				}
				break
			}
		}
		if !last.IsZero() && now.Sub(last) < interval {
			continue
		}
		lastAttempt[cluster.ID] = now
		result, collectErr := s.collectNodeMetricsForCluster(ctx, cluster, now)
		if collectErr != nil {
			slog.Warn("k8s node metrics collect failed", "cluster", cluster.ID, "error", collectErr)
			continue
		}
		if result.GPUCollectNote != "" && strings.HasPrefix(result.GPUCollectNote, "error:") {
			slog.Warn("k8s gpu metrics collect degraded", "cluster", cluster.ID, "detail", result.GPUCollectNote)
		}
	}
}

func (s *Server) collectNodeMetricsForCluster(ctx context.Context, cluster store.K8sCluster, now time.Time) (k8sNodeMetricCollectResult, error) {
	result := k8sNodeMetricCollectResult{ClusterID: cluster.ID, ObservedAt: now.UTC().Format(time.RFC3339Nano)}
	client, err := s.k8sClientForCluster(ctx, cluster)
	if err != nil {
		result.MetricsError = err.Error()
		s.recordNodeMetricCollectorStatus(ctx, cluster.ID, "error", "", err.Error())
		return result, err
	}
	metrics, err := client.CollectNodeMetrics(ctx)
	if err != nil {
		result.MetricsError = err.Error()
		s.recordNodeMetricCollectorStatus(ctx, cluster.ID, "error", "", err.Error())
	} else if len(metrics) == 0 && cluster.NodeCount > 0 {
		err = fmt.Errorf("metrics.k8s.io returned no node samples")
		result.MetricsError = err.Error()
		s.recordNodeMetricCollectorStatus(ctx, cluster.ID, "error", "", err.Error())
	} else {
		for _, metric := range metrics {
			metric.ID = newID("k8smet")
			metric.ClusterID = cluster.ID
			if metric.ObservedAt == "" {
				metric.ObservedAt = result.ObservedAt
			}
			if insertErr := s.db.InsertK8sMetricSample(ctx, metric); insertErr != nil {
				err = insertErr
				result.MetricsError = insertErr.Error()
				break
			}
			result.Metrics++
		}
		if err == nil {
			s.recordNodeMetricCollectorStatus(ctx, cluster.ID, "ok", result.ObservedAt, "")
		} else {
			s.recordNodeMetricCollectorStatus(ctx, cluster.ID, "error", "", err.Error())
		}
	}

	// GPU telemetry is optional and never masks metrics-server results. Device-level samples keep
	// MIG/workload/error labels; a node aggregate feeds the compact node trend chart.
	deviceSamples, gpuNote := s.collectDCGMDeviceSamples(ctx, cluster, now)
	result.GPUCollectNote = gpuNote
	previous, _ := s.db.ListK8sGPUSamples(ctx, store.K8sGPUSampleFilter{ClusterID: cluster.ID, Limit: 10000})
	previousByDevice := latestStoredGPUSamples(previous)
	for _, sample := range deviceSamples {
		sample.ID = newID("k8sgpu")
		sample.ClusterID = cluster.ID
		if insertErr := s.db.InsertK8sGPUSample(ctx, sample); insertErr != nil {
			result.GPUCollectNote = "error: " + insertErr.Error()
			break
		}
		s.emitGPUHardwareEvents(ctx, sample, previousByDevice[gpuStoreIdentity(sample)], now)
		result.GPUMetrics++
	}
	for _, metric := range aggregateDCGMNodeMetrics(deviceSamples, now) {
		metric.ID = newID("k8smet")
		metric.ClusterID = cluster.ID
		if insertErr := s.db.InsertK8sMetricSample(ctx, metric); insertErr != nil {
			result.GPUCollectNote = "error: " + insertErr.Error()
			break
		}
	}
	if result.GPUMetrics > 0 {
		_ = s.db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{
			ID: newID("k8scol"), ClusterID: cluster.ID, Collector: "node_gpu_metrics", Status: "ok", LastSuccessAt: result.ObservedAt,
		})
	} else if strings.HasPrefix(result.GPUCollectNote, "error:") {
		_ = s.db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{
			ID: newID("k8scol"), ClusterID: cluster.ID, Collector: "node_gpu_metrics", Status: "error", LastError: strings.TrimPrefix(result.GPUCollectNote, "error: "),
		})
	}
	return result, err
}

func (s *Server) recordNodeMetricCollectorStatus(ctx context.Context, clusterID, status, successAt, lastError string) {
	_ = s.db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{
		ID: newID("k8scol"), ClusterID: clusterID, Collector: "node_metrics", Status: status,
		LastSuccessAt: successAt, LastError: lastError,
	})
}

func (s *Server) collectDCGMDeviceSamples(ctx context.Context, cluster store.K8sCluster, now time.Time) ([]store.K8sGPUSample, string) {
	promURL := strings.TrimSpace(os.Getenv("PROMETHEUS_URL"))
	if promURL == "" {
		return nil, "Prometheus/DCGM 미구성 — GPU 할당량만 제공"
	}
	defaultQuery := `{__name__=~"DCGM_FI_DEV_GPU_UTIL|DCGM_FI_PROF_SM_ACTIVE|DCGM_FI_PROF_PIPE_TENSOR_ACTIVE|DCGM_FI_DEV_MEM_COPY_UTIL|DCGM_FI_PROF_DRAM_ACTIVE|DCGM_FI_DEV_FB_USED|DCGM_FI_DEV_FB_FREE|DCGM_FI_DEV_GPU_TEMP|DCGM_FI_DEV_POWER_USAGE|DCGM_FI_DEV_SM_CLOCK|DCGM_FI_DEV_XID_ERRORS|DCGM_FI_DEV_ECC_SBE_VOL_TOTAL|DCGM_FI_DEV_ECC_DBE_VOL_TOTAL|DCGM_FI_DEV_PCIE_REPLAY_COUNTER|DCGM_FI_DEV_NVLINK_CRC_FLIT_ERROR_COUNT_TOTAL|DCGM_FI_DEV_NVLINK_CRC_DATA_ERROR_COUNT_TOTAL|DCGM_FI_DEV_NVLINK_REPLAY_ERROR_COUNT_TOTAL|DCGM_FI_DEV_NVLINK_RECOVERY_ERROR_COUNT_TOTAL|DCGM_FI_DEV_THERMAL_VIOLATION"}`
	query := firstNonEmpty(strings.TrimSpace(s.flagValue(ctx, k8sGPUMetricsPromQL)), defaultQuery)
	nodeLabel := firstNonEmpty(strings.TrimSpace(s.flagValue(ctx, k8sGPUNodeLabelFlag)), "Hostname")
	client := prometheus.NewClient(promURL, os.Getenv("PROMETHEUS_TOKEN"))
	knownNodes := s.knownGPUNodeAliases(ctx, cluster.ID)
	promSamples, err := client.Query(ctx, query)
	if err != nil {
		return nil, "error: " + err.Error()
	}
	values := map[string]*store.K8sGPUSample{}
	observedAt := now.UTC().Format(time.RFC3339Nano)
	for _, promSample := range promSamples {
		labels := promSample.Labels
		node := resolveDCGMNode(labels, nodeLabel, knownNodes)
		metricName := labels["__name__"]
		if node == "" || metricName == "" {
			continue
		}
		namespace := firstLabel(labels, "namespace", "exported_namespace")
		pod := firstLabel(labels, "pod", "exported_pod")
		container := firstLabel(labels, "container", "exported_container")
		key := strings.Join([]string{node, firstLabel(labels, "UUID", "uuid"), firstLabel(labels, "device", "gpu"), firstLabel(labels, "GPU_I_PROFILE", "gpu_i_profile"), firstLabel(labels, "GPU_I_ID", "gpu_i_id"), namespace, pod, container}, "\x00")
		entry := values[key]
		if entry == nil {
			entry = &store.K8sGPUSample{ClusterID: cluster.ID, NodeName: node, Namespace: namespace, Pod: pod, Container: container,
				GPUUUID: firstLabel(labels, "UUID", "uuid"), GPUDevice: firstLabel(labels, "device", "gpu"),
				GPUModel: firstLabel(labels, "modelName", "model", "gpu_name"), MIGProfile: firstLabel(labels, "GPU_I_PROFILE", "gpu_i_profile"),
				MIGInstanceID: firstLabel(labels, "GPU_I_ID", "gpu_i_id"), ObservedAt: observedAt}
			values[key] = entry
		}
		applyDCGMMetric(entry, metricName, promSample.Value)
	}
	out := make([]store.K8sGPUSample, 0, len(values))
	for _, value := range values {
		out = append(out, *value)
	}
	if len(out) == 0 {
		return out, "DCGM 시계열 없음 — GPU 할당량만 제공"
	}
	return out, "DCGM 장치/MIG/워크로드 실사용 지표 수집"
}

func firstLabel(labels map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(labels[key]); value != "" {
			return value
		}
	}
	return ""
}

func applyDCGMMetric(sample *store.K8sGPUSample, name string, value float64) {
	// DCGM uses very large sentinel values for unavailable fields. Never turn those into false
	// XID/ECC/temperature incidents.
	if math.Abs(value) > 1e15 {
		return
	}
	switch name {
	case "DCGM_FI_DEV_GPU_UTIL":
		sample.UtilizationPct = value
	case "DCGM_FI_PROF_SM_ACTIVE":
		sample.SMActivePct = value * 100
	case "DCGM_FI_PROF_PIPE_TENSOR_ACTIVE":
		sample.TensorActivePct = value * 100
	case "DCGM_FI_DEV_MEM_COPY_UTIL":
		sample.MemoryCopyPct = value
	case "DCGM_FI_PROF_DRAM_ACTIVE":
		sample.DRAMActivePct = value * 100
	case "DCGM_FI_DEV_FB_USED":
		sample.FramebufferUsedBytes = value * 1024 * 1024
	case "DCGM_FI_DEV_FB_FREE":
		sample.FramebufferFreeBytes = value * 1024 * 1024
	case "DCGM_FI_DEV_GPU_TEMP":
		sample.TemperatureC = value
	case "DCGM_FI_DEV_POWER_USAGE":
		sample.PowerWatts = value
	case "DCGM_FI_DEV_SM_CLOCK":
		sample.SMClockMHz = value
	case "DCGM_FI_DEV_XID_ERRORS":
		sample.XIDErrors = value
	case "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL":
		sample.ECCSBE = value
	case "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL":
		sample.ECCDBE = value
	case "DCGM_FI_DEV_PCIE_REPLAY_COUNTER":
		sample.PCIeReplay = value
	case "DCGM_FI_DEV_NVLINK_CRC_FLIT_ERROR_COUNT_TOTAL", "DCGM_FI_DEV_NVLINK_CRC_DATA_ERROR_COUNT_TOTAL", "DCGM_FI_DEV_NVLINK_REPLAY_ERROR_COUNT_TOTAL", "DCGM_FI_DEV_NVLINK_RECOVERY_ERROR_COUNT_TOTAL":
		sample.NVLinkErrors += value
	case "DCGM_FI_DEV_THERMAL_VIOLATION":
		sample.ThrottleSeconds = value / 1e9
	}
}

func aggregateDCGMNodeMetrics(samples []store.K8sGPUSample, now time.Time) []store.K8sMetricSample {
	type agg struct {
		util, memory, temp float64
		count              int
	}
	byNode := map[string]*agg{}
	for _, sample := range samples {
		a := byNode[sample.NodeName]
		if a == nil {
			a = &agg{}
			byNode[sample.NodeName] = a
		}
		a.util += sample.UtilizationPct
		a.memory += sample.FramebufferUsedBytes
		if sample.TemperatureC > a.temp {
			a.temp = sample.TemperatureC
		}
		a.count++
	}
	out := []store.K8sMetricSample{}
	for node, a := range byNode {
		if a.count == 0 {
			continue
		}
		out = append(out, store.K8sMetricSample{ResourceKind: "Node", ResourceName: node, GPUUtilizationPct: a.util / float64(a.count), GPUMemoryUsedBytes: a.memory, GPUTemperatureC: a.temp, GPUObserved: true, ObservedAt: now.UTC().Format(time.RFC3339Nano)})
	}
	return out
}

func gpuStoreIdentity(sample store.K8sGPUSample) string {
	return strings.Join([]string{sample.ClusterID, sample.NodeName, sample.GPUUUID, sample.GPUDevice, sample.MIGProfile, sample.MIGInstanceID}, "\x00")
}

func latestStoredGPUSamples(samples []store.K8sGPUSample) map[string]store.K8sGPUSample {
	out := map[string]store.K8sGPUSample{}
	for _, sample := range samples {
		key := gpuStoreIdentity(sample)
		if previous, ok := out[key]; !ok || sample.ObservedAt > previous.ObservedAt {
			out[key] = sample
		}
	}
	return out
}

func (s *Server) emitGPUHardwareEvents(ctx context.Context, current, previous store.K8sGPUSample, now time.Time) {
	type signal struct {
		triggered       bool
		reason, message string
	}
	signals := []signal{
		{current.XIDErrors > 0 && current.XIDErrors != previous.XIDErrors, "GPUXID", fmt.Sprintf("GPU %s XID %.0f 오류", current.GPUUUID, current.XIDErrors)},
		{current.ECCDBE > previous.ECCDBE, "GPUECCDBE", fmt.Sprintf("GPU %s 복구 불가 ECC 오류 증가", current.GPUUUID)},
		{current.NVLinkErrors > previous.NVLinkErrors, "GPUNVLinkError", fmt.Sprintf("GPU %s NVLink 오류 증가", current.GPUUUID)},
		{current.TemperatureC >= 85 && previous.TemperatureC < 85, "GPUOverTemperature", fmt.Sprintf("GPU %s 온도 %.1f°C", current.GPUUUID, current.TemperatureC)},
	}
	for _, signal := range signals {
		if !signal.triggered {
			continue
		}
		_ = s.db.InsertK8sEvent(ctx, store.K8sEvent{ID: newID("k8sevt"), ClusterID: current.ClusterID, InvolvedKind: "Node", InvolvedName: current.NodeName, Type: "Warning", Reason: signal.reason, Message: signal.message, Source: "dcgm-exporter", FirstSeen: now.UTC().Format(time.RFC3339Nano), LastSeen: now.UTC().Format(time.RFC3339Nano)})
	}
}

func (s *Server) knownGPUNodeAliases(ctx context.Context, clusterID string) map[string]string {
	items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Node", Limit: 10000})
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, item := range items {
		out[strings.ToLower(item.Name)] = item.Name
		for _, key := range []string{"kubernetes.io/hostname", "beta.kubernetes.io/hostname"} {
			if alias := strings.TrimSpace(item.Labels[key]); alias != "" {
				out[strings.ToLower(alias)] = item.Name
			}
		}
	}
	return out
}

func resolveDCGMNode(labels map[string]string, preferred string, known map[string]string) string {
	raw := ""
	for _, key := range []string{preferred, "Hostname", "hostname", "node", "kubernetes_node", "instance"} {
		if raw = strings.TrimSpace(labels[key]); raw != "" {
			break
		}
	}
	if raw == "" {
		return ""
	}
	if host, _, ok := strings.Cut(raw, ":"); ok {
		raw = host
	}
	if len(known) == 0 {
		return raw
	}
	return known[strings.ToLower(raw)]
}

// GET /admin/k8s/nodes/monitoring?cluster_id=&window=6h
func (s *Server) handleK8sNodeMonitoring(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	windowName, window, bucket := nodeMonitoringWindow(r.URL.Query().Get("window"))
	now := time.Now().UTC()
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	metrics, err := s.db.ListK8sMetricSamplesFiltered(r.Context(), store.K8sMetricSampleFilter{
		ClusterID: clusterID, ResourceKind: "Node", Since: now.Add(-window).Format(time.RFC3339Nano), Limit: 100000,
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_node_metrics_failed")
		return
	}
	events, err := s.db.ListK8sEvents(r.Context(), clusterID, 500)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_events_failed")
		return
	}
	report := analyzer.AnalyzeNodeMonitoring(items, metrics, events, now, bucket)
	writeJSON(w, http.StatusOK, map[string]any{
		"report": report, "window": windowName, "bucket_seconds": int(bucket.Seconds()),
		"collection": map[string]any{
			"enabled":          s.k8sPollFlagBool(r.Context(), k8sNodeMetricsEnabledFlag, true),
			"interval_seconds": s.k8sPollFlagInt(r.Context(), k8sNodeMetricsSecsFlag, k8sNodeMetricsDefaultSecs),
			"metrics_source":   "metrics.k8s.io", "gpu_source_configured": strings.TrimSpace(os.Getenv("PROMETHEUS_URL")) != "",
		},
		"note": "임계치 도달 예상은 저장된 추세를 선형 연장한 운영 선행 경보이며 실제 장애 시점을 보장하지 않습니다. GPU 실사용률/온도는 Prometheus DCGM Exporter가 있을 때만 제공됩니다.",
	})
}

// GET /admin/k8s/gpu/operations returns device, MIG, workload, waste, VRAM, hardware and cost views.
func (s *Server) handleK8sGPUOperations(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	windowName, window, _ := nodeMonitoringWindow(r.URL.Query().Get("window"))
	now := time.Now().UTC()
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	samples, err := s.db.ListK8sGPUSamples(r.Context(), store.K8sGPUSampleFilter{ClusterID: clusterID, Since: now.Add(-window).Format(time.RFC3339Nano), Limit: 100000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_gpu_metrics_failed")
		return
	}
	policy := s.k8sGPUAlertPolicy(r.Context())
	hourlyCost := s.floatFlag(r.Context(), "k8s_gpu_hourly_cost_krw", 1200)
	report := analyzer.AnalyzeGPUOperations(items, samples, now, hourlyCost, policy)
	s.enrichVLLMModelMetrics(r.Context(), &report)
	writeJSON(w, http.StatusOK, map[string]any{
		"report": report, "window": windowName, "hourly_cost_krw": hourlyCost,
		"source": "NVIDIA DCGM Exporter via Prometheus",
		"note":   "Kubernetes workload labels require DCGM_EXPORTER_KUBERNETES=true. Hardware isolation is approval-linked; no automatic cordon/drain is executed.",
	})
}

func (s *Server) enrichVLLMModelMetrics(ctx context.Context, report *analyzer.GPUOperationsReport) {
	if report == nil || strings.TrimSpace(os.Getenv("PROMETHEUS_URL")) == "" {
		return
	}
	client := prometheus.NewClient(os.Getenv("PROMETHEUS_URL"), os.Getenv("PROMETHEUS_TOKEN"))
	queries := []struct {
		kind  string
		query string
	}{
		{"requests", `sum by (namespace, pod, model_name) (rate({__name__=~"vllm:request_success(_total)?"}[5m]))`},
		{"tokens", `sum by (namespace, pod, model_name) (rate({__name__=~"vllm:(prompt_tokens|generation_tokens)(_total)?"}[5m]))`},
		{"running", `sum by (namespace, pod, model_name) ({__name__="vllm:num_requests_running"})`},
		{"ttft", `histogram_quantile(0.95, sum by (le, namespace, pod, model_name) (rate({__name__="vllm:time_to_first_token_seconds_bucket"}[5m])))`},
		{"e2e", `histogram_quantile(0.95, sum by (le, namespace, pod, model_name) (rate({__name__="vllm:e2e_request_latency_seconds_bucket"}[5m])))`},
	}
	for _, query := range queries {
		samples, err := client.Query(ctx, query.query)
		if err != nil {
			continue
		}
		for _, sample := range samples {
			namespace := firstLabel(sample.Labels, "namespace", "exported_namespace")
			for i := range report.Models {
				model := &report.Models[i]
				if !strings.EqualFold(model.ModelServer, "vLLM") || (namespace != "" && model.Namespace != namespace) {
					continue
				}
				model.QualityMetrics = true
				model.QualityNote = "vLLM 요청·토큰·TTFT·E2E 지표와 GPU 소비량 연결"
				if name := strings.TrimSpace(sample.Labels["model_name"]); name != "" && !containsText(model.ServedModels, name) {
					model.ServedModels = append(model.ServedModels, name)
				}
				switch query.kind {
				case "requests":
					model.RequestsPerSec += sample.Value
				case "tokens":
					model.TokensPerSec += sample.Value
				case "running":
					model.RunningRequests += sample.Value
				case "ttft":
					if sample.Value > model.TTFTP95Seconds {
						model.TTFTP95Seconds = sample.Value
					}
				case "e2e":
					if sample.Value > model.E2EP95Seconds {
						model.E2EP95Seconds = sample.Value
					}
				}
			}
		}
	}
}

func containsText(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (s *Server) k8sGPUAlertPolicy(ctx context.Context) analyzer.GPUAlertPolicy {
	policy := analyzer.DefaultGPUAlertPolicy()
	policy.TemperatureC = s.floatFlag(ctx, "k8s_gpu_alert_temperature_c", policy.TemperatureC)
	policy.VRAMUtilPct = s.floatFlag(ctx, "k8s_gpu_alert_vram_pct", policy.VRAMUtilPct)
	policy.LowUtilPct = s.floatFlag(ctx, "k8s_gpu_alert_low_util_pct", policy.LowUtilPct)
	policy.LowUtilForMinutes = s.k8sPollFlagInt(ctx, "k8s_gpu_alert_low_util_minutes", policy.LowUtilForMinutes)
	return policy
}

func (s *Server) floatFlag(ctx context.Context, key string, fallback float64) float64 {
	if raw := strings.TrimSpace(s.flagValue(ctx, key)); raw != "" {
		if value, err := strconv.ParseFloat(raw, 64); err == nil && value >= 0 {
			return value
		}
	}
	return fallback
}

// GET/POST /admin/k8s/gpu/policy configures alert thresholds and the blended GPU-hour price.
func (s *Server) handleK8sGPUAlertPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"policy": s.k8sGPUAlertPolicy(r.Context()), "hourly_cost_krw": s.floatFlag(r.Context(), "k8s_gpu_hourly_cost_krw", 1200)})
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var payload struct {
		TemperatureC      *float64 `json:"temperature_c"`
		VRAMUtilPct       *float64 `json:"vram_utilization_pct"`
		LowUtilPct        *float64 `json:"low_utilization_pct"`
		LowUtilForMinutes *int     `json:"low_utilization_for_minutes"`
		HourlyCostKRW     *float64 `json:"hourly_cost_krw"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	setFloat := func(key string, value *float64, min, max float64) error {
		if value == nil {
			return nil
		}
		if *value < min || *value > max {
			return fmt.Errorf("%s must be between %.0f and %.0f", key, min, max)
		}
		return s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: key, Value: strconv.FormatFloat(*value, 'f', -1, 64), UpdatedBy: adminID(r)})
	}
	if err := setFloat("k8s_gpu_alert_temperature_c", payload.TemperatureC, 40, 120); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_gpu_policy")
		return
	}
	for _, entry := range []struct {
		key string
		val *float64
		max float64
	}{{"k8s_gpu_alert_vram_pct", payload.VRAMUtilPct, 100}, {"k8s_gpu_alert_low_util_pct", payload.LowUtilPct, 100}, {"k8s_gpu_hourly_cost_krw", payload.HourlyCostKRW, 10000000}} {
		if err := setFloat(entry.key, entry.val, 0, entry.max); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_gpu_policy")
			return
		}
	}
	if payload.LowUtilForMinutes != nil {
		if *payload.LowUtilForMinutes < 5 || *payload.LowUtilForMinutes > 10080 {
			writeOpenAIError(w, http.StatusBadRequest, "low_utilization_for_minutes must be between 5 and 10080", "invalid_request_error", "invalid_gpu_policy")
			return
		}
		if err := s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: "k8s_gpu_alert_low_util_minutes", Value: strconv.Itoa(*payload.LowUtilForMinutes), UpdatedBy: adminID(r)}); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
			return
		}
	}
	s.auditAdmin(r, "k8s.gpu.policy.update", "", auditJSON(payload))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": s.k8sGPUAlertPolicy(r.Context()), "hourly_cost_krw": s.floatFlag(r.Context(), "k8s_gpu_hourly_cost_krw", 1200)})
}

// POST /admin/k8s/node-metrics/collect?cluster_id= triggers one lightweight operator refresh.
func (s *Server) handleK8sNodeMetricCollect(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required", "invalid_request_error", "cluster_id_required")
		return
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), clusterID)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found", "invalid_request_error", "cluster_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	result, collectErr := s.collectNodeMetricsForCluster(r.Context(), cluster, time.Now().UTC())
	if collectErr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "result": result, "error": collectErr.Error()})
		return
	}
	s.auditAdmin(r, "k8s.node_metrics.collect", "", auditJSON(result))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func nodeMonitoringWindow(raw string) (string, time.Duration, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1h":
		return "1h", time.Hour, time.Minute
	case "24h", "1d":
		return "24h", 24 * time.Hour, 15 * time.Minute
	case "7d":
		return "7d", 7 * 24 * time.Hour, time.Hour
	default:
		return "6h", 6 * time.Hour, 5 * time.Minute
	}
}
