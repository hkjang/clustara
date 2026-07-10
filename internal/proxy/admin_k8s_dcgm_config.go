package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"clustara/internal/prometheus"
	"clustara/internal/store"
)

// defaultDCGMCountersCSV is both the out-of-box collector configuration and the source used to
// derive the default PromQL selector. Keeping one source prevents the dashboard and exporter from
// silently drifting apart.
const defaultDCGMCountersCSV = `# Clustara GPU Operations collector set for NVIDIA DCGM Exporter.
# Mount as /etc/dcgm-exporter/clustara-counters.csv and start dcgm-exporter with -f and -k.
DCGM_FI_DEV_GPU_UTIL, gauge, GPU utilization percent.
DCGM_FI_DEV_MEM_COPY_UTIL, gauge, Memory copy utilization percent.
DCGM_FI_DEV_SM_CLOCK, gauge, SM clock frequency in MHz.
DCGM_FI_DEV_MEM_CLOCK, gauge, Memory clock frequency in MHz.
DCGM_FI_DEV_GPU_TEMP, gauge, GPU temperature in Celsius.
DCGM_FI_DEV_POWER_USAGE, gauge, Power draw in watts.
DCGM_FI_DEV_TOTAL_ENERGY_CONSUMPTION, counter, Total energy consumption in millijoules.
DCGM_FI_DEV_FB_FREE, gauge, Framebuffer memory free in MiB.
DCGM_FI_DEV_FB_USED, gauge, Framebuffer memory used in MiB.
DCGM_FI_DEV_XID_ERRORS, gauge, Last NVIDIA XID error code.
DCGM_FI_DEV_ECC_SBE_VOL_TOTAL, counter, Volatile single-bit ECC errors.
DCGM_FI_DEV_ECC_DBE_VOL_TOTAL, counter, Volatile double-bit ECC errors.
DCGM_FI_DEV_PCIE_REPLAY_COUNTER, counter, PCIe replay counter.
DCGM_FI_DEV_NVLINK_CRC_FLIT_ERROR_COUNT_TOTAL, counter, NVLink flow-control CRC errors.
DCGM_FI_DEV_NVLINK_CRC_DATA_ERROR_COUNT_TOTAL, counter, NVLink data CRC errors.
DCGM_FI_DEV_NVLINK_REPLAY_ERROR_COUNT_TOTAL, counter, NVLink replay errors.
DCGM_FI_DEV_NVLINK_RECOVERY_ERROR_COUNT_TOTAL, counter, NVLink recovery errors.
DCGM_FI_DEV_THERMAL_VIOLATION, counter, Thermal throttling duration in nanoseconds.
DCGM_FI_PROF_SM_ACTIVE, gauge, Ratio of cycles with an active warp.
DCGM_FI_PROF_PIPE_TENSOR_ACTIVE, gauge, Ratio of cycles with the tensor pipe active.
DCGM_FI_PROF_DRAM_ACTIVE, gauge, Ratio of cycles with active device memory traffic.`

var (
	dcgmMetricNamePattern = regexp.MustCompile(`^DCGM_FI_(DEV|PROF)_[A-Z0-9_]+$`)
	k8sDNSLabelPattern    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dcgmRequiredMetrics   = []string{
		"DCGM_FI_DEV_GPU_UTIL", "DCGM_FI_DEV_FB_USED", "DCGM_FI_DEV_FB_FREE",
		"DCGM_FI_DEV_GPU_TEMP", "DCGM_FI_DEV_POWER_USAGE", "DCGM_FI_DEV_XID_ERRORS",
	}
	dcgmRecommendedMetrics = []string{
		"DCGM_FI_PROF_SM_ACTIVE", "DCGM_FI_PROF_PIPE_TENSOR_ACTIVE", "DCGM_FI_PROF_DRAM_ACTIVE",
		"DCGM_FI_DEV_MEM_COPY_UTIL", "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", "DCGM_FI_DEV_PCIE_REPLAY_COUNTER",
		"DCGM_FI_DEV_NVLINK_REPLAY_ERROR_COUNT_TOTAL", "DCGM_FI_DEV_THERMAL_VIOLATION",
	}
)

func validateK8sDNSLabelSetting(value string) error {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 63 || !k8sDNSLabelPattern.MatchString(value) {
		return fmt.Errorf("must be a Kubernetes DNS label (lowercase alphanumeric or '-', max 63 characters)")
	}
	return nil
}

type dcgmCSVValidation struct {
	Valid              bool     `json:"valid"`
	Errors             []string `json:"errors"`
	Warnings           []string `json:"warnings"`
	Metrics            []string `json:"metrics"`
	MissingRequired    []string `json:"missing_required"`
	MissingRecommended []string `json:"missing_recommended"`
	LineCount          int      `json:"line_count"`
}

func parseDCGMCountersCSV(value string) dcgmCSVValidation {
	result := dcgmCSVValidation{Errors: []string{}, Warnings: []string{}, Metrics: []string{}, MissingRequired: []string{}, MissingRecommended: []string{}}
	seen := map[string]bool{}
	for lineNo, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result.LineCount++
		record, err := csv.NewReader(strings.NewReader(line)).Read()
		if err != nil || len(record) != 3 {
			result.Errors = append(result.Errors, fmt.Sprintf("%d행: metric,type,help 3개 필드가 필요합니다", lineNo+1))
			continue
		}
		metric, metricType := strings.TrimSpace(record[0]), strings.ToLower(strings.TrimSpace(record[1]))
		if !dcgmMetricNamePattern.MatchString(metric) {
			result.Errors = append(result.Errors, fmt.Sprintf("%d행: 잘못된 DCGM metric 이름 %q", lineNo+1, metric))
			continue
		}
		if metricType != "gauge" && metricType != "counter" {
			result.Errors = append(result.Errors, fmt.Sprintf("%d행: type은 gauge 또는 counter여야 합니다", lineNo+1))
			continue
		}
		if strings.TrimSpace(record[2]) == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("%d행: help 설명이 비어 있습니다", lineNo+1))
			continue
		}
		if seen[metric] {
			result.Errors = append(result.Errors, fmt.Sprintf("%d행: 중복 metric %s", lineNo+1, metric))
			continue
		}
		seen[metric] = true
		result.Metrics = append(result.Metrics, metric)
	}
	if len(result.Metrics) == 0 {
		result.Errors = append(result.Errors, "하나 이상의 DCGM counter가 필요합니다")
	}
	for _, metric := range dcgmRequiredMetrics {
		if !seen[metric] {
			result.MissingRequired = append(result.MissingRequired, metric)
		}
	}
	for _, metric := range dcgmRecommendedMetrics {
		if !seen[metric] {
			result.MissingRecommended = append(result.MissingRecommended, metric)
		}
	}
	if len(result.MissingRequired) > 0 {
		result.Errors = append(result.Errors, "필수 counter 누락: "+strings.Join(result.MissingRequired, ", "))
	}
	if len(result.MissingRecommended) > 0 {
		result.Warnings = append(result.Warnings, "권장 counter 누락: "+strings.Join(result.MissingRecommended, ", "))
	}
	result.Valid = len(result.Errors) == 0
	return result
}

func validateDCGMCountersCSVSetting(value string) error {
	result := parseDCGMCountersCSV(value)
	if result.Valid {
		return nil
	}
	return fmt.Errorf("invalid DCGM counters CSV: %s", strings.Join(result.Errors, "; "))
}

func dcgmPromQLFromCSV(value string) string {
	validation := parseDCGMCountersCSV(value)
	if len(validation.Metrics) == 0 {
		return ""
	}
	metrics := append([]string(nil), validation.Metrics...)
	sort.Strings(metrics)
	for i := range metrics {
		metrics[i] = regexp.QuoteMeta(metrics[i])
	}
	return `{__name__=~"` + strings.Join(metrics, "|") + `"}`
}

// runtimeSettingValue reads DB overrides on demand so monitoring workers in every Clustara pod
// observe a save without process restart. Environment/default values remain the fallback layer.
func (s *Server) runtimeSettingValue(ctx context.Context, key string) string {
	d, ok := settingDefByKey(key)
	if !ok {
		return ""
	}
	stored := map[string]store.AdminSetting{}
	if value, found, err := s.db.GetAdminSetting(ctx, key); err == nil && found {
		stored[key] = value
	}
	value, _ := s.effectiveSettingValue(stored, d)
	return strings.TrimSpace(value)
}

func (s *Server) monitoringBool(ctx context.Context, key string, fallback bool) bool {
	value, err := strconv.ParseBool(s.runtimeSettingValue(ctx, key))
	if err != nil {
		return fallback
	}
	return value
}

func (s *Server) monitoringInt(ctx context.Context, key string, fallback int) int {
	value, err := strconv.Atoi(s.runtimeSettingValue(ctx, key))
	if err != nil {
		return fallback
	}
	return value
}

func (s *Server) monitoringFloat(ctx context.Context, key string, fallback float64) float64 {
	value, err := strconv.ParseFloat(s.runtimeSettingValue(ctx, key), 64)
	if err != nil {
		return fallback
	}
	return value
}

func (s *Server) monitoringPrometheusConfig(ctx context.Context) (string, string) {
	return strings.TrimRight(s.runtimeSettingValue(ctx, "k8s.monitoring.prometheus_url"), "/"), s.runtimeSettingValue(ctx, "k8s.monitoring.prometheus_token")
}

func dcgmConfigMapManifest(namespace, name, counters string) string {
	if namespace == "" {
		namespace = "gpu-operator"
	}
	if name == "" {
		name = "clustara-dcgm-counters"
	}
	var body strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(strings.TrimSpace(counters), "\r\n", "\n"), "\n") {
		body.WriteString("    ")
		body.WriteString(line)
		body.WriteByte('\n')
	}
	return fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n  namespace: %s\ndata:\n  counters.csv: |\n%s", name, namespace, body.String())
}

func (s *Server) effectiveDCGMConfig(ctx context.Context) (string, string, string, dcgmCSVValidation) {
	counters := s.runtimeSettingValue(ctx, "k8s.monitoring.dcgm_counters_csv")
	override := s.runtimeSettingValue(ctx, "k8s.monitoring.dcgm_metrics_promql")
	query, source := override, "promql_override"
	if query == "" {
		query, source = dcgmPromQLFromCSV(counters), "dcgm_counters_csv"
	}
	return counters, query, source, parseDCGMCountersCSV(counters)
}

// GET /admin/k8s/gpu/dcgm-config returns the effective CSV, validation and an apply-ready
// ConfigMap preview. It never mutates the cluster; rollout remains an explicit operator action.
func (s *Server) handleK8sDCGMConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	counters, query, source, validation := s.effectiveDCGMConfig(r.Context())
	namespace := s.runtimeSettingValue(r.Context(), "k8s.monitoring.dcgm_configmap_namespace")
	name := s.runtimeSettingValue(r.Context(), "k8s.monitoring.dcgm_configmap_name")
	promURL, token := s.monitoringPrometheusConfig(r.Context())
	sum := sha256.Sum256([]byte(counters))
	writeJSON(w, http.StatusOK, map[string]any{
		"counters_csv": counters, "sha256": hex.EncodeToString(sum[:]), "validation": validation,
		"derived_promql": query, "query_source": source,
		"configmap_manifest": dcgmConfigMapManifest(namespace, name, counters),
		"diagnostics":        map[string]any{"prometheus_configured": promURL != "", "token_configured": token != "", "node_label": s.runtimeSettingValue(r.Context(), "k8s.monitoring.dcgm_node_label")},
	})
}

// POST /admin/settings/test/k8s-monitoring verifies both the CSV-derived query and the effective
// Prometheus credentials. The response is deliberately metadata-only: tokens never leave memory.
func (s *Server) handleSettingsTestK8sMonitoring(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	started := time.Now()
	promURL, token := s.monitoringPrometheusConfig(r.Context())
	counters, query, source, validation := s.effectiveDCGMConfig(r.Context())
	nodeLabel := s.runtimeSettingValue(r.Context(), "k8s.monitoring.dcgm_node_label")
	var payload struct {
		PrometheusURL   *string `json:"prometheus_url"`
		PrometheusToken *string `json:"prometheus_token"`
		NodeLabel       *string `json:"dcgm_node_label"`
		PromQL          *string `json:"dcgm_metrics_promql"`
		CountersCSV     *string `json:"dcgm_counters_csv"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if payload.PrometheusURL != nil {
		promURL = strings.TrimRight(strings.TrimSpace(*payload.PrometheusURL), "/")
	}
	if payload.PrometheusToken != nil && strings.TrimSpace(*payload.PrometheusToken) != "" {
		token = strings.TrimSpace(*payload.PrometheusToken)
	}
	if payload.NodeLabel != nil {
		nodeLabel = strings.TrimSpace(*payload.NodeLabel)
	}
	if payload.CountersCSV != nil {
		counters = strings.TrimSpace(*payload.CountersCSV)
		validation = parseDCGMCountersCSV(counters)
	}
	if payload.PromQL != nil {
		if strings.TrimSpace(*payload.PromQL) != "" {
			query, source = strings.TrimSpace(*payload.PromQL), "promql_override"
		} else {
			query, source = dcgmPromQLFromCSV(counters), "dcgm_counters_csv"
		}
	}
	if !validation.Valid && source == "dcgm_counters_csv" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "DCGM CSV 검증 실패", "validation": validation, "query_source": source, "latency_ms": time.Since(started).Milliseconds()})
		return
	}
	if promURL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Prometheus URL이 설정되지 않았습니다", "csv_valid": validation.Valid, "validation": validation, "query_source": source, "latency_ms": time.Since(started).Milliseconds()})
		return
	}
	if d, ok := settingDefByKey("k8s.monitoring.prometheus_url"); ok && d.validate != nil {
		if err := d.validate(promURL); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Prometheus URL 형식 오류: " + err.Error(), "csv_valid": validation.Valid, "validation": validation, "query_source": source, "latency_ms": time.Since(started).Milliseconds()})
			return
		}
	}
	samples, err := prometheus.NewClient(promURL, token).Query(r.Context(), query)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Prometheus/DCGM 쿼리 실패: " + err.Error(), "csv_valid": validation.Valid, "validation": validation, "query_source": source, "latency_ms": time.Since(started).Milliseconds()})
		return
	}
	metrics, nodes := map[string]bool{}, map[string]bool{}
	for _, sample := range samples {
		if metric := sample.Labels["__name__"]; metric != "" {
			metrics[metric] = true
		}
		if node := firstLabel(sample.Labels, nodeLabel, "Hostname", "hostname", "node", "instance"); node != "" {
			nodes[node] = true
		}
	}
	observed := make([]string, 0, len(metrics))
	for metric := range metrics {
		observed = append(observed, metric)
	}
	sort.Strings(observed)
	missingRequired := []string{}
	for _, metric := range dcgmRequiredMetrics {
		if !metrics[metric] {
			missingRequired = append(missingRequired, metric)
		}
	}
	warning := ""
	if len(samples) == 0 {
		warning = "쿼리는 성공했지만 현재 DCGM 표본이 없습니다. exporter target과 counter 적용 상태를 확인하세요."
	} else if len(missingRequired) > 0 {
		warning = "필수 지표 일부가 현재 instant vector에 없습니다: " + strings.Join(missingRequired, ", ")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": fmt.Sprintf("DCGM 표본 %d개 · 노드 %d개", len(samples), len(nodes)),
		"sample_count": len(samples), "node_count": len(nodes), "observed_metrics": observed,
		"missing_required_metrics": missingRequired, "warning": warning, "validation": validation,
		"csv_valid": validation.Valid, "query_source": source, "latency_ms": time.Since(started).Milliseconds(),
	})
}
