package proxy

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"clustara/internal/prometheus"
	"clustara/internal/store"
)

// handleK8sLatencyCollect pulls per-workload request latency from Prometheus (the K8s core API
// has none) and stores it as latency metric samples so RCA-10 can detect post-deploy regressions.
// PROMETHEUS_URL/PROMETHEUS_TOKEN from env; PromQL + label mapping from runtime config.
// POST /admin/k8s/latency/collect?cluster_id=
func (s *Server) handleK8sLatencyCollect(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	promURL := strings.TrimSpace(os.Getenv("PROMETHEUS_URL"))
	if promURL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"collected": false, "note": "Prometheus가 구성되지 않았습니다 (PROMETHEUS_URL)."})
		return
	}
	promQL := s.flagValue(r.Context(), "k8s_latency_promql")
	if strings.TrimSpace(promQL) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "latency PromQL이 설정되지 않았습니다 (운영 설정에서 지정).", "invalid_request_error", "latency_promql_unset")
		return
	}
	nsLabel := firstNonEmpty(s.flagValue(r.Context(), "k8s_latency_ns_label"), "namespace")
	nameLabel := firstNonEmpty(s.flagValue(r.Context(), "k8s_latency_name_label"), "workload")
	clusterID := r.URL.Query().Get("cluster_id")

	client := prometheus.NewClient(promURL, os.Getenv("PROMETHEUS_TOKEN"))
	samples, err := client.Query(r.Context(), promQL)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "Prometheus 쿼리 실패: "+err.Error(), "server_error", "prometheus_query_failed")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	stored := 0
	for _, smp := range samples {
		name := smp.Labels[nameLabel]
		if name == "" {
			name = firstNonEmpty(smp.Labels["deployment"], smp.Labels["pod"], smp.Labels["service"])
		}
		if name == "" {
			continue
		}
		if err := s.db.InsertK8sMetricSample(r.Context(), store.K8sMetricSample{
			ID: newID("k8smet"), ClusterID: clusterID, Namespace: smp.Labels[nsLabel],
			ResourceKind: "Workload", ResourceName: name, LatencyMS: smp.Value, ObservedAt: now,
		}); err == nil {
			stored++
		}
	}
	s.auditAdmin(r, "k8s.latency.collect", "", auditJSON(map[string]any{"cluster_id": clusterID, "stored": stored}))
	writeJSON(w, http.StatusOK, map[string]any{"collected": true, "stored": stored, "queried": len(samples)})
}

// handleK8sLatencyConfig reads/sets the latency PromQL + label mapping. GET/POST /admin/k8s/latency/config
func (s *Server) handleK8sLatencyConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"prometheus_url": os.Getenv("PROMETHEUS_URL"),
			"promql":         s.flagValue(r.Context(), "k8s_latency_promql"),
			"ns_label":       firstNonEmpty(s.flagValue(r.Context(), "k8s_latency_ns_label"), "namespace"),
			"name_label":     firstNonEmpty(s.flagValue(r.Context(), "k8s_latency_name_label"), "workload"),
		})
	case http.MethodPost:
		var p struct {
			PromQL    *string `json:"promql"`
			NSLabel   *string `json:"ns_label"`
			NameLabel *string `json:"name_label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		set := func(key string, v *string) error {
			if v == nil {
				return nil
			}
			return s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: key, Value: strings.TrimSpace(*v), UpdatedAt: time.Now().UTC(), UpdatedBy: adminID(r)})
		}
		if err := set("k8s_latency_promql", p.PromQL); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "flag_save_failed")
			return
		}
		_ = set("k8s_latency_ns_label", p.NSLabel)
		_ = set("k8s_latency_name_label", p.NameLabel)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}
