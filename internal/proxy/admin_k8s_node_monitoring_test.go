package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func TestK8sNodeAndGPUOperationsEndpoints(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{ID: "n1", ClusterID: "c1", Kind: "Node", Name: "gpu-1", Status: "Ready", Labels: map[string]string{"nvidia.com/gpu.product": "H100"}, StatusObject: map[string]any{"allocatable": map[string]any{"cpu": "4", "memory": "8Gi", "nvidia.com/gpu": "1"}, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := db.InsertK8sMetricSample(ctx, store.K8sMetricSample{ID: "m1", ClusterID: "c1", ResourceKind: "Node", ResourceName: "gpu-1", CPUMillicores: 2000, MemoryBytes: 4 << 30, ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sGPUSample(ctx, store.K8sGPUSample{ID: "g1", ClusterID: "c1", NodeName: "gpu-1", GPUUUID: "GPU-1", UtilizationPct: 50, FramebufferUsedBytes: 20 << 30, FramebufferFreeBytes: 60 << 30, TemperatureC: 60, ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/admin/k8s/nodes/monitoring?cluster_id=c1&window=1h")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var nodes struct {
		Report analyzer.NodeMonitoringReport `json:"report"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(nodes.Report.Nodes) != 1 || nodes.Report.Nodes[0].CPU.Percent != 50 {
		t.Fatalf("unexpected node monitoring response: status=%d report=%+v", resp.StatusCode, nodes.Report)
	}

	gpuResp, err := http.Get(proxy.URL + "/admin/k8s/gpu/operations?cluster_id=c1&window=1h")
	if err != nil {
		t.Fatal(err)
	}
	defer gpuResp.Body.Close()
	var gpu struct {
		Report analyzer.GPUOperationsReport `json:"report"`
	}
	if err := json.NewDecoder(gpuResp.Body).Decode(&gpu); err != nil {
		t.Fatal(err)
	}
	if gpuResp.StatusCode != http.StatusOK || gpu.Report.Summary.Devices != 1 || len(gpu.Report.Nodes) != 1 {
		t.Fatalf("unexpected GPU operations response: status=%d report=%+v", gpuResp.StatusCode, gpu.Report)
	}
}

func TestAdminUIIncludesNodeAndGPUOperationsControls(t *testing.T) {
	for _, marker := range []string{"/admin/k8s/nodes/monitoring", "장애 위험 레이더", "GPU Operations · DCGM", "GPU 워크로드 매핑", "VRAM 부족 예측", "MIG 인스턴스", "GPU 알림 정책", "k8sGPUSavePolicy", "입력값으로 GPU/DCGM 검증", "openDCGMConfigPreview", "showK8sMonitoringTest"} {
		if !strings.Contains(adminHTML, marker) {
			t.Errorf("admin UI missing %q", marker)
		}
	}
}

func TestDCGMCountersValidationAndDerivedPromQL(t *testing.T) {
	validation := parseDCGMCountersCSV(defaultDCGMCountersCSV)
	if !validation.Valid || len(validation.Metrics) < 20 {
		t.Fatalf("default DCGM CSV should be valid: %+v", validation)
	}
	query := dcgmPromQLFromCSV(defaultDCGMCountersCSV)
	if !strings.Contains(query, "DCGM_FI_DEV_GPU_UTIL") || !strings.Contains(query, "DCGM_FI_PROF_PIPE_TENSOR_ACTIVE") {
		t.Fatalf("derived PromQL missing counters: %s", query)
	}
	invalid := parseDCGMCountersCSV("DCGM_FI_DEV_GPU_UTIL,unknown,help")
	if invalid.Valid || len(invalid.Errors) == 0 || len(invalid.MissingRequired) == 0 {
		t.Fatalf("invalid CSV was not rejected: %+v", invalid)
	}
}

func TestK8sMonitoringTestUsesUnsavedScreenValues(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("query"), "DCGM_FI_DEV_GPU_UTIL") {
			t.Errorf("derived query missing GPU util: %s", r.URL.Query().Get("query"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_GPU_UTIL","Hostname":"gpu-1"},"value":[1,"42"]}]}}`))
	}))
	defer prom.Close()
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()
	payload, _ := json.Marshal(map[string]string{
		"prometheus_url": prom.URL, "dcgm_node_label": "Hostname", "dcgm_counters_csv": defaultDCGMCountersCSV, "dcgm_metrics_promql": "",
	})
	resp, out := req(t, http.MethodPost, proxy.URL+"/admin/settings/test/k8s-monitoring", string(payload))
	if resp.StatusCode != http.StatusOK || out["ok"] != true || out["sample_count"].(float64) != 1 || out["node_count"].(float64) != 1 {
		t.Fatalf("unexpected monitoring test response status=%d body=%+v", resp.StatusCode, out)
	}
	if got := server.runtimeSettingValue(context.Background(), "k8s.monitoring.prometheus_url"); got != "" {
		t.Fatalf("screen-value test must not persist URL, got %q", got)
	}
}
