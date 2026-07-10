package analyzer

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestAnalyzeGPUOperationsCoversWorkloadWasteVRAMHardwareMIGAndCost(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{
		{ClusterID: "prod", Kind: "Node", Name: "gpu-1", Labels: map[string]string{"nvidia.com/gpu.product": "NVIDIA-H100-80GB-HBM3"}},
		{ClusterID: "prod", Kind: "Pod", Namespace: "llm", Name: "vllm-0", Labels: map[string]string{"app.kubernetes.io/name": "llama-service"}, Spec: map[string]any{
			"nodeName": "gpu-1", "containers": []any{map[string]any{"name": "server", "image": "vllm/vllm-openai:latest", "resources": map[string]any{"requests": map[string]any{"nvidia.com/gpu": "1"}}}},
		}},
	}
	samples := []store.K8sGPUSample{}
	const totalVRAM = float64(80 << 30)
	for i := 0; i <= 30; i++ {
		usedPct := 40.0 + float64(i)*1.9
		samples = append(samples, store.K8sGPUSample{
			ClusterID: "prod", NodeName: "gpu-1", Namespace: "llm", Pod: "vllm-0", Container: "server",
			GPUUUID: "GPU-1", GPUDevice: "nvidia0", MIGProfile: "1g.10gb", MIGInstanceID: "7",
			UtilizationPct: 2, SMActivePct: 1.5, TensorActivePct: 0.5, DRAMActivePct: 30,
			FramebufferUsedBytes: totalVRAM * usedPct / 100, FramebufferFreeBytes: totalVRAM * (100 - usedPct) / 100,
			TemperatureC: 70, PowerWatts: 220, ObservedAt: now.Add(time.Duration(i-30) * time.Minute).Format(time.RFC3339Nano),
		})
	}
	samples[len(samples)-1].TemperatureC = 90
	samples[len(samples)-1].XIDErrors = 79
	samples[len(samples)-1].ECCDBE = 1
	samples[len(samples)-1].NVLinkErrors = 2

	report := AnalyzeGPUOperations(items, samples, now, 2000, DefaultGPUAlertPolicy())
	if report.Summary.Devices != 1 || report.Summary.MIGInstances != 1 || report.Summary.CriticalFindings < 3 {
		t.Fatalf("unexpected GPU summary: %+v", report.Summary)
	}
	if len(report.Nodes) != 1 || len(report.Nodes[0].Models) != 1 || report.Nodes[0].Models[0] != "NVIDIA-H100-80GB-HBM3" {
		t.Fatalf("expected node model enrichment: %+v", report.Nodes)
	}
	if len(report.Workloads) != 1 || report.Workloads[0].ModelServer != "vLLM" || report.Workloads[0].GPURequest != 1 {
		t.Fatalf("expected vLLM workload mapping: %+v", report.Workloads)
	}
	if len(report.Waste) != 1 || report.Waste[0].AveragePct != 2 {
		t.Fatalf("expected sustained low-util finding: %+v", report.Waste)
	}
	if len(report.VRAMRisks) != 1 || report.VRAMRisks[0].Level != "critical" {
		t.Fatalf("expected VRAM OOM risk: %+v", report.VRAMRisks)
	}
	if len(report.MIG) != 1 || report.MIG[0].Profile != "1g.10gb" {
		t.Fatalf("expected MIG mapping: %+v", report.MIG)
	}
	if len(report.CostAllocation) != 1 || report.CostAllocation[0].GPUHours < 0.4 || report.CostAllocation[0].EstimatedKRW < 800 {
		t.Fatalf("expected GPU-hour cost allocation: %+v", report.CostAllocation)
	}
	if len(report.Models) != 1 || report.Models[0].ModelServer != "vLLM" {
		t.Fatalf("expected model observability mapping: %+v", report.Models)
	}
}

func TestAnalyzeGPUOperationsDoesNotFlagShortLowUtilWindow(t *testing.T) {
	now := time.Now().UTC()
	items := []store.K8sInventoryItem{{ClusterID: "c", Kind: "Pod", Namespace: "n", Name: "p", Spec: map[string]any{"containers": []any{map[string]any{"resources": map[string]any{"requests": map[string]any{"nvidia.com/gpu": "1"}}}}}}}
	samples := []store.K8sGPUSample{
		{ClusterID: "c", Namespace: "n", Pod: "p", GPUUUID: "g", UtilizationPct: 1, ObservedAt: now.Add(-10 * time.Minute).Format(time.RFC3339Nano)},
		{ClusterID: "c", Namespace: "n", Pod: "p", GPUUUID: "g", UtilizationPct: 1, ObservedAt: now.Format(time.RFC3339Nano)},
	}
	report := AnalyzeGPUOperations(items, samples, now, 0, DefaultGPUAlertPolicy())
	if len(report.Waste) != 0 {
		t.Fatalf("short observation should not be labeled waste: %+v", report.Waste)
	}
}
