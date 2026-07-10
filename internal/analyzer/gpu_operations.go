package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

type GPUOperationsReport struct {
	GeneratedAt    string                  `json:"generated_at"`
	Summary        GPUOperationsSummary    `json:"summary"`
	Nodes          []GPUNodeSummary        `json:"nodes"`
	Workloads      []GPUWorkloadSummary    `json:"workloads"`
	Waste          []GPUWasteFinding       `json:"waste_findings"`
	VRAMRisks      []GPUVRAMRisk           `json:"vram_risks"`
	Hardware       []GPUHardwareFinding    `json:"hardware_findings"`
	MIG            []GPUMIGSummary         `json:"mig_instances"`
	CostAllocation []GPUCostAllocation     `json:"cost_allocation"`
	Models         []GPUModelObservability `json:"model_observability"`
	AlertPolicy    GPUAlertPolicy          `json:"alert_policy"`
}

type GPUOperationsSummary struct {
	Nodes             int     `json:"nodes"`
	Devices           int     `json:"devices"`
	MIGInstances      int     `json:"mig_instances"`
	MappedWorkloads   int     `json:"mapped_workloads"`
	AverageUtilPct    float64 `json:"average_utilization_pct"`
	TotalVRAMBytes    float64 `json:"total_vram_bytes"`
	UsedVRAMBytes     float64 `json:"used_vram_bytes"`
	PowerWatts        float64 `json:"power_watts"`
	WasteCandidates   int     `json:"waste_candidates"`
	CriticalFindings  int     `json:"critical_findings"`
	UnattributedCount int     `json:"unattributed_devices"`
}

type GPUNodeSummary struct {
	ClusterID       string   `json:"cluster_id"`
	Node            string   `json:"node"`
	Models          []string `json:"models"`
	Devices         int      `json:"devices"`
	MIGInstances    int      `json:"mig_instances"`
	VRAMTotalBytes  float64  `json:"vram_total_bytes"`
	VRAMUsedBytes   float64  `json:"vram_used_bytes"`
	UtilizationPct  float64  `json:"utilization_pct"`
	SMActivePct     float64  `json:"sm_active_pct"`
	TensorActivePct float64  `json:"tensor_active_pct"`
	DRAMActivePct   float64  `json:"dram_active_pct"`
	TemperatureC    float64  `json:"temperature_c"`
	PowerWatts      float64  `json:"power_watts"`
	Health          string   `json:"health"`
	ObservedAt      string   `json:"observed_at"`
}

type GPUWorkloadSummary struct {
	ClusterID       string   `json:"cluster_id"`
	Namespace       string   `json:"namespace"`
	Pod             string   `json:"pod"`
	Container       string   `json:"container"`
	Service         string   `json:"service"`
	ModelServer     string   `json:"model_server"`
	Nodes           []string `json:"nodes"`
	GPUDevices      int      `json:"gpu_devices"`
	GPURequest      int      `json:"gpu_request"`
	AverageUtilPct  float64  `json:"average_utilization_pct"`
	CurrentUtilPct  float64  `json:"current_utilization_pct"`
	VRAMUsedBytes   float64  `json:"vram_used_bytes"`
	VRAMTotalBytes  float64  `json:"vram_total_bytes"`
	SMActivePct     float64  `json:"sm_active_pct"`
	TensorActivePct float64  `json:"tensor_active_pct"`
	DRAMActivePct   float64  `json:"dram_active_pct"`
	ObservedAt      string   `json:"observed_at"`
}

type GPUWasteFinding struct {
	ClusterID  string  `json:"cluster_id"`
	Namespace  string  `json:"namespace"`
	Pod        string  `json:"pod"`
	Container  string  `json:"container"`
	GPURequest int     `json:"gpu_request"`
	AveragePct float64 `json:"average_utilization_pct"`
	DurationH  float64 `json:"duration_hours"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
}

type GPUVRAMRisk struct {
	ClusterID        string  `json:"cluster_id"`
	Node             string  `json:"node"`
	GPUUUID          string  `json:"gpu_uuid"`
	MIGProfile       string  `json:"mig_profile"`
	Namespace        string  `json:"namespace"`
	Pod              string  `json:"pod"`
	CurrentPct       float64 `json:"current_pct"`
	TrendPctPerHour  float64 `json:"trend_pct_per_hour"`
	HoursToThreshold float64 `json:"hours_to_90_pct"`
	ExpectedAt       string  `json:"expected_at,omitempty"`
	Level            string  `json:"level"`
	Message          string  `json:"message"`
}

type GPUHardwareFinding struct {
	ClusterID      string `json:"cluster_id"`
	Node           string `json:"node"`
	GPUUUID        string `json:"gpu_uuid"`
	Code           string `json:"code"`
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	CordonEligible bool   `json:"cordon_eligible"`
	DrainRequired  bool   `json:"drain_required"`
	ObservedAt     string `json:"observed_at"`
}

type GPUMIGSummary struct {
	ClusterID     string  `json:"cluster_id"`
	Node          string  `json:"node"`
	GPUUUID       string  `json:"gpu_uuid"`
	Profile       string  `json:"profile"`
	InstanceID    string  `json:"instance_id"`
	Namespace     string  `json:"namespace"`
	Pod           string  `json:"pod"`
	Utilization   float64 `json:"utilization_pct"`
	VRAMUsedBytes float64 `json:"vram_used_bytes"`
	VRAMTotal     float64 `json:"vram_total_bytes"`
	ObservedAt    string  `json:"observed_at"`
}

type GPUCostAllocation struct {
	ClusterID       string  `json:"cluster_id"`
	Namespace       string  `json:"namespace"`
	Service         string  `json:"service"`
	ModelServer     string  `json:"model_server"`
	GPUHours        float64 `json:"gpu_hours"`
	UtilizedGPUHour float64 `json:"utilized_gpu_hours"`
	EstimatedKRW    float64 `json:"estimated_krw"`
	Attribution     string  `json:"attribution"`
}

type GPUModelObservability struct {
	ClusterID       string   `json:"cluster_id"`
	Namespace       string   `json:"namespace"`
	ModelServer     string   `json:"model_server"`
	Pods            int      `json:"pods"`
	GPUDevices      int      `json:"gpu_devices"`
	AverageUtilPct  float64  `json:"average_utilization_pct"`
	VRAMUsedBytes   float64  `json:"vram_used_bytes"`
	QualityMetrics  bool     `json:"quality_metrics_available"`
	QualityNote     string   `json:"quality_note"`
	ServedModels    []string `json:"served_models"`
	RequestsPerSec  float64  `json:"requests_per_second"`
	TokensPerSec    float64  `json:"tokens_per_second"`
	RunningRequests float64  `json:"running_requests"`
	TTFTP95Seconds  float64  `json:"ttft_p95_seconds"`
	E2EP95Seconds   float64  `json:"e2e_p95_seconds"`
}

type GPUAlertPolicy struct {
	TemperatureC       float64 `json:"temperature_c"`
	VRAMUtilPct        float64 `json:"vram_utilization_pct"`
	LowUtilPct         float64 `json:"low_utilization_pct"`
	LowUtilForMinutes  int     `json:"low_utilization_for_minutes"`
	AlertOnXID         bool    `json:"alert_on_xid"`
	AlertOnECCDBE      bool    `json:"alert_on_ecc_dbe"`
	AlertOnNVLinkError bool    `json:"alert_on_nvlink_error"`
}

func DefaultGPUAlertPolicy() GPUAlertPolicy {
	return GPUAlertPolicy{TemperatureC: 85, VRAMUtilPct: 90, LowUtilPct: 10, LowUtilForMinutes: 30, AlertOnXID: true, AlertOnECCDBE: true, AlertOnNVLinkError: true}
}

// AnalyzeGPUOperations produces a pure, explainable report over DCGM device samples and current
// Kubernetes inventory. hourlyCostKRW is an operator-configurable blended price per observed GPU.
func AnalyzeGPUOperations(items []store.K8sInventoryItem, samples []store.K8sGPUSample, now time.Time, hourlyCostKRW float64, policy GPUAlertPolicy) GPUOperationsReport {
	if policy.TemperatureC <= 0 {
		policy = DefaultGPUAlertPolicy()
	}
	if hourlyCostKRW < 0 {
		hourlyCostKRW = 0
	}
	report := GPUOperationsReport{GeneratedAt: now.UTC().Format(time.RFC3339Nano), AlertPolicy: policy}
	pods := gpuPodInventory(items)
	nodeModels := gpuNodeModelInventory(items)
	for i := range samples {
		key := samples[i].ClusterID + "\x00" + samples[i].Namespace + "\x00" + samples[i].Pod
		if pod, ok := pods[key]; ok {
			if samples[i].ModelServer == "" {
				samples[i].ModelServer = pod.modelServer
			}
			if samples[i].GPUModel == "" {
				samples[i].GPUModel = pod.gpuModel
			}
		}
		if samples[i].GPUModel == "" {
			samples[i].GPUModel = nodeModels[nodeKey(samples[i].ClusterID, samples[i].NodeName)]
		}
	}
	latest, history := latestGPUSamples(samples)
	report.Nodes = gpuNodeSummaries(latest)
	report.Workloads = gpuWorkloadSummaries(samples, latest, pods)
	report.Waste = gpuWasteFindings(samples, pods, policy)
	report.VRAMRisks = gpuVRAMRisks(history, now, policy)
	report.Hardware = gpuHardwareFindings(history, policy)
	report.MIG = gpuMIGSummaries(latest)
	report.CostAllocation = gpuCostAllocation(samples, pods, hourlyCostKRW)
	report.Models = gpuModelSummaries(report.Workloads)
	report.Summary.Nodes = len(report.Nodes)
	report.Summary.Devices = len(latest)
	report.Summary.MIGInstances = len(report.MIG)
	report.Summary.MappedWorkloads = len(report.Workloads)
	report.Summary.WasteCandidates = len(report.Waste)
	for _, sample := range latest {
		report.Summary.AverageUtilPct += sample.UtilizationPct
		report.Summary.TotalVRAMBytes += sample.FramebufferUsedBytes + sample.FramebufferFreeBytes
		report.Summary.UsedVRAMBytes += sample.FramebufferUsedBytes
		report.Summary.PowerWatts += sample.PowerWatts
		if sample.Pod == "" {
			report.Summary.UnattributedCount++
		}
	}
	if len(latest) > 0 {
		report.Summary.AverageUtilPct = roundNode(report.Summary.AverageUtilPct / float64(len(latest)))
	}
	for _, finding := range report.Hardware {
		if finding.Severity == "critical" {
			report.Summary.CriticalFindings++
		}
	}
	return report
}

func gpuNodeModelInventory(items []store.K8sInventoryItem) map[string]string {
	out := map[string]string{}
	for _, item := range items {
		if strings.EqualFold(item.Kind, "Node") {
			out[nodeKey(item.ClusterID, item.Name)] = firstText(item.Labels["nvidia.com/gpu.product"], item.Labels["gpu.nvidia.com/model"], item.Labels["amd.com/gpu.product"])
		}
	}
	return out
}

type gpuPodInfo struct {
	request     int
	service     string
	modelServer string
	gpuModel    string
}

func gpuPodInventory(items []store.K8sInventoryItem) map[string]gpuPodInfo {
	nodeModels := map[string]string{}
	for _, item := range items {
		if strings.EqualFold(item.Kind, "Node") {
			nodeModels[nodeKey(item.ClusterID, item.Name)] = firstText(item.Labels["nvidia.com/gpu.product"], item.Labels["gpu.nvidia.com/model"], item.Labels["amd.com/gpu.product"])
		}
	}
	out := map[string]gpuPodInfo{}
	for _, item := range items {
		if !strings.EqualFold(item.Kind, "Pod") {
			continue
		}
		search := strings.ToLower(item.Name + " " + item.Labels["app"] + " " + item.Labels["app.kubernetes.io/name"])
		for _, raw := range podContainers(item.Spec) {
			search += " " + strings.ToLower(str(asAnyMap(raw)["image"]))
		}
		service := firstText(item.Labels["serving.kserve.io/inferenceservice"], item.Labels["app.kubernetes.io/name"], item.Labels["app"], item.Name)
		node := str(item.Spec["nodeName"])
		out[item.ClusterID+"\x00"+item.Namespace+"\x00"+item.Name] = gpuPodInfo{
			request: podGPURequests(item.Spec), service: service, modelServer: classifyModelServer(search), gpuModel: nodeModels[nodeKey(item.ClusterID, node)],
		}
	}
	return out
}

func classifyModelServer(text string) string {
	for _, candidate := range []struct{ needle, label string }{
		{"vllm", "vLLM"}, {"ollama", "Ollama"}, {"jupyterhub", "JupyterHub"}, {"jupyter", "Jupyter"},
		{"triton", "Triton"}, {"text-generation-inference", "TGI"}, {"torchserve", "TorchServe"}, {"ray-serve", "Ray Serve"},
	} {
		if strings.Contains(text, candidate.needle) {
			return candidate.label
		}
	}
	return "generic"
}

func gpuIdentity(sample store.K8sGPUSample) string {
	id := firstText(sample.GPUUUID, sample.NodeName+"/"+sample.GPUDevice)
	return sample.ClusterID + "\x00" + id + "\x00" + sample.MIGProfile + "\x00" + sample.MIGInstanceID
}

func latestGPUSamples(samples []store.K8sGPUSample) (map[string]store.K8sGPUSample, map[string][]store.K8sGPUSample) {
	latest := map[string]store.K8sGPUSample{}
	history := map[string][]store.K8sGPUSample{}
	for _, sample := range samples {
		key := gpuIdentity(sample)
		history[key] = append(history[key], sample)
		if current, ok := latest[key]; !ok || sample.ObservedAt > current.ObservedAt {
			latest[key] = sample
		}
	}
	for key := range history {
		sort.SliceStable(history[key], func(i, j int) bool { return history[key][i].ObservedAt < history[key][j].ObservedAt })
	}
	return latest, history
}

func gpuNodeSummaries(latest map[string]store.K8sGPUSample) []GPUNodeSummary {
	type agg struct {
		GPUNodeSummary
		models map[string]bool
	}
	byNode := map[string]*agg{}
	for _, sample := range latest {
		key := nodeKey(sample.ClusterID, sample.NodeName)
		a := byNode[key]
		if a == nil {
			a = &agg{GPUNodeSummary: GPUNodeSummary{ClusterID: sample.ClusterID, Node: sample.NodeName, Health: "healthy"}, models: map[string]bool{}}
			byNode[key] = a
		}
		a.Devices++
		if sample.MIGProfile != "" {
			a.MIGInstances++
		}
		if sample.GPUModel != "" {
			a.models[sample.GPUModel] = true
		}
		a.VRAMUsedBytes += sample.FramebufferUsedBytes
		a.VRAMTotalBytes += sample.FramebufferUsedBytes + sample.FramebufferFreeBytes
		a.UtilizationPct += sample.UtilizationPct
		a.SMActivePct += sample.SMActivePct
		a.TensorActivePct += sample.TensorActivePct
		a.DRAMActivePct += sample.DRAMActivePct
		if sample.TemperatureC > a.TemperatureC {
			a.TemperatureC = sample.TemperatureC
		}
		a.PowerWatts += sample.PowerWatts
		if sample.ObservedAt > a.ObservedAt {
			a.ObservedAt = sample.ObservedAt
		}
		if sample.XIDErrors > 0 || sample.ECCDBE > 0 || sample.TemperatureC >= 85 {
			a.Health = "critical"
		}
	}
	out := []GPUNodeSummary{}
	for _, a := range byNode {
		if a.Devices > 0 {
			a.UtilizationPct = roundNode(a.UtilizationPct / float64(a.Devices))
			a.SMActivePct = roundNode(a.SMActivePct / float64(a.Devices))
			a.TensorActivePct = roundNode(a.TensorActivePct / float64(a.Devices))
			a.DRAMActivePct = roundNode(a.DRAMActivePct / float64(a.Devices))
		}
		for model := range a.models {
			a.Models = append(a.Models, model)
		}
		sort.Strings(a.Models)
		out = append(out, a.GPUNodeSummary)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Health != out[j].Health {
			return out[i].Health == "critical"
		}
		return out[i].Node < out[j].Node
	})
	return out
}

func gpuWorkloadKey(sample store.K8sGPUSample) string {
	return sample.ClusterID + "\x00" + sample.Namespace + "\x00" + sample.Pod + "\x00" + sample.Container
}

func gpuWorkloadSummaries(samples []store.K8sGPUSample, latest map[string]store.K8sGPUSample, pods map[string]gpuPodInfo) []GPUWorkloadSummary {
	type agg struct {
		GPUWorkloadSummary
		count   int
		devices map[string]bool
		nodes   map[string]bool
	}
	byWorkload := map[string]*agg{}
	for _, sample := range samples {
		if sample.Pod == "" {
			continue
		}
		key := gpuWorkloadKey(sample)
		a := byWorkload[key]
		if a == nil {
			pod := pods[sample.ClusterID+"\x00"+sample.Namespace+"\x00"+sample.Pod]
			a = &agg{GPUWorkloadSummary: GPUWorkloadSummary{ClusterID: sample.ClusterID, Namespace: sample.Namespace, Pod: sample.Pod, Container: sample.Container, Service: pod.service, ModelServer: firstText(sample.ModelServer, pod.modelServer), GPURequest: pod.request}, devices: map[string]bool{}, nodes: map[string]bool{}}
			byWorkload[key] = a
		}
		a.AverageUtilPct += sample.UtilizationPct
		a.count++
	}
	for _, sample := range latest {
		if sample.Pod == "" {
			continue
		}
		a := byWorkload[gpuWorkloadKey(sample)]
		if a == nil {
			continue
		}
		a.devices[gpuIdentity(sample)] = true
		a.nodes[sample.NodeName] = true
		a.CurrentUtilPct += sample.UtilizationPct
		a.VRAMUsedBytes += sample.FramebufferUsedBytes
		a.VRAMTotalBytes += sample.FramebufferUsedBytes + sample.FramebufferFreeBytes
		a.SMActivePct += sample.SMActivePct
		a.TensorActivePct += sample.TensorActivePct
		a.DRAMActivePct += sample.DRAMActivePct
		if sample.ObservedAt > a.ObservedAt {
			a.ObservedAt = sample.ObservedAt
		}
	}
	out := []GPUWorkloadSummary{}
	for _, a := range byWorkload {
		a.GPUDevices = len(a.devices)
		if a.count > 0 {
			a.AverageUtilPct = roundNode(a.AverageUtilPct / float64(a.count))
		}
		if a.GPUDevices > 0 {
			a.CurrentUtilPct = roundNode(a.CurrentUtilPct / float64(a.GPUDevices))
			a.SMActivePct = roundNode(a.SMActivePct / float64(a.GPUDevices))
			a.TensorActivePct = roundNode(a.TensorActivePct / float64(a.GPUDevices))
			a.DRAMActivePct = roundNode(a.DRAMActivePct / float64(a.GPUDevices))
		}
		for node := range a.nodes {
			a.Nodes = append(a.Nodes, node)
		}
		sort.Strings(a.Nodes)
		out = append(out, a.GPUWorkloadSummary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CurrentUtilPct > out[j].CurrentUtilPct })
	return out
}

func gpuWasteFindings(samples []store.K8sGPUSample, pods map[string]gpuPodInfo, policy GPUAlertPolicy) []GPUWasteFinding {
	byWorkload := map[string][]store.K8sGPUSample{}
	for _, sample := range samples {
		if sample.Pod != "" {
			byWorkload[gpuWorkloadKey(sample)] = append(byWorkload[gpuWorkloadKey(sample)], sample)
		}
	}
	out := []GPUWasteFinding{}
	for _, history := range byWorkload {
		sort.SliceStable(history, func(i, j int) bool { return history[i].ObservedAt < history[j].ObservedAt })
		pod := pods[history[0].ClusterID+"\x00"+history[0].Namespace+"\x00"+history[0].Pod]
		if pod.request <= 0 || len(history) < 2 {
			continue
		}
		first, e1 := time.Parse(time.RFC3339Nano, history[0].ObservedAt)
		last, e2 := time.Parse(time.RFC3339Nano, history[len(history)-1].ObservedAt)
		if e1 != nil || e2 != nil || last.Sub(first) < time.Duration(policy.LowUtilForMinutes)*time.Minute {
			continue
		}
		avg := 0.0
		for _, sample := range history {
			avg += sample.UtilizationPct
		}
		avg /= float64(len(history))
		if avg >= policy.LowUtilPct {
			continue
		}
		severity := "warning"
		if avg < 3 && last.Sub(first) >= 2*time.Hour {
			severity = "high"
		}
		out = append(out, GPUWasteFinding{ClusterID: history[0].ClusterID, Namespace: history[0].Namespace, Pod: history[0].Pod, Container: history[0].Container, GPURequest: pod.request, AveragePct: roundNode(avg), DurationH: roundNode(last.Sub(first).Hours()), Severity: severity, Message: fmt.Sprintf("GPU %d개를 요청했지만 평균 사용률이 %.1f%%입니다.", pod.request, avg)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AveragePct < out[j].AveragePct })
	return out
}

func gpuVRAMRisks(history map[string][]store.K8sGPUSample, now time.Time, policy GPUAlertPolicy) []GPUVRAMRisk {
	out := []GPUVRAMRisk{}
	for _, samples := range history {
		values := []timedNodeValue{}
		for _, sample := range samples {
			total := sample.FramebufferUsedBytes + sample.FramebufferFreeBytes
			ts, err := time.Parse(time.RFC3339Nano, sample.ObservedAt)
			if total <= 0 || err != nil {
				continue
			}
			values = append(values, timedNodeValue{at: ts, value: sample.FramebufferUsedBytes * 100 / total})
		}
		if len(values) == 0 {
			continue
		}
		latest := samples[len(samples)-1]
		current, trend := values[len(values)-1].value, nodeLinearTrend(values)
		risk := GPUVRAMRisk{ClusterID: latest.ClusterID, Node: latest.NodeName, GPUUUID: latest.GPUUUID, MIGProfile: latest.MIGProfile, Namespace: latest.Namespace, Pod: latest.Pod, CurrentPct: roundNode(current), TrendPctPerHour: roundNode(trend), HoursToThreshold: -1, Level: "healthy", Message: "VRAM 여유가 있습니다."}
		if current >= 95 {
			risk.Level, risk.HoursToThreshold, risk.Message = "critical", 0, "VRAM이 95% 이상으로 OOM 위험이 큽니다."
		} else if trend > 0.25 {
			hours := (policy.VRAMUtilPct - current) / trend
			if hours >= 0 && hours <= 168 {
				risk.HoursToThreshold = roundNode(hours)
				risk.ExpectedAt = now.Add(time.Duration(hours * float64(time.Hour))).UTC().Format(time.RFC3339Nano)
				risk.Message = fmt.Sprintf("현재 추세가 지속되면 %.1f시간 내 VRAM %.0f%% 도달 예상", hours, policy.VRAMUtilPct)
				if hours <= 6 {
					risk.Level = "high"
				} else if hours <= 24 {
					risk.Level = "warning"
				}
			}
		}
		if risk.Level != "healthy" || current >= 80 {
			out = append(out, risk)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CurrentPct > out[j].CurrentPct })
	return out
}

func gpuHardwareFindings(history map[string][]store.K8sGPUSample, policy GPUAlertPolicy) []GPUHardwareFinding {
	out := []GPUHardwareFinding{}
	for _, samples := range history {
		if len(samples) == 0 {
			continue
		}
		first, latest := samples[0], samples[len(samples)-1]
		add := func(code, severity, message string, isolate bool) {
			out = append(out, GPUHardwareFinding{ClusterID: latest.ClusterID, Node: latest.NodeName, GPUUUID: latest.GPUUUID, Code: code, Severity: severity, Message: message, CordonEligible: isolate, DrainRequired: isolate, ObservedAt: latest.ObservedAt})
		}
		if policy.AlertOnXID && latest.XIDErrors > 0 {
			add("xid", "critical", fmt.Sprintf("NVIDIA XID %.0f 오류가 관측되었습니다.", latest.XIDErrors), true)
		}
		if policy.AlertOnECCDBE && latest.ECCDBE > 0 {
			add("ecc_dbe", "critical", fmt.Sprintf("복구 불가 ECC 오류 누적 %.0f건(구간 증가 %.0f건)", latest.ECCDBE, latest.ECCDBE-first.ECCDBE), true)
		}
		if latest.ECCSBE > 0 {
			add("ecc_sbe", "warning", fmt.Sprintf("복구 가능 ECC 오류 누적 %.0f건(구간 증가 %.0f건)", latest.ECCSBE, latest.ECCSBE-first.ECCSBE), false)
		}
		if policy.AlertOnNVLinkError && latest.NVLinkErrors > 0 {
			add("nvlink", "critical", fmt.Sprintf("NVLink 오류 누적 %.0f건(구간 증가 %.0f건)", latest.NVLinkErrors, latest.NVLinkErrors-first.NVLinkErrors), true)
		}
		if latest.PCIeReplay > 0 && (len(samples) == 1 || latest.PCIeReplay > first.PCIeReplay) {
			add("pcie_replay", "warning", fmt.Sprintf("PCIe replay counter 누적 %.0f입니다.", latest.PCIeReplay), false)
		}
		if latest.TemperatureC >= policy.TemperatureC {
			add("temperature", "critical", fmt.Sprintf("GPU 온도가 %.1f°C로 임계치 %.1f°C를 초과했습니다.", latest.TemperatureC, policy.TemperatureC), true)
		}
		if latest.ThrottleSeconds > 0 && (len(samples) == 1 || latest.ThrottleSeconds > first.ThrottleSeconds) {
			add("thermal_throttle", "warning", "GPU thermal throttling 누적 시간이 증가했습니다.", false)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity < out[j].Severity })
	return out
}

func gpuMIGSummaries(latest map[string]store.K8sGPUSample) []GPUMIGSummary {
	out := []GPUMIGSummary{}
	for _, sample := range latest {
		if sample.MIGProfile == "" && sample.MIGInstanceID == "" {
			continue
		}
		out = append(out, GPUMIGSummary{ClusterID: sample.ClusterID, Node: sample.NodeName, GPUUUID: sample.GPUUUID, Profile: sample.MIGProfile, InstanceID: sample.MIGInstanceID, Namespace: sample.Namespace, Pod: sample.Pod, Utilization: sample.UtilizationPct, VRAMUsedBytes: sample.FramebufferUsedBytes, VRAMTotal: sample.FramebufferUsedBytes + sample.FramebufferFreeBytes, ObservedAt: sample.ObservedAt})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

func gpuCostAllocation(samples []store.K8sGPUSample, pods map[string]gpuPodInfo, hourlyKRW float64) []GPUCostAllocation {
	type agg struct{ hours, utilized float64 }
	byKey := map[string]*agg{}
	byDevice := map[string][]store.K8sGPUSample{}
	for _, sample := range samples {
		byDevice[gpuIdentity(sample)+"\x00"+sample.Namespace+"\x00"+sample.Pod] = append(byDevice[gpuIdentity(sample)+"\x00"+sample.Namespace+"\x00"+sample.Pod], sample)
	}
	meta := map[string]store.K8sGPUSample{}
	for key, history := range byDevice {
		sort.SliceStable(history, func(i, j int) bool { return history[i].ObservedAt < history[j].ObservedAt })
		for i := 1; i < len(history); i++ {
			prev, e1 := time.Parse(time.RFC3339Nano, history[i-1].ObservedAt)
			cur, e2 := time.Parse(time.RFC3339Nano, history[i].ObservedAt)
			if e1 != nil || e2 != nil {
				continue
			}
			delta := cur.Sub(prev)
			if delta <= 0 || delta > 5*time.Minute {
				continue
			}
			sample := history[i]
			pod := pods[sample.ClusterID+"\x00"+sample.Namespace+"\x00"+sample.Pod]
			allocationKey := sample.ClusterID + "\x00" + firstText(sample.Namespace, "unattributed") + "\x00" + firstText(pod.service, sample.Pod, "unattributed") + "\x00" + firstText(sample.ModelServer, pod.modelServer, "generic")
			a := byKey[allocationKey]
			if a == nil {
				a = &agg{}
				byKey[allocationKey] = a
				meta[allocationKey] = sample
			}
			hours := delta.Hours()
			a.hours += hours
			a.utilized += hours * ((history[i-1].UtilizationPct + sample.UtilizationPct) / 2) / 100
		}
		_ = key
	}
	out := []GPUCostAllocation{}
	for key, a := range byKey {
		parts := strings.Split(key, "\x00")
		sample := meta[key]
		out = append(out, GPUCostAllocation{ClusterID: parts[0], Namespace: parts[1], Service: parts[2], ModelServer: parts[3], GPUHours: roundNode(a.hours), UtilizedGPUHour: roundNode(a.utilized), EstimatedKRW: roundNode(a.hours * hourlyKRW), Attribution: firstText(sample.Pod, "node-level/unattributed")})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].EstimatedKRW > out[j].EstimatedKRW })
	return out
}

func gpuModelSummaries(workloads []GPUWorkloadSummary) []GPUModelObservability {
	type agg struct {
		GPUModelObservability
		podSet map[string]bool
		count  int
	}
	byModel := map[string]*agg{}
	for _, workload := range workloads {
		key := workload.ClusterID + "\x00" + workload.Namespace + "\x00" + workload.ModelServer
		a := byModel[key]
		if a == nil {
			a = &agg{GPUModelObservability: GPUModelObservability{ClusterID: workload.ClusterID, Namespace: workload.Namespace, ModelServer: workload.ModelServer, QualityNote: "GPU 소비량 연결됨; 요청·토큰 처리량·TTFT는 모델 서버 Prometheus 지표 설정 시 확장 가능"}, podSet: map[string]bool{}}
			byModel[key] = a
		}
		a.podSet[workload.Pod] = true
		a.GPUDevices += workload.GPUDevices
		a.AverageUtilPct += workload.CurrentUtilPct
		a.VRAMUsedBytes += workload.VRAMUsedBytes
		a.count++
	}
	out := []GPUModelObservability{}
	for _, a := range byModel {
		a.Pods = len(a.podSet)
		if a.count > 0 {
			a.AverageUtilPct = roundNode(a.AverageUtilPct / float64(a.count))
		}
		out = append(out, a.GPUModelObservability)
	}
	return out
}

func firstText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
