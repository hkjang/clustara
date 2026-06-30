package analyzer

import "strconv"

// ResourceTags is a compact CPU/memory request+limit summary for operations list rows — so an
// operator triaging e.g. an OOMKilled pod can see how much it was actually allocated without
// opening the detail. Values are human-formatted Kubernetes quantities ("250m", "512Mi").
type ResourceTags struct {
	ReqCPU string `json:"req_cpu,omitempty"`
	LimCPU string `json:"lim_cpu,omitempty"`
	ReqMem string `json:"req_mem,omitempty"`
	LimMem string `json:"lim_mem,omitempty"`
	HasReq bool   `json:"has_req"`
	HasLim bool   `json:"has_lim"`
}

// SummarizePodResources sums the regular containers' CPU/memory requests and limits from a pod or
// workload spec (.spec.containers or .spec.template.spec.containers) and formats them for display.
// initContainers are excluded (they don't run alongside the main containers). Pure.
func SummarizePodResources(spec map[string]any) ResourceTags {
	var reqCPU, limCPU int   // millicores
	var reqMem, limMem int64 // bytes
	hasReq, hasLim := false, false
	for _, raw := range regularContainers(spec) {
		res := asAnyMap(asAnyMap(raw)["resources"])
		req := asAnyMap(res["requests"])
		lim := asAnyMap(res["limits"])
		if _, ok := req["cpu"]; ok {
			reqCPU += qtyCPU(req["cpu"])
			hasReq = true
		}
		if _, ok := req["memory"]; ok {
			reqMem += qtyMem(req["memory"])
			hasReq = true
		}
		if _, ok := lim["cpu"]; ok {
			limCPU += qtyCPU(lim["cpu"])
			hasLim = true
		}
		if _, ok := lim["memory"]; ok {
			limMem += qtyMem(lim["memory"])
			hasLim = true
		}
	}
	t := ResourceTags{HasReq: hasReq, HasLim: hasLim}
	if hasReq {
		t.ReqCPU = formatCPUMillis(reqCPU)
		t.ReqMem = formatMemBytes(reqMem)
	}
	if hasLim {
		t.LimCPU = formatCPUMillis(limCPU)
		t.LimMem = formatMemBytes(limMem)
	}
	return t
}

func regularContainers(spec map[string]any) []any {
	ps := spec
	if tmpl := asAnyMap(spec["template"]); tmpl != nil {
		if inner := asAnyMap(tmpl["spec"]); inner != nil {
			ps = inner
		}
	}
	return asAnySlice(ps["containers"])
}

// formatCPUMillis renders millicores as "Nm" (<1 core), whole cores ("2"), or fractional ("1.5").
func formatCPUMillis(m int) string {
	if m <= 0 {
		return "0"
	}
	if m < 1000 {
		return strconv.Itoa(m) + "m"
	}
	if m%1000 == 0 {
		return strconv.Itoa(m / 1000)
	}
	return strconv.FormatFloat(float64(m)/1000, 'f', -1, 64)
}

// formatMemBytes renders bytes as the nearest Gi (whole/one-decimal) or Mi.
func formatMemBytes(b int64) string {
	if b <= 0 {
		return "0"
	}
	const Mi = int64(1) << 20
	const Gi = int64(1) << 30
	if b >= Gi {
		if b%Gi == 0 {
			return strconv.FormatInt(b/Gi, 10) + "Gi"
		}
		return strconv.FormatFloat(float64(b)/float64(Gi), 'f', 1, 64) + "Gi"
	}
	mi := b / Mi
	if mi < 1 {
		mi = 1
	}
	return strconv.FormatInt(mi, 10) + "Mi"
}
