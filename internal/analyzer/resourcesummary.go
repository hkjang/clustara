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

// PodResourceQuantities is the numeric (millicores / bytes) CPU+memory request/limit totals for a
// pod or workload spec. Companion to ResourceTags (which is the display-formatted view).
type PodResourceQuantities struct {
	ReqCPUm int   // millicores
	LimCPUm int   // millicores
	ReqMemB int64 // bytes
	LimMemB int64 // bytes
	HasReq  bool
	HasLim  bool
}

// PodResourceNumbers sums the regular containers' CPU/memory requests and limits as numeric totals
// (.spec.containers or .spec.template.spec.containers; initContainers excluded). Pure.
func PodResourceNumbers(spec map[string]any) PodResourceQuantities {
	var q PodResourceQuantities
	for _, raw := range regularContainers(spec) {
		res := asAnyMap(asAnyMap(raw)["resources"])
		req := asAnyMap(res["requests"])
		lim := asAnyMap(res["limits"])
		if _, ok := req["cpu"]; ok {
			q.ReqCPUm += qtyCPU(req["cpu"])
			q.HasReq = true
		}
		if _, ok := req["memory"]; ok {
			q.ReqMemB += qtyMem(req["memory"])
			q.HasReq = true
		}
		if _, ok := lim["cpu"]; ok {
			q.LimCPUm += qtyCPU(lim["cpu"])
			q.HasLim = true
		}
		if _, ok := lim["memory"]; ok {
			q.LimMemB += qtyMem(lim["memory"])
			q.HasLim = true
		}
	}
	return q
}

// SummarizePodResources sums the regular containers' CPU/memory requests and limits from a pod or
// workload spec and formats them for display. initContainers are excluded. Pure.
func SummarizePodResources(spec map[string]any) ResourceTags {
	q := PodResourceNumbers(spec)
	t := ResourceTags{HasReq: q.HasReq, HasLim: q.HasLim}
	if q.HasReq {
		t.ReqCPU = formatCPUMillis(q.ReqCPUm)
		t.ReqMem = formatMemBytes(q.ReqMemB)
	}
	if q.HasLim {
		t.LimCPU = formatCPUMillis(q.LimCPUm)
		t.LimMem = formatMemBytes(q.LimMemB)
	}
	return t
}

// FormatCPUMillis / FormatMemBytes expose the display formatters for callers building resource
// recommendations (e.g. Resource Request Advisor).
func FormatCPUMillis(m int) string    { return formatCPUMillis(m) }
func FormatMemBytes(b int64) string   { return formatMemBytes(b) }

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
