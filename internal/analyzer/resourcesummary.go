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

// PodResourceNumbers totals a pod's (or workload template's) CPU/memory requests and limits as
// numeric values, using the same effective-request rule the scheduler applies — regular
// containers sum, init containers contribute their largest single value. Reading only
// .spec.containers, as this did, under-reports a pod whose init container is the biggest
// consumer: the operator triaging an OOMKill saw a memory limit smaller than the one the pod
// actually holds. Pure.
func PodResourceNumbers(spec map[string]any) PodResourceQuantities {
	var q PodResourceQuantities
	q.ReqCPUm = int(effectivePodTotal(spec, func(c map[string]any) int64 {
		return int64(qtyCPU(containerQuantity(c, "requests", "cpu")))
	}))
	q.ReqMemB = effectivePodTotal(spec, func(c map[string]any) int64 {
		return qtyMem(containerQuantity(c, "requests", "memory"))
	})
	q.LimCPUm = int(effectivePodTotal(spec, func(c map[string]any) int64 {
		return int64(qtyCPU(containerQuantity(c, "limits", "cpu")))
	}))
	q.LimMemB = effectivePodTotal(spec, func(c map[string]any) int64 {
		return qtyMem(containerQuantity(c, "limits", "memory"))
	})
	q.HasReq = podDeclaresResources(spec, "requests")
	q.HasLim = podDeclaresResources(spec, "limits")
	return q
}

// podDeclaresResources reports whether any container states a cpu or memory value in the
// given section. It is what drives the "no requests set" badge, so it must not be inferred
// from the totals: a container declaring `cpu: 0` has stated a value.
func podDeclaresResources(spec map[string]any, section string) bool {
	for _, raw := range podContainers(spec) {
		res := asAnyMap(asAnyMap(asAnyMap(raw)["resources"])[section])
		if _, ok := res["cpu"]; ok {
			return true
		}
		if _, ok := res["memory"]; ok {
			return true
		}
	}
	return false
}

// SummarizePodResources totals a pod or workload spec's CPU/memory requests and limits and
// formats them for display. Pure.
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
