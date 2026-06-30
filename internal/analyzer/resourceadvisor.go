package analyzer

import (
	"fmt"
	"sort"
)

// Resource Request Advisor (CLU-REQ-06).
//
// Connects observed failure symptoms — OOMKilled, Pending (insufficient resources), CPU
// throttling, restart storm — to concrete CPU/memory request·limit recommendations. This is the
// symptom-driven complement to RecommendRightsizing (which is usage-driven, cost-focused): the
// advisor fires when a workload is actively failing for a resource reason and proposes the change
// that fixes it. Pure over numeric inputs; the handler extracts quantities + symptoms.

// ResourceAdvisorInput is one workload's current sizing plus the symptoms observed on its pods.
type ResourceAdvisorInput struct {
	Namespace string
	Workload  string
	Kind      string
	ReqCPUm   int   // current CPU request (millicores), 0 = unset
	LimCPUm   int   // current CPU limit (millicores), 0 = unset
	ReqMemB   int64 // current memory request (bytes), 0 = unset
	LimMemB   int64 // current memory limit (bytes), 0 = unset
	HasReq    bool
	HasLim    bool
	UsageCPUm int   // observed CPU usage (millicores), 0 = unknown
	UsageMemB int64 // observed memory usage (bytes), 0 = unknown
	OOMKilled bool  // a container was OOMKilled
	OOMCount  int
	Pending           bool   // a pod is Pending
	PendingInsufficient string // "memory" | "cpu" | "" — resource the scheduler reported insufficient
	Restarting        bool   // restart storm / repeated restarts
	Replicas          int
}

// ResourceRec is one recommended change to a request or limit.
type ResourceRec struct {
	Resource    string `json:"resource"`  // cpu | memory
	Field       string `json:"field"`     // request | limit
	Direction   string `json:"direction"` // up | down | set
	Current     string `json:"current"`   // formatted (empty when unset)
	Recommended string `json:"recommended"`
	Reason      string `json:"reason"`
}

// ResourceAdvice is the advisor's verdict for one workload.
type ResourceAdvice struct {
	Namespace string        `json:"namespace"`
	Workload  string        `json:"workload"`
	Kind      string        `json:"kind"`
	Severity  string        `json:"severity"` // critical | warning | info
	Symptoms  []string      `json:"symptoms"`
	Recs      []ResourceRec `json:"recommendations"`
	Summary   string        `json:"summary"`
}

const (
	oomLimitHeadroom = 3.0 / 2.0 // OOMKilled → raise memory limit by 50%
	advisorHeadroom  = 1.3       // usage-based recommendations: usage + 30%
	throttleNearLimit = 0.9      // CPU usage within 90% of limit ≈ throttling
)

// AdviseResources turns one workload's symptoms + sizing into recommendations. Returns ok=false
// when there's nothing actionable (no symptoms and well-sized).
func AdviseResources(in ResourceAdvisorInput) (ResourceAdvice, bool) {
	adv := ResourceAdvice{
		Namespace: in.Namespace, Workload: in.Workload, Kind: in.Kind,
		Severity: "info", Symptoms: []string{}, Recs: []ResourceRec{},
	}
	severity := 0 // 0 info, 1 warning, 2 critical
	raise := func(s int) {
		if s > severity {
			severity = s
		}
	}

	// OOMKilled → memory limit is too low. Raise the limit (and request when set).
	if in.OOMKilled {
		adv.Symptoms = append(adv.Symptoms, fmt.Sprintf("OOMKilled%s", countSuffix(in.OOMCount)))
		newLim := oomRecommendedMem(in)
		if newLim > 0 {
			rec := ResourceRec{Resource: "memory", Field: "limit", Direction: "up", Recommended: FormatMemBytes(newLim),
				Reason: "OOMKilled — 메모리 limit이 부족합니다. 사용량/현재 limit 기준으로 상향하세요."}
			if in.LimMemB > 0 {
				rec.Current = FormatMemBytes(in.LimMemB)
			} else {
				rec.Direction = "set"
				rec.Reason = "OOMKilled인데 메모리 limit이 없습니다. 사용량 기준으로 limit을 설정하세요."
			}
			adv.Recs = append(adv.Recs, rec)
			// Keep request ≥ ~60% of the new limit so it schedules onto adequately-sized nodes.
			if in.ReqMemB > 0 && float64(in.ReqMemB) < float64(newLim)*0.6 {
				adv.Recs = append(adv.Recs, ResourceRec{Resource: "memory", Field: "request", Direction: "up",
					Current: FormatMemBytes(in.ReqMemB), Recommended: FormatMemBytes(int64(float64(newLim) * 0.6)),
					Reason: "limit 상향에 맞춰 request도 올려 스케줄링 노드 용량을 확보하세요."})
			}
		}
		raise(2)
	}

	// Pending due to insufficient resources → the request can't be scheduled.
	if in.Pending && in.PendingInsufficient != "" {
		adv.Symptoms = append(adv.Symptoms, "Pending(Insufficient "+in.PendingInsufficient+")")
		switch in.PendingInsufficient {
		case "memory":
			if in.ReqMemB > 0 {
				rec := ResourceRec{Resource: "memory", Field: "request", Direction: "down", Current: FormatMemBytes(in.ReqMemB),
					Reason: "메모리 request가 노드 여유보다 커서 스케줄되지 못합니다. 사용량 기준으로 낮추거나 노드 용량을 확보하세요."}
				if in.UsageMemB > 0 {
					rec.Recommended = FormatMemBytes(int64(float64(in.UsageMemB) * advisorHeadroom))
				}
				adv.Recs = append(adv.Recs, rec)
			}
		case "cpu":
			if in.ReqCPUm > 0 {
				rec := ResourceRec{Resource: "cpu", Field: "request", Direction: "down", Current: FormatCPUMillis(in.ReqCPUm),
					Reason: "CPU request가 노드 여유보다 커서 스케줄되지 못합니다. 사용량 기준으로 낮추거나 노드 용량을 확보하세요."}
				if in.UsageCPUm > 0 {
					rec.Recommended = FormatCPUMillis(int(float64(in.UsageCPUm) * advisorHeadroom))
				}
				adv.Recs = append(adv.Recs, rec)
			}
		}
		raise(2)
	}

	// CPU usage near/over the limit → throttling. Raise the CPU limit.
	if in.LimCPUm > 0 && in.UsageCPUm > 0 && float64(in.UsageCPUm) >= float64(in.LimCPUm)*throttleNearLimit {
		adv.Symptoms = append(adv.Symptoms, "CPU throttling 의심")
		adv.Recs = append(adv.Recs, ResourceRec{Resource: "cpu", Field: "limit", Direction: "up",
			Current: FormatCPUMillis(in.LimCPUm), Recommended: FormatCPUMillis(int(float64(in.UsageCPUm) * oomLimitHeadroom)),
			Reason: "CPU 사용량이 limit에 근접해 throttling이 의심됩니다. limit을 상향하세요."})
		raise(1)
	}

	if in.Restarting {
		adv.Symptoms = append(adv.Symptoms, "반복 재시작")
	}

	// No requests set at all → no QoS guarantee / unreliable scheduling. Recommend setting requests.
	if !in.HasReq {
		adv.Symptoms = append(adv.Symptoms, "request 미설정")
		if in.UsageMemB > 0 {
			adv.Recs = append(adv.Recs, ResourceRec{Resource: "memory", Field: "request", Direction: "set",
				Recommended: FormatMemBytes(int64(float64(in.UsageMemB) * advisorHeadroom)),
				Reason: "request가 없어 QoS·스케줄링이 불안정합니다. 사용량 기준으로 설정하세요."})
		}
		if in.UsageCPUm > 0 {
			adv.Recs = append(adv.Recs, ResourceRec{Resource: "cpu", Field: "request", Direction: "set",
				Recommended: FormatCPUMillis(int(float64(in.UsageCPUm) * advisorHeadroom)),
				Reason: "request가 없어 QoS·스케줄링이 불안정합니다. 사용량 기준으로 설정하세요."})
		}
		raise(1)
	} else if !in.OOMKilled && in.ReqMemB > 0 && in.UsageMemB > int64(float64(in.ReqMemB)*1.1) {
		// Memory usage exceeds request (no OOM yet) → under-provisioned request.
		adv.Symptoms = append(adv.Symptoms, "메모리 사용량 > request")
		adv.Recs = append(adv.Recs, ResourceRec{Resource: "memory", Field: "request", Direction: "up",
			Current: FormatMemBytes(in.ReqMemB), Recommended: FormatMemBytes(int64(float64(in.UsageMemB) * advisorHeadroom)),
			Reason: "메모리 사용량이 request를 초과합니다. 안정성을 위해 request를 상향하세요."})
		raise(1)
	}

	if len(adv.Recs) == 0 {
		return ResourceAdvice{}, false
	}
	adv.Severity = []string{"info", "warning", "critical"}[severity]
	adv.Summary = advisorSummary(adv)
	return adv, true
}

// oomRecommendedMem picks the recommended memory limit (bytes) after an OOMKill: peak usage ×2 if
// known, else current limit ×1.5, else request ×2.
func oomRecommendedMem(in ResourceAdvisorInput) int64 {
	switch {
	case in.UsageMemB > 0:
		return int64(float64(in.UsageMemB) * 2)
	case in.LimMemB > 0:
		return int64(float64(in.LimMemB) * oomLimitHeadroom)
	case in.ReqMemB > 0:
		return in.ReqMemB * 2
	default:
		return 0
	}
}

func advisorSummary(adv ResourceAdvice) string {
	return fmt.Sprintf("%s/%s — %s · 권장 %d건", adv.Namespace, adv.Workload, joinSymptoms(adv.Symptoms), len(adv.Recs))
}

func joinSymptoms(s []string) string {
	if len(s) == 0 {
		return "정상"
	}
	out := s[0]
	for _, x := range s[1:] {
		out += ", " + x
	}
	return out
}

func countSuffix(n int) string {
	if n > 1 {
		return fmt.Sprintf(" ×%d", n)
	}
	return ""
}

// SortResourceAdvice orders advice worst-first (critical → warning → info), then by namespace/workload.
func SortResourceAdvice(items []ResourceAdvice) {
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.SliceStable(items, func(i, j int) bool {
		if rank[items[i].Severity] != rank[items[j].Severity] {
			return rank[items[i].Severity] < rank[items[j].Severity]
		}
		if items[i].Namespace != items[j].Namespace {
			return items[i].Namespace < items[j].Namespace
		}
		return items[i].Workload < items[j].Workload
	})
}
