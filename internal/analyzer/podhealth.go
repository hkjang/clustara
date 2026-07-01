package analyzer

import (
	"sort"
	"strconv"
	"strings"
)

// Pod Health Score: a 0–100 operational health score per Pod plus an auto-detected primary symptom
// (CrashLoopBackOff / OOMKilled / ImagePullBackOff / Pending / …) so the Pod list can answer
// "어디부터 봐야 하는지" without the operator reading describe/logs by hand. Pure over its input.

// PodHealthInput carries the parsed Pod signals (the caller maps its Pod view onto these primitives
// so this stays decoupled from the proxy/store types).
type PodHealthInput struct {
	Phase                 string   // Running | Pending | Failed | Succeeded | ...
	ContainerCount        int      // total containers (init+app) with status
	ReadyCount            int      // ready containers
	RestartCount          int      // summed restart count
	RecentRestartCount    int      // restart count that still has recent/current evidence
	RestartRecencyKnown   bool     // when true, RestartCount without RecentRestartCount is treated as historical
	RestartAlertThreshold int      // recent restart count at/above this value becomes a symptom (default 3)
	WarningEvents         int      // matched Warning events
	RiskLevel             string   // inventory risk: low|medium|high|critical
	RecentChange          bool     // a recent deploy/config change correlated to this pod
	Deleting              bool     // has a deletion timestamp (Terminating)
	ContainerReasons      []string // waiting/terminated reasons across containers (current + last state)
}

// PodHealth is the scored result with an explainable breakdown.
type PodHealth struct {
	Score          int      `json:"score"`           // 0–100 (higher = healthier)
	Band           string   `json:"band"`            // healthy | warning | critical
	PrimarySymptom string   `json:"primary_symptom"` // dominant problem tag, "Healthy" if none
	Symptoms       []string `json:"symptoms"`        // all detected problem tags
	Reasons        []string `json:"reasons"`         // human-readable scoring factors
}

// symptomRule maps a detectable symptom to its severity weighting. Order = detection priority
// (highest-impact first); the first matching symptom becomes PrimarySymptom.
type symptomRule struct {
	tag      string
	penalty  int
	critical bool
	match    func(in PodHealthInput, reasons string) bool
}

var podSymptomRules = []symptomRule{
	{tag: "OOMKilled", penalty: 60, critical: true, match: func(_ PodHealthInput, r string) bool { return strings.Contains(r, "oomkilled") }},
	{tag: "CrashLoopBackOff", penalty: 60, critical: true, match: func(_ PodHealthInput, r string) bool { return strings.Contains(r, "crashloop") }},
	{tag: "ImagePullBackOff", penalty: 50, critical: true, match: func(_ PodHealthInput, r string) bool {
		return strings.Contains(r, "imagepull") || strings.Contains(r, "errimagepull") || strings.Contains(r, "imageinspecterror")
	}},
	{tag: "CreateContainerError", penalty: 45, critical: true, match: func(_ PodHealthInput, r string) bool {
		return strings.Contains(r, "createcontainer") || strings.Contains(r, "configerror")
	}},
	{tag: "Evicted", penalty: 50, critical: true, match: func(in PodHealthInput, r string) bool {
		return strings.Contains(r, "evicted") || (strings.EqualFold(in.Phase, "Failed") && strings.Contains(r, "evict"))
	}},
	{tag: "Pending", penalty: 40, critical: false, match: func(in PodHealthInput, _ string) bool {
		return strings.EqualFold(in.Phase, "Pending")
	}},
	{tag: "Terminating", penalty: 25, critical: false, match: func(in PodHealthInput, _ string) bool { return in.Deleting }},
	{tag: "ProbeFailing", penalty: 30, critical: false, match: func(in PodHealthInput, r string) bool {
		notReady := in.ContainerCount > 0 && in.ReadyCount < in.ContainerCount
		return notReady && (in.WarningEvents > 0 || strings.Contains(r, "unhealthy") || strings.Contains(r, "probe"))
	}},
}

// ScorePodHealth computes the Pod health score and primary symptom.
func ScorePodHealth(in PodHealthInput) PodHealth {
	reasonsBlob := strings.ToLower(strings.Join(in.ContainerReasons, " "))
	score := 100
	symptoms := []string{}
	factors := []string{}
	primary := ""
	forceCritical := false

	for _, rule := range podSymptomRules {
		if !rule.match(in, reasonsBlob) {
			continue
		}
		symptoms = append(symptoms, rule.tag)
		score -= rule.penalty
		factors = append(factors, rule.tag+" 감지 (-"+strconv.Itoa(rule.penalty)+")")
		if primary == "" {
			primary = rule.tag
		}
		if rule.critical {
			forceCritical = true
		}
	}

	restartScoreCount := in.RestartCount
	if in.RestartRecencyKnown {
		restartScoreCount = in.RecentRestartCount
	}
	if restartScoreCount > 0 {
		p := minInt(35, restartScoreCount*6)
		score -= p
		factors = append(factors, "최근 재시작 징후 "+strconv.Itoa(restartScoreCount)+"회 (-"+strconv.Itoa(p)+")")
		threshold := in.RestartAlertThreshold
		if threshold <= 0 {
			threshold = 3
		}
		if restartScoreCount >= threshold {
			symptoms = append(symptoms, "RecentRestart")
			if primary == "" {
				primary = "RecentRestart"
			}
		}
	} else if in.RestartRecencyKnown && in.RestartCount > 0 {
		factors = append(factors, "과거 재시작 "+strconv.Itoa(in.RestartCount)+"회 — 현재 안정 상태로 보정")
	}
	if in.WarningEvents > 0 {
		p := minInt(20, in.WarningEvents*5)
		score -= p
		factors = append(factors, "Warning 이벤트 "+strconv.Itoa(in.WarningEvents)+"건 (-"+strconv.Itoa(p)+")")
	}
	if in.ContainerCount > 0 && in.ReadyCount < in.ContainerCount {
		p := minInt(30, (in.ContainerCount-in.ReadyCount)*10)
		score -= p
		factors = append(factors, "Ready "+strconv.Itoa(in.ReadyCount)+"/"+strconv.Itoa(in.ContainerCount)+" (-"+strconv.Itoa(p)+")")
	}
	switch strings.ToLower(in.RiskLevel) {
	case "critical":
		score -= 25
		factors = append(factors, "인벤토리 위험도 critical (-25)")
	case "high":
		score -= 15
		factors = append(factors, "인벤토리 위험도 high (-15)")
	}
	if in.RecentChange {
		factors = append(factors, "최근 배포/설정 변경 있음")
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	band := "healthy"
	switch {
	case forceCritical || score < 40:
		band = "critical"
	case score < 70 || len(symptoms) > 0:
		band = "warning"
	}
	if primary == "" {
		if band == "healthy" {
			primary = "Healthy"
		} else {
			primary = "Degraded"
		}
	}
	sort.Strings(symptoms)
	return PodHealth{Score: score, Band: band, PrimarySymptom: primary, Symptoms: symptoms, Reasons: factors}
}
