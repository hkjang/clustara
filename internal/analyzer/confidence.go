package analyzer

import (
	"fmt"
	"strings"
	"time"

	"clustara/internal/store"
)

// Incident Confidence Score: how strongly the available signals corroborate the incident's likely
// cause. It is not a severity score — it answers "왜 이 원인을 믿어야 하는가" by combining a recent
// config change (diff), corroborating warning events, restart/backoff churn, captured evidence,
// related findings and blast radius into a 0–100 score with an explainable factor breakdown.

// ConfidenceFactor is one contributing signal and the points it added.
type ConfidenceFactor struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Points int    `json:"points"`
}

// ConfidenceScore is the rolled-up confidence with its explainable breakdown.
type ConfidenceScore struct {
	Score   int                `json:"score"` // 0–100
	Level   string             `json:"level"` // high | medium | low
	Factors []ConfidenceFactor `json:"factors"`
}

// ConfidenceInput carries the (already-correlated) signals for one incident.
type ConfidenceInput struct {
	Severity      string
	OpenedAt      string
	Events        []store.K8sEvent
	Revisions     []store.K8sResourceRevision
	Findings      []store.K8sSecurityFinding
	EvidenceCount int
	ImpactCount   int
	Now           time.Time
}

// recentChangeWindow is how close before the incident a config change must land to count as a
// likely trigger.
const recentChangeWindow = 30 * time.Minute

var backoffReasons = []string{"BackOff", "Killing", "Unhealthy", "Failed", "FailedMount", "FailedScheduling"}

// ScoreIncidentConfidence computes the confidence score. Pure over its inputs.
func ScoreIncidentConfidence(in ConfidenceInput) ConfidenceScore {
	factors := []ConfidenceFactor{}
	add := func(name, detail string, pts int) {
		if pts > 0 {
			factors = append(factors, ConfidenceFactor{Name: name, Detail: detail, Points: pts})
		}
	}

	// Severity base — a critical condition is inherently a stronger prior.
	switch strings.ToLower(in.Severity) {
	case "critical":
		add("severity", "critical 조건", 30)
	case "high":
		add("severity", "high 조건", 20)
	default:
		add("severity", "심각도 기준선", 10)
	}

	// Recent config change (diff) just before the incident — the strongest causal signal.
	opened, hasOpen := parseTime(in.OpenedAt)
	var bestChange *store.K8sResourceRevision
	for i := range in.Revisions {
		rev := in.Revisions[i]
		if !strings.EqualFold(rev.ChangeKind, "updated") {
			continue
		}
		rt, ok := parseTime(rev.ObservedAt)
		if !ok || !hasOpen {
			continue
		}
		delta := opened.Sub(rt)
		if delta >= 0 && delta <= recentChangeWindow {
			if bestChange == nil {
				bestChange = &in.Revisions[i]
			}
		}
	}
	if bestChange != nil {
		add("recent_change", "장애 직전 설정 변경(diff) 발생 — 배포/구성 변경이 유력 원인", 25)
	}

	// Corroborating warning events.
	warnCount, totalEventCount := 0, 0
	churn := false
	for _, e := range in.Events {
		totalEventCount += maxInt(1, e.Count)
		if strings.EqualFold(e.Type, "Warning") {
			warnCount += maxInt(1, e.Count)
		}
		for _, br := range backoffReasons {
			if strings.Contains(e.Reason, br) {
				churn = true
				break
			}
		}
	}
	if warnCount > 0 {
		add("warning_events", fmt.Sprintf("매칭된 Warning 이벤트 %d건", warnCount), minInt(20, warnCount*5))
	}
	if churn {
		add("restart_churn", "재시작/스케줄 실패 반복(BackOff·Unhealthy·FailedScheduling)", 15)
	}

	// Captured evidence lines.
	if in.EvidenceCount > 0 {
		add("evidence", fmt.Sprintf("수집된 근거 %d건", in.EvidenceCount), minInt(10, in.EvidenceCount*3))
	}
	// Related security/health findings.
	if len(in.Findings) > 0 {
		add("findings", fmt.Sprintf("연관 finding %d건", len(in.Findings)), minInt(10, len(in.Findings)*5))
	}
	// Blast radius — many affected resources raises operational confidence that this matters.
	if in.ImpactCount > 1 {
		add("impact", fmt.Sprintf("영향 리소스 %d개", in.ImpactCount), minInt(10, (in.ImpactCount-1)*2))
	}

	score := 0
	for _, f := range factors {
		score += f.Points
	}
	if score > 100 {
		score = 100
	}
	level := "low"
	switch {
	case score >= 70:
		level = "high"
	case score >= 40:
		level = "medium"
	}
	return ConfidenceScore{Score: score, Level: level, Factors: factors}
}

func parseTime(s string) (time.Time, bool) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
