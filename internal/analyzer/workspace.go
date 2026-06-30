package analyzer

import (
	"fmt"
	"sort"
)

// Workspace Center (CLU-OCP-01 / CLU-WS-002).
//
// Absorbs OpenShift's "Project" UX as a generic Kubernetes notion: a Workspace = a namespace plus
// its operational context (owner team, environment, criticality). ScoreWorkspaceHealth combines the
// signals Clustara already collects — pod health, open incidents, quota pressure, external exposure,
// runtime-security findings — into one 0..100 trust score per workspace, so an operator scans
// business units instead of raw namespaces. Pure: the handler aggregates the counts and passes them.

// WorkspaceInput is one namespace's aggregated operational signals.
type WorkspaceInput struct {
	Namespace        string
	OwnerTeam        string
	Environment      string
	Criticality      string  // critical | high | normal | low (informational)
	PodTotal         int
	PodCritical      int
	PodWarning       int
	OpenIncidents    int
	QuotaUsedPct     float64 // 0..100; -1 = no quota / unknown
	Exposed          bool    // has an Ingress / LoadBalancer
	SecurityFindings int     // privileged / hostPath / runAsRoot etc. pods
}

// WorkspaceHealth is the scored result for one workspace.
type WorkspaceHealth struct {
	Namespace     string   `json:"namespace"`
	OwnerTeam     string   `json:"owner_team,omitempty"`
	Environment   string   `json:"environment,omitempty"`
	Criticality   string   `json:"criticality,omitempty"`
	Score         int      `json:"score"`
	Band          string   `json:"band"` // healthy | warning | critical
	PodTotal      int      `json:"pod_total"`
	PodCritical   int      `json:"pod_critical"`
	PodWarning    int      `json:"pod_warning"`
	OpenIncidents int      `json:"open_incidents"`
	QuotaUsedPct  float64  `json:"quota_used_pct"`
	Exposed       bool     `json:"exposed"`
	SecurityRisk  int      `json:"security_findings"`
	Reasons       []string `json:"reasons"`
}

// ScoreWorkspaceHealth combines workspace signals into a 0..100 score (higher = healthier).
func ScoreWorkspaceHealth(in WorkspaceInput) WorkspaceHealth {
	out := WorkspaceHealth{
		Namespace: in.Namespace, OwnerTeam: in.OwnerTeam, Environment: in.Environment, Criticality: in.Criticality,
		PodTotal: in.PodTotal, PodCritical: in.PodCritical, PodWarning: in.PodWarning,
		OpenIncidents: in.OpenIncidents, QuotaUsedPct: round2(in.QuotaUsedPct), Exposed: in.Exposed,
		SecurityRisk: in.SecurityFindings, Reasons: []string{},
	}
	score := 100

	// Open incidents dominate.
	if in.OpenIncidents > 0 {
		p := min2(40, 20+in.OpenIncidents*10)
		score -= p
		out.Reasons = append(out.Reasons, fmt.Sprintf("미해결 incident %d건", in.OpenIncidents))
	}
	// Pod health: critical pods weigh heavier than warnings, scaled by share of the workspace.
	if in.PodCritical > 0 {
		p := min2(35, 15+in.PodCritical*5)
		score -= p
		out.Reasons = append(out.Reasons, fmt.Sprintf("위험 Pod %d개", in.PodCritical))
	} else if in.PodWarning > 0 {
		score -= min2(15, in.PodWarning*3)
		out.Reasons = append(out.Reasons, fmt.Sprintf("주의 Pod %d개", in.PodWarning))
	}
	// Quota pressure.
	switch {
	case in.QuotaUsedPct >= 95:
		score -= 20
		out.Reasons = append(out.Reasons, fmt.Sprintf("Quota 사용률 %.0f%%(임박)", in.QuotaUsedPct))
	case in.QuotaUsedPct >= 80:
		score -= 8
		out.Reasons = append(out.Reasons, fmt.Sprintf("Quota 사용률 %.0f%%", in.QuotaUsedPct))
	}
	// Security findings (privileged/hostPath/runAsRoot ...).
	if in.SecurityFindings > 0 {
		p := min2(25, in.SecurityFindings*5)
		score -= p
		out.Reasons = append(out.Reasons, fmt.Sprintf("런타임 보안 위험 %d건", in.SecurityFindings))
	}
	// Exposure is not a penalty by itself, but raises severity when combined with the above —
	// an exposed workspace with risks is higher blast radius. Apply a small penalty only when
	// the workspace already has critical signals.
	if in.Exposed && (in.PodCritical > 0 || in.OpenIncidents > 0 || in.SecurityFindings > 0) {
		score -= 5
		out.Reasons = append(out.Reasons, "외부 노출 + 위험 신호")
	}

	out.Score = clampScore(score)
	switch {
	case out.Score >= 80:
		out.Band = "healthy"
	case out.Score >= 50:
		out.Band = "warning"
	default:
		out.Band = "critical"
	}
	if len(out.Reasons) == 0 {
		out.Reasons = append(out.Reasons, "위험 신호 없음")
	}
	return out
}

// WorkspaceSummary is the fleet rollup for the Workspace Center header.
type WorkspaceSummary struct {
	Total    int `json:"total"`
	Healthy  int `json:"healthy"`
	Warning  int `json:"warning"`
	Critical int `json:"critical"`
	Exposed  int `json:"exposed"`
	Incidents int `json:"incidents"`
}

// SummarizeWorkspaces tallies workspaces by band (worst-first ordering is applied to the slice).
func SummarizeWorkspaces(ws []WorkspaceHealth) WorkspaceSummary {
	s := WorkspaceSummary{Total: len(ws)}
	for _, w := range ws {
		switch w.Band {
		case "healthy":
			s.Healthy++
		case "warning":
			s.Warning++
		default:
			s.Critical++
		}
		if w.Exposed {
			s.Exposed++
		}
		s.Incidents += w.OpenIncidents
	}
	return s
}

// SortWorkspaces orders worst-first (critical → warning → healthy, then lowest score).
func SortWorkspaces(ws []WorkspaceHealth) {
	rank := map[string]int{"critical": 0, "warning": 1, "healthy": 2}
	sort.SliceStable(ws, func(i, j int) bool {
		if rank[ws[i].Band] != rank[ws[j].Band] {
			return rank[ws[i].Band] < rank[ws[j].Band]
		}
		if ws[i].Score != ws[j].Score {
			return ws[i].Score < ws[j].Score
		}
		return ws[i].Namespace < ws[j].Namespace
	})
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
