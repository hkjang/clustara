package analyzer

import "fmt"

// Adaptive Collection Policy (CLU-REQ-04).
//
// The v0.9.11 scheduler picks a base cadence purely on realtime-agent liveness (60s without an
// agent, 30m with one). This refines that base by *operational importance*: a cluster's priority
// label, whether it currently has open incidents, and whether any of its workloads are on a watch
// list. An active incident forces a fast cadence regardless of agent (you want fresh data while
// firefighting); watched/high-priority clusters collect more often; low-priority ones back off.
// (Change-aware bursts — CLU-REQ-05 — are applied separately and override this.)

// CollectPolicyInput is the per-cluster signal set for one scheduler tick.
type CollectPolicyInput struct {
	BaseSecs      int    // no-agent base cadence (e.g. 60)
	WithAgentSecs int    // with-agent reconcile cadence (e.g. 1800)
	AgentAlive    bool   // a realtime watch agent is live
	Priority      string // critical | high | normal | low (default normal)
	OpenIncidents int    // open incidents on this cluster
	WatchCount    int    // watch-list entries on this cluster
	IncidentSecs  int    // floor cadence while an incident is open (e.g. 30); 0 → 30
	MinSecs       int    // hard floor (e.g. 15); 0 → 15
}

// EffectiveCollectInterval computes the adaptive collect cadence (seconds) and a short reason.
func EffectiveCollectInterval(in CollectPolicyInput) (int, string) {
	base := in.BaseSecs
	if base <= 0 {
		base = 60
	}
	if in.AgentAlive {
		base = in.WithAgentSecs
		if base <= 0 {
			base = 1800
		}
	}
	minSecs := in.MinSecs
	if minSecs <= 0 {
		minSecs = 15
	}
	incidentSecs := in.IncidentSecs
	if incidentSecs <= 0 {
		incidentSecs = 30
	}

	factor, reason := priorityFactor(in.Priority)
	if in.WatchCount > 0 {
		factor *= 0.5
		reason = "watch 등록 워크로드"
	}

	secs := int(float64(base) * factor)

	// An open incident forces a fast cadence regardless of agent/priority — fresh data while triaging.
	if in.OpenIncidents > 0 {
		if incidentSecs < secs {
			secs = incidentSecs
		}
		reason = fmt.Sprintf("미해결 incident %d건", in.OpenIncidents)
	}

	if secs < minSecs {
		secs = minSecs
	}
	if reason == "" {
		reason = "기본 주기"
	}
	return secs, reason
}

// priorityFactor maps a cluster priority label to a cadence multiplier (lower = more frequent).
func priorityFactor(priority string) (float64, string) {
	switch priority {
	case "critical":
		return 0.25, "우선순위 critical"
	case "high":
		return 0.5, "우선순위 high"
	case "low":
		return 2.0, "우선순위 low"
	default:
		return 1.0, ""
	}
}
