package analyzer

import (
	"fmt"
	"sort"
	"time"
)

// Inventory Freshness Score (CLU-REQ-01) + Stale Warning (CLU-REQ-10).
//
// Once the adaptive collector (v0.9.11) keeps inventory updated automatically, the next
// operational question is "can I trust what I'm looking at right now?". This computes a
// 0..100 freshness score per scope (cluster / namespace / kind) from collection timing,
// realtime-agent liveness, and recent collect failures — so every screen can show a data
// timestamp and a stale warning instead of silently presenting old data as current.
//
// Pure functions only: the proxy handler reads store rows, builds FreshnessInput values,
// and calls ScoreFreshness / SummarizeFreshness.

// FreshnessInput captures the collection-timing signals for a single scope. Times are zero
// when unknown (e.g. never collected, no agent). ExpectedInterval is the cluster's adaptive
// collect cadence (60s without a live agent, 1800s with one).
type FreshnessInput struct {
	Scope            string        // "cluster" | "namespace" | "kind"
	Key              string        // cluster id, namespace, or kind label
	ClusterID        string        // owning cluster (echoed through for grouping)
	LastCollectedAt  time.Time     // newest ObservedAt/UpdatedAt in scope (zero = never)
	AgentAlive       bool          // a realtime watch agent is currently live (heartbeat fresh)
	AgentAttached    bool          // an agent has reported at least once (alive or stale)
	AgentLastSeen    time.Time     // last heartbeat (zero = none)
	ExpectedInterval time.Duration // adaptive collect cadence for this cluster
	FailedAttempts   int           // consecutive failed collect attempts
	ResourceCount    int           // resources observed in scope
	Now              time.Time
}

// FreshnessFactor is one explainable contribution to the score (negative Delta = penalty).
type FreshnessFactor struct {
	Label string `json:"label"`
	Delta int    `json:"delta"`
}

// Freshness is the scored result for one scope.
type Freshness struct {
	Scope         string            `json:"scope"`
	Key           string            `json:"key"`
	ClusterID     string            `json:"cluster_id,omitempty"`
	Score         int               `json:"score"` // 0..100
	Band          string            `json:"band"`  // fresh | aging | stale | unknown
	Stale         bool              `json:"stale"`
	AgeSeconds    int64             `json:"age_seconds"` // since reference time (-1 = never collected)
	LagRatio      float64           `json:"lag_ratio"`   // age / expected interval (0 when never/unknown)
	ResourceCount int               `json:"resource_count"`
	ReferenceAt   string            `json:"reference_at,omitempty"` // RFC3339 freshness reference time
	AgentAlive    bool              `json:"agent_alive"`
	Reason        string            `json:"reason"`
	Factors       []FreshnessFactor `json:"factors"`
}

const (
	freshnessFreshBand = "fresh"
	freshnessAgingBand = "aging"
	freshnessStaleBand = "stale"
	freshnessUnknown   = "unknown"

	// Fallback cadence when a caller doesn't know the cluster's configured interval.
	defaultExpectedInterval = 60 * time.Second
)

// ScoreFreshness rates how trustworthy the collected data for one scope is right now.
func ScoreFreshness(in FreshnessInput) Freshness {
	out := Freshness{
		Scope:         orDefault(in.Scope, "cluster"),
		Key:           in.Key,
		ClusterID:     in.ClusterID,
		ResourceCount: in.ResourceCount,
		AgentAlive:    in.AgentAlive,
		AgeSeconds:    -1,
		Factors:       []FreshnessFactor{},
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Never collected → cannot trust anything in this scope.
	if in.LastCollectedAt.IsZero() {
		out.Score = 0
		out.Band = freshnessUnknown
		out.Stale = true
		out.Reason = "수집 기록이 없습니다 — 데이터를 신뢰할 수 없습니다."
		out.Factors = append(out.Factors, FreshnessFactor{Label: "수집 기록 없음", Delta: -100})
		return out
	}

	// A live agent streams changes continuously, so its heartbeat is a stronger freshness
	// signal than the last reconcile poll. Use whichever proves the data is most recent.
	reference := in.LastCollectedAt
	if in.AgentAlive && in.AgentLastSeen.After(reference) {
		reference = in.AgentLastSeen
	}
	out.ReferenceAt = reference.UTC().Format(time.RFC3339)

	age := now.Sub(reference)
	if age < 0 {
		age = 0
	}
	out.AgeSeconds = int64(age / time.Second)

	expected := in.ExpectedInterval
	if expected <= 0 {
		expected = defaultExpectedInterval
	}
	out.LagRatio = round2(float64(age) / float64(expected))

	score := 100

	// Lag against the cluster's own expected cadence. One interval of slack is "on schedule".
	switch {
	case out.LagRatio <= 1:
		// on schedule — no penalty
	case out.LagRatio <= 2:
		score -= 15
		out.Factors = append(out.Factors, FreshnessFactor{Label: fmt.Sprintf("수집 주기의 %.1f배 경과", out.LagRatio), Delta: -15})
	case out.LagRatio <= 4:
		score -= 35
		out.Factors = append(out.Factors, FreshnessFactor{Label: fmt.Sprintf("수집 주기의 %.1f배 경과", out.LagRatio), Delta: -35})
	case out.LagRatio <= 8:
		score -= 60
		out.Factors = append(out.Factors, FreshnessFactor{Label: fmt.Sprintf("수집 주기의 %.1f배 경과", out.LagRatio), Delta: -60})
	default:
		score -= 85
		out.Factors = append(out.Factors, FreshnessFactor{Label: fmt.Sprintf("수집 주기의 %.0f배 이상 경과", out.LagRatio), Delta: -85})
	}

	// Recent collect failures erode trust regardless of timestamp.
	if in.FailedAttempts > 0 {
		penalty := in.FailedAttempts * 10
		if penalty > 40 {
			penalty = 40
		}
		score -= penalty
		out.Factors = append(out.Factors, FreshnessFactor{Label: fmt.Sprintf("연속 수집 실패 %d회", in.FailedAttempts), Delta: -penalty})
	}

	// A live realtime agent means changes arrive continuously between reconcile polls.
	if in.AgentAlive {
		score += 5
		out.Factors = append(out.Factors, FreshnessFactor{Label: "실시간 agent 수신 중", Delta: +5})
	} else if in.AgentAttached {
		// An agent was attached but its heartbeat went stale — the stream we relied on is down.
		score -= 15
		out.Factors = append(out.Factors, FreshnessFactor{Label: "실시간 agent 오프라인", Delta: -15})
	}

	// Collected but empty: either a genuinely empty scope or a partial/failed collect.
	if in.ResourceCount == 0 {
		score -= 10
		out.Factors = append(out.Factors, FreshnessFactor{Label: "수집된 리소스 없음", Delta: -10})
	}

	out.Score = clampScore(score)
	out.Band, out.Stale = freshnessBand(out.Score)
	out.Reason = freshnessReason(out)
	return out
}

func freshnessBand(score int) (string, bool) {
	switch {
	case score >= 80:
		return freshnessFreshBand, false
	case score >= 50:
		return freshnessAgingBand, false
	default:
		return freshnessStaleBand, true
	}
}

func freshnessReason(f Freshness) string {
	mins := f.AgeSeconds / 60
	ageText := fmt.Sprintf("%d초 전", f.AgeSeconds)
	if mins >= 1 {
		ageText = fmt.Sprintf("%d분 전", mins)
	}
	switch f.Band {
	case freshnessFreshBand:
		if f.AgentAlive {
			return "실시간 agent로 최신 상태가 유지되고 있습니다."
		}
		return fmt.Sprintf("최근 수집(%s) — 데이터가 최신입니다.", ageText)
	case freshnessAgingBand:
		return fmt.Sprintf("마지막 수집 %s — 데이터가 다소 오래됐습니다.", ageText)
	default:
		return fmt.Sprintf("마지막 수집 %s — 오래된 데이터일 수 있어 판단에 주의가 필요합니다.", ageText)
	}
}

// FreshnessSummary aggregates per-scope scores for the home/collection-status overview.
type FreshnessSummary struct {
	Total        int         `json:"total"`
	Fresh        int         `json:"fresh"`
	Aging        int         `json:"aging"`
	Stale        int         `json:"stale"`
	Unknown      int         `json:"unknown"`
	WorstScore   int         `json:"worst_score"`   // 100 when nothing scored
	AverageScore int         `json:"average_score"` // 0..100
	StaleScopes  []Freshness `json:"stale_scopes"`  // stale/unknown, worst-first
}

// SummarizeFreshness rolls up per-scope freshness into counts + the worst offenders.
func SummarizeFreshness(items []Freshness) FreshnessSummary {
	out := FreshnessSummary{Total: len(items), WorstScore: 100, StaleScopes: []Freshness{}}
	if len(items) == 0 {
		return out
	}
	sum := 0
	for _, it := range items {
		sum += it.Score
		if it.Score < out.WorstScore {
			out.WorstScore = it.Score
		}
		switch it.Band {
		case freshnessFreshBand:
			out.Fresh++
		case freshnessAgingBand:
			out.Aging++
		case freshnessUnknown:
			out.Unknown++
			out.StaleScopes = append(out.StaleScopes, it)
		default:
			out.Stale++
			out.StaleScopes = append(out.StaleScopes, it)
		}
	}
	out.AverageScore = sum / len(items)
	sort.SliceStable(out.StaleScopes, func(i, j int) bool {
		return out.StaleScopes[i].Score < out.StaleScopes[j].Score
	})
	return out
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
