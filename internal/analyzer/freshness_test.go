package analyzer

import (
	"testing"
	"time"
)

func TestScoreFreshness(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	minInterval := 60 * time.Second

	// Never collected → unknown, stale, score 0.
	never := ScoreFreshness(FreshnessInput{Scope: "cluster", Key: "c1", Now: now})
	if never.Band != freshnessUnknown || !never.Stale || never.Score != 0 {
		t.Fatalf("never-collected should be unknown/stale/0: %+v", never)
	}
	if never.AgeSeconds != -1 {
		t.Fatalf("never-collected age should be -1: %+v", never)
	}

	// Just collected, on schedule, with resources → fresh, not stale.
	fresh := ScoreFreshness(FreshnessInput{
		Scope: "cluster", Key: "c1",
		LastCollectedAt: now.Add(-30 * time.Second),
		ExpectedInterval: minInterval, ResourceCount: 120, Now: now,
	})
	if fresh.Band != freshnessFreshBand || fresh.Stale {
		t.Fatalf("recent collect should be fresh: %+v", fresh)
	}
	if fresh.Score != 100 {
		t.Fatalf("on-schedule with resources should be 100: %+v", fresh)
	}

	// 3x interval behind → aging band, penalized but not yet stale.
	aging := ScoreFreshness(FreshnessInput{
		Scope: "cluster", Key: "c1",
		LastCollectedAt: now.Add(-180 * time.Second), // 3x of 60s
		ExpectedInterval: minInterval, ResourceCount: 50, Now: now,
	})
	if aging.Band != freshnessAgingBand {
		t.Fatalf("3x interval should be aging: %+v", aging)
	}
	if aging.Score >= fresh.Score {
		t.Fatalf("aging must score below fresh: aging=%d fresh=%d", aging.Score, fresh.Score)
	}

	// Far behind (10x) → stale.
	stale := ScoreFreshness(FreshnessInput{
		Scope: "cluster", Key: "c1",
		LastCollectedAt: now.Add(-600 * time.Second), // 10x of 60s
		ExpectedInterval: minInterval, ResourceCount: 50, Now: now,
	})
	if stale.Band != freshnessStaleBand || !stale.Stale {
		t.Fatalf("10x interval should be stale: %+v", stale)
	}

	// A live agent keeps an otherwise-old reconcile poll fresh via its heartbeat.
	agent := ScoreFreshness(FreshnessInput{
		Scope: "cluster", Key: "c2",
		LastCollectedAt:  now.Add(-25 * time.Minute), // old reconcile poll
		AgentAlive:       true,
		AgentAttached:    true,
		AgentLastSeen:    now.Add(-10 * time.Second), // but agent is streaming
		ExpectedInterval: 30 * time.Minute,
		ResourceCount:    200, Now: now,
	})
	if agent.Band != freshnessFreshBand || agent.Stale {
		t.Fatalf("live agent should keep data fresh: %+v", agent)
	}
	if agent.ReferenceAt == "" || agent.AgeSeconds > 60 {
		t.Fatalf("agent heartbeat should be the freshness reference: %+v", agent)
	}

	// An attached-but-offline agent is penalized (the stream we relied on is down).
	offline := ScoreFreshness(FreshnessInput{
		Scope: "cluster", Key: "c2",
		LastCollectedAt:  now.Add(-90 * time.Second),
		AgentAttached:    true,
		AgentAlive:       false,
		AgentLastSeen:    now.Add(-5 * time.Minute),
		ExpectedInterval: minInterval, ResourceCount: 200, Now: now,
	})
	hasOfflineFactor := false
	for _, f := range offline.Factors {
		if f.Label == "실시간 agent 오프라인" {
			hasOfflineFactor = true
		}
	}
	if !hasOfflineFactor {
		t.Fatalf("offline agent should add a penalty factor: %+v", offline.Factors)
	}

	// Consecutive failures erode trust even when the timestamp is recent.
	failing := ScoreFreshness(FreshnessInput{
		Scope: "cluster", Key: "c3",
		LastCollectedAt: now.Add(-20 * time.Second),
		ExpectedInterval: minInterval, ResourceCount: 30, FailedAttempts: 3, Now: now,
	})
	if failing.Score >= fresh.Score {
		t.Fatalf("failures must lower the score: failing=%d fresh=%d", failing.Score, fresh.Score)
	}
}

func TestSummarizeFreshness(t *testing.T) {
	empty := SummarizeFreshness(nil)
	if empty.Total != 0 || empty.WorstScore != 100 || len(empty.StaleScopes) != 0 {
		t.Fatalf("empty summary should be zero/100/empty: %+v", empty)
	}

	items := []Freshness{
		{Key: "a", Score: 95, Band: freshnessFreshBand},
		{Key: "b", Score: 60, Band: freshnessAgingBand},
		{Key: "c", Score: 30, Band: freshnessStaleBand, Stale: true},
		{Key: "d", Score: 0, Band: freshnessUnknown, Stale: true},
	}
	s := SummarizeFreshness(items)
	if s.Total != 4 || s.Fresh != 1 || s.Aging != 1 || s.Stale != 1 || s.Unknown != 1 {
		t.Fatalf("band counts wrong: %+v", s)
	}
	if s.WorstScore != 0 {
		t.Fatalf("worst score should be 0: %+v", s)
	}
	if s.AverageScore != (95+60+30+0)/4 {
		t.Fatalf("average wrong: %+v", s)
	}
	// Stale scopes worst-first: d (0) before c (30).
	if len(s.StaleScopes) != 2 || s.StaleScopes[0].Key != "d" || s.StaleScopes[1].Key != "c" {
		t.Fatalf("stale scopes should be worst-first [d,c]: %+v", s.StaleScopes)
	}
}
