package analyzer

import "testing"

func TestEffectiveCollectInterval(t *testing.T) {
	// No agent, normal priority → base.
	if secs, _ := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 60, WithAgentSecs: 1800}); secs != 60 {
		t.Fatalf("normal no-agent should be 60, got %d", secs)
	}
	// Agent alive → reconcile base.
	if secs, _ := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 60, WithAgentSecs: 1800, AgentAlive: true}); secs != 1800 {
		t.Fatalf("agent-alive should be 1800, got %d", secs)
	}
	// High priority halves the base.
	if secs, r := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 60, Priority: "high"}); secs != 30 || r != "우선순위 high" {
		t.Fatalf("high priority should be 30, got %d (%s)", secs, r)
	}
	// Critical = quarter, clamped at min floor.
	if secs, _ := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 60, Priority: "critical"}); secs != 15 {
		t.Fatalf("critical 60*0.25=15, got %d", secs)
	}
	// Low priority doubles (back off).
	if secs, _ := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 60, Priority: "low"}); secs != 120 {
		t.Fatalf("low priority 60*2=120, got %d", secs)
	}
	// Watch-list halves the (priority-adjusted) cadence.
	if secs, r := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 60, WatchCount: 2}); secs != 30 || r != "watch 등록 워크로드" {
		t.Fatalf("watch should halve to 30, got %d (%s)", secs, r)
	}
	// Open incident forces fast cadence even with a live agent (reconcile base 1800).
	secs, r := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 60, WithAgentSecs: 1800, AgentAlive: true, OpenIncidents: 2, IncidentSecs: 30})
	if secs != 30 {
		t.Fatalf("open incident should force 30 even with agent, got %d", secs)
	}
	if r != "미해결 incident 2건" {
		t.Fatalf("reason should cite incidents: %s", r)
	}
	// Min floor respected.
	if secs, _ := EffectiveCollectInterval(CollectPolicyInput{BaseSecs: 10, Priority: "critical", MinSecs: 15}); secs != 15 {
		t.Fatalf("should clamp to min 15, got %d", secs)
	}
}
