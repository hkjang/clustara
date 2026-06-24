package analyzer

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestScoreIncidentConfidence(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	opened := now.Add(-5 * time.Minute)
	rfc := func(tm time.Time) string { return tm.Format(time.RFC3339Nano) }

	// Strong case: critical + config change 10m before open + warning events + backoff + evidence.
	strong := ConfidenceInput{
		Severity: "critical",
		OpenedAt: rfc(opened),
		Revisions: []store.K8sResourceRevision{
			{ChangeKind: "updated", ObservedAt: rfc(opened.Add(-10 * time.Minute))},
		},
		Events: []store.K8sEvent{
			{Type: "Warning", Reason: "BackOff", Count: 3},
			{Type: "Warning", Reason: "Unhealthy", Count: 1},
		},
		EvidenceCount: 3,
		Findings:      []store.K8sSecurityFinding{{}},
		ImpactCount:   4,
		Now:           now,
	}
	got := ScoreIncidentConfidence(strong)
	if got.Level != "high" || got.Score < 70 {
		t.Fatalf("strong case should be high: %+v", got)
	}
	// Factors must be explainable and include the causal change.
	hasChange := false
	for _, f := range got.Factors {
		if f.Name == "recent_change" {
			hasChange = true
		}
	}
	if !hasChange {
		t.Fatalf("strong case should credit recent_change: %+v", got.Factors)
	}

	// Weak case: low severity, no change, no events.
	weak := ScoreIncidentConfidence(ConfidenceInput{Severity: "low", OpenedAt: rfc(opened), Now: now})
	if weak.Level != "low" || weak.Score >= 40 {
		t.Fatalf("weak case should be low: %+v", weak)
	}

	// A config change OUTSIDE the window must not be credited.
	stale := ScoreIncidentConfidence(ConfidenceInput{
		Severity: "high", OpenedAt: rfc(opened),
		Revisions: []store.K8sResourceRevision{{ChangeKind: "updated", ObservedAt: rfc(opened.Add(-2 * time.Hour))}},
		Now:       now,
	})
	for _, f := range stale.Factors {
		if f.Name == "recent_change" {
			t.Fatalf("change outside window should not count: %+v", stale.Factors)
		}
	}

	// Score is capped at 100.
	if got.Score > 100 {
		t.Fatalf("score must be capped at 100, got %d", got.Score)
	}
}
