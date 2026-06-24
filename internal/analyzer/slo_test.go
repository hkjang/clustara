package analyzer

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestComputeSLO(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	window := 30 * 24 * time.Hour // 43200 min
	rfc := func(t time.Time) string { return t.Format(time.RFC3339Nano) }

	incs := []store.K8sIncident{
		// payments: one resolved incident lasting 60 min within window.
		{Namespace: "payments", Status: "resolved",
			OpenedAt: rfc(now.Add(-10 * 24 * time.Hour)), ResolvedAt: rfc(now.Add(-10*24*time.Hour + 60*time.Minute))},
		// payments: still open, started 30 min ago → 30 min downtime.
		{Namespace: "payments", Status: "open", OpenedAt: rfc(now.Add(-30 * time.Minute))},
		// web: resolved, 5 min.
		{Namespace: "web", Status: "resolved",
			OpenedAt: rfc(now.Add(-2 * 24 * time.Hour)), ResolvedAt: rfc(now.Add(-2*24*time.Hour + 5*time.Minute))},
		// stale: opened before the window → must be excluded.
		{Namespace: "payments", Status: "resolved",
			OpenedAt: rfc(now.Add(-40 * 24 * time.Hour)), ResolvedAt: rfc(now.Add(-40 * 24 * time.Hour))},
	}

	lines := ComputeSLO(incs, now, window, 99.9)
	by := map[string]SLOLine{}
	for _, l := range lines {
		by[l.Namespace] = l
	}
	pay := by["payments"]
	if pay.Incidents != 2 || pay.Open != 1 {
		t.Fatalf("payments counts: %+v (stale incident should be excluded)", pay)
	}
	// downtime = 60 + 30 = 90 min; MTTR only counts the one resolved-in-window = 60 min.
	if pay.DowntimeMinutes != 90 || pay.MTTRMinutes != 60 {
		t.Fatalf("payments downtime/mttr: %+v", pay)
	}
	// allowed budget = 43200 * 0.1% = 43.2 min; 90 min consumed → budget exhausted, breached.
	if !pay.Breached || pay.ErrorBudgetRemainingPct != 0 {
		t.Fatalf("payments should breach with 0 budget left: %+v", pay)
	}
	// Worst availability first → payments before web.
	if lines[0].Namespace != "payments" {
		t.Fatalf("expected payments (worst) first, got %s", lines[0].Namespace)
	}
	if by["web"].Breached {
		t.Fatalf("web (5 min) should not breach: %+v", by["web"])
	}
}
