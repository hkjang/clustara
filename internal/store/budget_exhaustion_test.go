package store

import (
	"context"
	"testing"
	"time"
)

// The exhaustion date is "when cumulative spend at the current run-rate hits the
// budget". A low run rate makes that number of days enormous, and
// float64 → time.Duration overflows past roughly 106,751 days into a NEGATIVE
// duration — so start.Add(d) lands centuries before the month began, which then
// satisfies the "not after month end" test and gets published.
//
// A 1,000,000 KRW budget with 0.05 KRW spent early in the month reported an
// exhaustion date of 1734-04-22: the dashboard showed the budget as long
// exhausted exactly when spending was lowest.
func TestBudgetExhaustionDateIsNotReportedInThePast(t *testing.T) {
	db := openStoreForTest(t)
	defer db.Close()
	ctx := context.Background()

	now := time.Date(2026, 8, 1, 9, 0, 0, 0, budgetKST) // the very start of a month
	seedBudgetSpend(t, db, "team", "platform", 0.05, now)

	st, err := db.budgetStatus(ctx, Budget{
		ID: "b1", Scope: "team", ScopeValue: "platform", MonthlyKRW: 1000000,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.ExhaustionDate == "" {
		return // nothing published, which is the correct answer at this run rate
	}
	parsed, perr := time.Parse("2006-01-02", st.ExhaustionDate)
	if perr != nil {
		t.Fatalf("unparseable exhaustion date %q", st.ExhaustionDate)
	}
	if parsed.Before(now.AddDate(0, 0, -1)) {
		t.Fatalf("exhaustion date %s is in the past: a run rate this low overflows the duration "+
			"conversion, and the negative result passes the month-end check", st.ExhaustionDate)
	}
}

// A run rate that really does exhaust the budget within the month must still
// produce a date, or the guard would just suppress the feature.
func TestBudgetExhaustionDateIsStillReportedWhenItFallsInTheMonth(t *testing.T) {
	db := openStoreForTest(t)
	defer db.Close()
	ctx := context.Background()

	// Half the month gone, 80% of the budget spent: exhaustion lands before month end.
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, budgetKST)
	seedBudgetSpend(t, db, "team", "platform", 800, now)

	st, err := db.budgetStatus(ctx, Budget{
		ID: "b1", Scope: "team", ScopeValue: "platform", MonthlyKRW: 1000,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.ExhaustionDate == "" {
		t.Fatalf("no exhaustion date for a budget on track to run out this month: %+v", st)
	}
	parsed, err := time.Parse("2006-01-02", st.ExhaustionDate)
	if err != nil {
		t.Fatal(err)
	}
	monthStart, daysInMonth := kstMonthBounds(now)
	if parsed.Before(monthStart) || parsed.After(monthStart.AddDate(0, 0, int(daysInMonth))) {
		t.Fatalf("exhaustion date %s falls outside the month", st.ExhaustionDate)
	}
}

func seedBudgetSpend(t *testing.T, db *SQLStore, scope, value string, krw float64, now time.Time) {
	t.Helper()
	ctx := context.Background()
	at := now.Add(-time.Minute)
	if err := db.InsertLogRecord(ctx, LogRecord{
		Request: RequestLog{
			ID: "req_budget", TraceID: "tr", APIKeyID: "key_b", Endpoint: "/v1/chat/completions",
			Model: "m", Provider: "p", StatusCode: 200, CreatedAt: at,
		},
		Usage: &TokenUsage{
			ID: "usage_budget", RequestID: "req_budget", TotalTokens: 10,
			EstimatedCost: krw, Currency: "KRW", CreatedAt: at,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAPIKey(ctx, APIKeyRecord{
		ID: "key_b", Name: "k", KeyHash: "h", Team: value, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
}
