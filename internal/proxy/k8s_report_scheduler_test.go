package proxy

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestK8sReportDue(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	rfc := func(tm time.Time) string { return tm.Format(time.RFC3339Nano) }

	// No interval → manual only, never auto-due.
	if k8sReportDue(store.K8sReportSchedule{Interval: ""}, now) {
		t.Fatal("empty interval should not be due")
	}
	if k8sReportDue(store.K8sReportSchedule{Interval: "bogus"}, now) {
		t.Fatal("invalid interval should not be due")
	}
	// Never run + valid interval → due.
	if !k8sReportDue(store.K8sReportSchedule{Interval: "24h"}, now) {
		t.Fatal("never-run schedule should be due")
	}
	// Ran 25h ago with 24h interval → due.
	if !k8sReportDue(store.K8sReportSchedule{Interval: "24h", LastRunAt: rfc(now.Add(-25 * time.Hour))}, now) {
		t.Fatal("25h since last run with 24h interval should be due")
	}
	// Ran 1h ago with 24h interval → not due.
	if k8sReportDue(store.K8sReportSchedule{Interval: "24h", LastRunAt: rfc(now.Add(-1 * time.Hour))}, now) {
		t.Fatal("1h since last run with 24h interval should not be due")
	}
}
