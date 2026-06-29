package analyzer

import (
	"strings"
	"testing"
)

func TestFormatReportDigest(t *testing.T) {
	// Healthy → green, no failures.
	d := FormatReportDigest(ReportDigestInput{ClusterID: "prod", Workloads: 12, SecurityScore: 90, MonthlyCostKRW: 1234567})
	if !strings.Contains(d, "🟢") || !strings.Contains(d, "prod") {
		t.Fatalf("healthy digest: %q", d)
	}
	if !strings.Contains(d, "1,234,567") {
		t.Fatalf("cost should be comma-formatted: %q", d)
	}

	// Failures + SLO breach → red headline.
	d = FormatReportDigest(ReportDigestInput{ClusterID: "prod", HighFailures: 3, SLOBreaches: 2, OpenActions: 1, TopCostIncrease: "payments +35%"})
	if !strings.Contains(d, "🔴") {
		t.Fatalf("high failures + SLO breach should be red: %q", d)
	}
	if !strings.Contains(d, "payments +35%") {
		t.Fatalf("top cost increase should appear: %q", d)
	}

	// Only open actions → yellow.
	d = FormatReportDigest(ReportDigestInput{OpenActions: 2})
	if !strings.Contains(d, "🟡") {
		t.Fatalf("open actions only should be yellow: %q", d)
	}
	// Empty cluster id → "전체 클러스터".
	if !strings.Contains(d, "전체 클러스터") {
		t.Fatalf("empty cluster should render 전체 클러스터: %q", d)
	}
}
