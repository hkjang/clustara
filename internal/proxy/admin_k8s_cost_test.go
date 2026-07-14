package proxy

import (
	"math"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestBuildK8sCostHistoryAggregatesDailyAndUsesMonthEnd(t *testing.T) {
	snaps := []store.K8sCostSnapshot{
		{Day: "2026-06-30", Key: "api", MonthlyKRW: 30000},
		{Day: "2026-06-30", Key: "db", MonthlyKRW: 60000},
		{Day: "2026-07-01", Key: "api", MonthlyKRW: 45000},
		{Day: "2026-07-01", Key: "db", MonthlyKRW: 75000},
		{Day: "2026-07-14", Key: "api", MonthlyKRW: 60000},
		{Day: "2026-07-14", Key: "db", MonthlyKRW: 90000},
		{Day: "invalid", Key: "ignored", MonthlyKRW: 999999},
	}
	daily, monthly := buildK8sCostHistory(snaps)
	if len(daily) != 3 || daily[0].Period != "2026-06-30" || daily[0].MonthlyKRW != 90000 || daily[2].MonthlyKRW != 150000 {
		t.Fatalf("unexpected daily series: %+v", daily)
	}
	if math.Abs(daily[2].HourlyKRW-150000.0/730.0) > 0.001 {
		t.Fatalf("hourly run-rate must use 730 hours: %+v", daily[2])
	}
	if len(monthly) != 2 || monthly[0].Period != "2026-06" || monthly[0].MonthlyKRW != 90000 || monthly[1].Period != "2026-07" || monthly[1].MonthlyKRW != 150000 {
		t.Fatalf("monthly series must use the latest snapshot in each month: %+v", monthly)
	}
}

func TestK8sCostVisualizationUXContract(t *testing.T) {
	for _, marker := range []string{
		`비용 추세·구성 분석`, `24시간 환산`, `최근 30일`, `최근 12개월`,
		`Namespace 비용 비중`, `Rightsizing 후 예상`, `추정 모델·신뢰도`,
		`Metric Coverage`, `Request Coverage`, `k8sCostChartSVG`, `k8sCostSelectPeriod`,
		`실제 시간별 청구액이 아닙니다`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("cost dashboard is missing visualization contract %q", marker)
		}
	}
}
