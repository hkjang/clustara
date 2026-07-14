package proxy

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestK8sCostSnapshotDue(t *testing.T) {
	now := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	if !k8sCostSnapshotDue("", now, 24*time.Hour) {
		t.Fatal("missing history must run immediately")
	}
	if k8sCostSnapshotDue(now.Add(-23*time.Hour).Format(time.RFC3339Nano), now, 24*time.Hour) {
		t.Fatal("snapshot must not run before interval")
	}
	if !k8sCostSnapshotDue(now.Add(-24*time.Hour).Format(time.RFC3339Nano), now, 24*time.Hour) {
		t.Fatal("snapshot must run when interval elapsed")
	}
}

func TestRecordK8sCostSnapshotPersistsClusterScopedNamespaceTotals(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "cost-c1", Name: "cost"}); err != nil {
		t.Fatal(err)
	}
	pod := store.K8sInventoryItem{ID: "cost-pod", ClusterID: "cost-c1", Namespace: "ml", Kind: "Pod", Name: "trainer", Spec: map[string]any{"containers": []any{map[string]any{"resources": map[string]any{"requests": map[string]any{"cpu": "1", "memory": "1Gi", "nvidia.com/gpu": "1"}}}}}}
	pvc := store.K8sInventoryItem{ID: "cost-pvc", ClusterID: "cost-c1", Namespace: "ml", Kind: "PersistentVolumeClaim", Name: "models", Spec: map[string]any{"resources": map[string]any{"requests": map[string]any{"storage": "10Gi"}}}}
	if err := db.UpsertK8sInventory(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, pvc); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	recorded, err := s.recordK8sCostSnapshot(ctx, "cost-c1")
	if err != nil || recorded != 1 {
		t.Fatalf("recorded=%d err=%v", recorded, err)
	}
	snaps, err := db.ListK8sCostSnapshots(ctx, "cost-c1", "namespace", 10)
	if err != nil || len(snaps) != 1 || snaps[0].Key != "ml" || snaps[0].MonthlyKRW <= 700000 {
		t.Fatalf("unexpected snapshots: %+v err=%v", snaps, err)
	}
}

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
		`자동 스냅샷`, `snapshot_interval_seconds`, `GPU 비용`, `Persistent Volume 비용`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("cost dashboard is missing visualization contract %q", marker)
		}
	}
}
