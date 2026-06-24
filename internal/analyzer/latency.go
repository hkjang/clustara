package analyzer

import (
	"fmt"
	"time"

	"clustara/internal/store"
)

// AnalyzeLatencyRegressions correlates a recent deploy (spec revision) with a latency increase
// measured by external latency samples (RCA-10, latency half). For each workload deployed within
// the lookback window it compares the average latency before vs after the deploy and flags a
// significant regression. Pure over its inputs.
func AnalyzeLatencyRegressions(revisions []store.K8sResourceRevision, metrics []store.K8sMetricSample, now time.Time, lookback time.Duration) []RCAFinding {
	// Most recent "updated" revision (deploy) per workload, within lookback.
	type dep struct {
		rev store.K8sResourceRevision
		at  time.Time
	}
	deploys := map[string]dep{}
	for _, rev := range revisions {
		if rev.ChangeKind != "updated" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, rev.ObservedAt)
		if err != nil || now.Sub(at) > lookback {
			continue
		}
		key := rev.Namespace + "/" + rev.Name
		if cur, ok := deploys[key]; !ok || at.After(cur.at) {
			deploys[key] = dep{rev: rev, at: at}
		}
	}
	if len(deploys) == 0 {
		return nil
	}

	type acc struct{ beforeSum, afterSum float64; beforeN, afterN int }
	stats := map[string]*acc{}
	for _, m := range metrics {
		if m.LatencyMS <= 0 {
			continue
		}
		key := m.Namespace + "/" + m.ResourceName
		d, ok := deploys[key]
		if !ok {
			continue
		}
		when, err := time.Parse(time.RFC3339Nano, m.ObservedAt)
		if err != nil {
			continue
		}
		a := stats[key]
		if a == nil {
			a = &acc{}
			stats[key] = a
		}
		if when.Before(d.at) {
			a.beforeSum += m.LatencyMS
			a.beforeN++
		} else {
			a.afterSum += m.LatencyMS
			a.afterN++
		}
	}

	out := []RCAFinding{}
	for key, a := range stats {
		if a.beforeN == 0 || a.afterN == 0 {
			continue // need both sides to compare
		}
		before := a.beforeSum / float64(a.beforeN)
		after := a.afterSum / float64(a.afterN)
		// Significant: +30% AND +20ms absolute (avoid noise on tiny latencies).
		if after <= before*1.3 || after-before < 20 {
			continue
		}
		d := deploys[key]
		out = append(out, RCAFinding{
			ClusterID: d.rev.ClusterID, Namespace: d.rev.Namespace, ResourceKind: d.rev.Kind, ResourceName: d.rev.Name,
			Condition: "PostDeploymentLatency", Severity: "high",
			Cause: fmt.Sprintf("배포 후 평균 latency가 %.0fms → %.0fms 로 상승했습니다.", before, after),
			Evidence: []string{
				"배포 시각: " + d.rev.ObservedAt,
				fmt.Sprintf("배포 전 평균 %.0fms (n=%d) → 배포 후 평균 %.0fms (n=%d)", before, a.beforeN, after, a.afterN),
			},
			CheckResources: []string{"이전/현재 image", "직전 diff", "의존 서비스 latency", "리소스 limit/throttling"},
			Actions:        []string{"변경 타임라인에서 배포 전후 diff를 확인합니다.", "회귀가 확인되면 rollout undo(rollback)를 검토합니다."},
		})
	}
	return out
}
