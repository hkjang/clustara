package serviceinstance

import (
	"math"
	"strings"

	"clustara/internal/store"
)

type HealthArea struct {
	Score    int      `json:"score"`
	Max      int      `json:"max"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence"`
}

type HealthResult struct {
	Score               int                   `json:"score"`
	Status              string                `json:"status"`
	Areas               map[string]HealthArea `json:"areas"`
	MissingComponents   int                   `json:"missing_components"`
	ObservedComponents  int                   `json:"observed_components"`
	TotalRestarts       int                   `json:"total_restarts"`
	MetricFreshness     string                `json:"metric_freshness"`
	CollectionStatus    string                `json:"collection_status"`
	InventoryObservedAt string                `json:"inventory_observed_at,omitempty"`
}

type HealthInput struct {
	Components   []store.K8sServiceComponent
	Inventory    []store.K8sInventoryItem
	Metrics      []store.K8sMetricSample
	Stateful     bool
	BackupStatus string
}

func EvaluateHealth(in HealthInput) HealthResult {
	result := HealthResult{Areas: map[string]HealthArea{}}
	byKey := map[string]store.K8sInventoryItem{}
	for _, it := range in.Inventory {
		byKey[strings.ToLower(it.Kind)+"|"+it.Namespace+"|"+it.Name] = it
	}
	group := func(kinds ...string) (found, total, health int, evidence []string) {
		allowed := map[string]bool{}
		for _, k := range kinds {
			allowed[strings.ToLower(k)] = true
		}
		for _, c := range in.Components {
			if !allowed[strings.ToLower(c.Kind)] {
				continue
			}
			total++
			it, ok := byKey[strings.ToLower(c.Kind)+"|"+c.Namespace+"|"+c.ResourceName]
			if !ok {
				evidence = append(evidence, c.Kind+"/"+c.ResourceName+" 미관측")
				continue
			}
			found++
			health += clamp(it.HealthScore, 0, 100)
			if !healthyStatus(it.Status) {
				evidence = append(evidence, c.Kind+"/"+c.ResourceName+" 상태 "+it.Status)
			}
		}
		return
	}
	area := func(name string, max, found, total, health int, evidence []string) {
		score := max
		if total > 0 {
			score = int(math.Round(float64(max) * float64(health) / float64(total*100)))
		}
		status := "ok"
		if score < max*6/10 {
			status = "error"
		} else if score < max*85/100 {
			status = "warning"
		}
		result.Areas[name] = HealthArea{Score: score, Max: max, Status: status, Evidence: evidence}
		result.Score += score
		result.ObservedComponents += found
		result.MissingComponents += total - found
	}
	f, t, h, e := group("Deployment", "StatefulSet", "DaemonSet")
	area("workload", 25, f, t, h, e)
	f, t, h, e = group("Service", "Ingress", "Route")
	area("endpoint", 15, f, t, h, e)
	f, t, h, e = group("PersistentVolumeClaim")
	if t == 0 {
		f, t, h = 1, 1, 100
	}
	area("storage", 15, f, t, h, e)

	restarts := 0
	podHealth, pods := 0, 0
	for _, it := range in.Inventory {
		if !strings.EqualFold(it.Kind, "Pod") {
			continue
		}
		pods++
		podHealth += clamp(it.HealthScore, 0, 100)
		for _, raw := range anySlice(it.StatusObject["containerStatuses"]) {
			if m, ok := raw.(map[string]any); ok {
				restarts += intNumber(m["restartCount"])
			}
		}
	}
	incidentScore := 15
	incidentEvidence := []string{}
	if pods == 0 && componentCount(in.Components, "Deployment", "StatefulSet", "DaemonSet") > 0 {
		incidentScore = 3
		incidentEvidence = append(incidentEvidence, "연결된 Pod가 아직 관측되지 않음")
	} else if pods > 0 {
		incidentScore = int(math.Round(15 * float64(podHealth) / float64(pods*100)))
	}
	incidentScore -= min(incidentScore, restarts*2)
	if restarts > 0 {
		incidentEvidence = append(incidentEvidence, "컨테이너 재시작 "+itoa(restarts)+"회")
	}
	result.Areas["incidents"] = HealthArea{Score: incidentScore, Max: 15, Status: areaStatus(incidentScore, 15), Evidence: incidentEvidence}
	result.Score += incidentScore
	result.TotalRestarts = restarts

	backupScore := 10
	backupEvidence := []string{}
	if in.Stateful {
		switch strings.ToLower(in.BackupStatus) {
		case "success", "succeeded", "completed":
			backupScore = 10
		case "failed", "error":
			backupScore = 0
			backupEvidence = append(backupEvidence, "최근 백업 실패")
		default:
			backupScore = 3
			backupEvidence = append(backupEvidence, "성공한 백업 증적 없음")
		}
	}
	result.Areas["backup"] = HealthArea{Score: backupScore, Max: 10, Status: areaStatus(backupScore, 10), Evidence: backupEvidence}
	result.Score += backupScore

	securityScore := 10
	securityEvidence := []string{}
	for _, it := range in.Inventory {
		switch strings.ToLower(it.RiskLevel) {
		case "critical":
			securityScore -= 5
			securityEvidence = append(securityEvidence, it.Kind+"/"+it.Name+" critical")
		case "high":
			securityScore -= 3
			securityEvidence = append(securityEvidence, it.Kind+"/"+it.Name+" high")
		}
	}
	securityScore = clamp(securityScore, 0, 10)
	result.Areas["security"] = HealthArea{Score: securityScore, Max: 10, Status: areaStatus(securityScore, 10), Evidence: securityEvidence}
	result.Score += securityScore

	saturationScore := 5
	satEvidence := []string{"사용량 표본 수집 대기"}
	result.MetricFreshness = "missing"
	if len(in.Metrics) > 0 {
		saturationScore = 10
		satEvidence = nil
		result.MetricFreshness = "observed"
		for _, m := range in.Metrics {
			if m.GPUTemperatureC >= 85 {
				saturationScore -= 4
				satEvidence = append(satEvidence, "GPU 온도 임계치 초과")
			} else if m.LatencyMS >= 2000 {
				saturationScore -= 3
				satEvidence = append(satEvidence, "응답 지연 2초 이상")
			}
		}
	}
	saturationScore = clamp(saturationScore, 0, 10)
	result.Areas["saturation"] = HealthArea{Score: saturationScore, Max: 10, Status: areaStatus(saturationScore, 10), Evidence: satEvidence}
	result.Score += saturationScore

	result.Score = clamp(result.Score, 0, 100)
	switch {
	case result.Score >= 85 && result.MissingComponents == 0:
		result.Status = "ready"
	case result.Score >= 60:
		result.Status = "degraded"
	default:
		result.Status = "failed"
	}
	return result
}

func healthyStatus(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "" || v == "ready" || v == "running" || v == "active" || v == "bound" || v == "available" || v == "healthy"
}
func componentCount(rows []store.K8sServiceComponent, kinds ...string) int {
	m := map[string]bool{}
	for _, k := range kinds {
		m[strings.ToLower(k)] = true
	}
	n := 0
	for _, r := range rows {
		if m[strings.ToLower(r.Kind)] {
			n++
		}
	}
	return n
}
func anySlice(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return nil
}
func intNumber(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	}
	return 0
}
func areaStatus(score, max int) string {
	if score < max*6/10 {
		return "error"
	}
	if score < max*85/100 {
		return "warning"
	}
	return "ok"
}
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
