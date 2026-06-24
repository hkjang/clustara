package analyzer

import "sort"

// RemediationAdvice recommends how to act on an RCA finding: the suggested action, why, whether
// a rollback is viable, and an urgency priority. RiskLevel/RequiresApproval are filled by the
// handler from the action classifier so this stays a pure mapping (Remediation Advisor).
type RemediationAdvice struct {
	ClusterID         string `json:"cluster_id"`
	Namespace         string `json:"namespace"`
	Kind              string `json:"kind"`
	Name              string `json:"name"`
	Condition         string `json:"condition"`
	Severity          string `json:"severity"`
	RecommendedAction string `json:"recommended_action"` // executor action, or investigate/rollback (advisory)
	Actionable        bool   `json:"actionable"`         // true if RecommendedAction maps to an executor action
	Rationale         string `json:"rationale"`
	RollbackPossible  bool   `json:"rollback_possible"`
	Priority          int    `json:"priority"` // 0 = most urgent
	RiskLevel         string `json:"risk_level"`
	RequiresApproval  bool   `json:"requires_approval"`
}

type adviceRule struct {
	action     string
	actionable bool
	rationale  string
	rollback   bool
}

var remediationByCondition = map[string]adviceRule{
	"CrashLoopBackOff":      {"rollout_restart", true, "이전 컨테이너 로그·설정을 확인하고, 최근 배포가 원인이면 rollback. 일시 오류면 rollout restart.", true},
	"OOMKilled":             {"patch", true, "메모리 limit 증설(image/replicas/annotations 외 patch는 제한) 또는 누수 점검.", false},
	"ImagePullBackOff":      {"investigate", false, "이미지 경로/태그·imagePullSecret·registry 접근을 확인. 직전 image 변경이면 rollback.", true},
	"Pending":               {"investigate", false, "FailedScheduling 사유(리소스 부족·taint·PVC·quota)를 확인. 직접 액션 대신 스케줄 조건 조정.", false},
	"UnavailableReplicas":   {"rollout_restart", true, "하위 Pod·rollout 진행률 점검 후 재시작, 회귀면 rollback.", true},
	"RolloutStuck":          {"rollout_restart", true, "ProgressDeadline 초과 — 이미지/probe/리소스 점검 후 재시작 또는 rollback.", true},
	"ReadinessProbeFailed":  {"investigate", false, "readiness probe 설정·의존 서비스 연결을 점검. Service 영향 확인.", false},
	"LivenessProbeFailed":   {"investigate", false, "liveness initialDelay/threshold가 기동 시간 대비 충분한지 점검(과도한 재시작 방지).", false},
	"DNSResolutionFailed":   {"investigate", false, "CoreDNS 상태·Service name/namespace·NetworkPolicy(egress 53)를 점검.", false},
	"NodePressure":          {"cordon", true, "압박 노드를 cordon하고 워크로드 재배치/노드 증설을 검토(drain은 PDB 확인 후 승인).", false},
	"PostDeploymentErrors":  {"rollback", false, "배포 직후 오류 증가 — rollout undo(rollback)를 우선 검토.", true},
	"PostDeploymentLatency": {"rollback", false, "배포 후 latency 회귀 — 직전 diff 확인 후 rollback 검토.", true},
	"JobFailing":            {"investigate", false, "실패 Job 로그·backoffLimit·입력/권한을 점검.", false},
	"CronJobNoSuccess":      {"investigate", false, "최근 생성된 Job의 실패 원인·schedule/suspend를 점검.", false},
}

func severityPriority(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	}
	return 3
}

// AdviseRemediation maps RCA findings to remediation advice, sorted by urgency (severity).
func AdviseRemediation(findings []RCAFinding) []RemediationAdvice {
	out := []RemediationAdvice{}
	for _, f := range findings {
		rule, ok := remediationByCondition[f.Condition]
		if !ok {
			rule = adviceRule{action: "investigate", actionable: false, rationale: "수집된 근거를 바탕으로 수동 점검이 필요합니다.", rollback: false}
		}
		out = append(out, RemediationAdvice{
			ClusterID: f.ClusterID, Namespace: f.Namespace, Kind: f.ResourceKind, Name: f.ResourceName,
			Condition: f.Condition, Severity: f.Severity,
			RecommendedAction: rule.action, Actionable: rule.actionable, Rationale: rule.rationale,
			RollbackPossible: rule.rollback, Priority: severityPriority(f.Severity),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}
