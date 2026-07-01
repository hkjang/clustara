package analyzer

import (
	"strconv"
	"strings"
)

// Pod Briefing: a One-Page diagnosis that synthesizes the Pod's health, primary symptom, recent
// change and event signals into "이 Pod가 왜 위험한지 / 가장 가능성 높은 원인 / 먼저 볼 것" — so the
// operator sees the verdict at the top of the Pod detail without assembling describe+logs by hand.
// Rule-based (no LLM); complements the status playbook (runbook) and remediation advisor.

// PodBriefingInput carries the already-derived Pod signals.
type PodBriefingInput struct {
	Health              PodHealth
	RestartCount        int
	RecentRestartCount  int
	RestartRecencyKnown bool
	WarningEvents       int
	RecentChange        bool
	ChangeSummary       string // e.g. "image x:1.2 → x:1.3" when a recent revision exists
	TopEventReason      string // most relevant warning event reason, if any
	OwnerKind           string
	OwnerName           string
}

// PodBriefing is the synthesized one-page diagnosis.
type PodBriefing struct {
	Verdict     string   `json:"verdict"`      // one-line headline
	Severity    string   `json:"severity"`     // healthy | warning | critical (from health band)
	LikelyCause string   `json:"likely_cause"` // most probable cause
	FirstChecks []string `json:"first_checks"` // what to look at first (logs/events/diff)
	WatchOuts   []string `json:"watch_outs"`   // secondary signals worth noting
}

// symptomGuidance maps a primary symptom to its likely cause and first-look checklist
// (reviewer §8: RCA 유형 → 먼저 볼 로그/추가 분석).
var symptomGuidance = map[string]struct {
	cause  string
	checks []string
}{
	"CrashLoopBackOff": {
		cause:  "컨테이너가 시작 직후 반복 종료 — 애플리케이션 시작 실패 또는 직전 배포/설정 변경이 유력",
		checks: []string{"previous 로그(이전 컨테이너) 우선 확인", "컨테이너 exit code·last state 확인", "최근 ConfigMap/Secret/이미지 변경 diff 확인"},
	},
	"OOMKilled": {
		cause:  "메모리 limit 초과로 커널이 컨테이너를 종료 — 메모리 누수 또는 limit 과소 설정",
		checks: []string{"이전 로그 마지막 200줄 확인", "메모리 usage vs request/limit 비교", "Rightsizing 권장값 확인"},
	},
	"ImagePullBackOff": {
		cause:  "이미지를 가져오지 못함 — 태그 오타, 레지스트리 인증(imagePullSecret), 네트워크/레지스트리 장애",
		checks: []string{"이벤트 로그의 pull 실패 사유 확인", "image tag·registry 경로 확인", "imagePullSecret·노드 레지스트리 연결 확인"},
	},
	"CreateContainerError": {
		cause:  "컨테이너 생성 실패 — ConfigMap/Secret 마운트 누락 또는 잘못된 command/env",
		checks: []string{"이벤트의 CreateContainer 사유 확인", "참조 ConfigMap/Secret 존재 여부 확인", "command/args/env 설정 확인"},
	},
	"Evicted": {
		cause:  "노드 리소스 압박(disk/memory)으로 Pod가 축출됨",
		checks: []string{"노드 condition(DiskPressure/MemoryPressure) 확인", "노드 용량·다른 Pod 밀도 확인", "재스케줄 여부 확인"},
	},
	"Pending": {
		cause:  "스케줄링 불가 — 노드 리소스 부족, taint/toleration 불일치, PVC 미바인딩, affinity 제약",
		checks: []string{"스케줄링(FailedScheduling) 이벤트 확인", "노드 가용 리소스·taint 확인", "PVC 바인딩·affinity/nodeSelector 확인"},
	},
	"ProbeFailing": {
		cause:  "Readiness/Liveness probe 실패로 트래픽에서 제외 — 앱 응답 지연 또는 probe 설정 부적합",
		checks: []string{"현재 로그에서 요청 처리/지연 확인", "probe 경로·임계값·initialDelay 확인", "Service Endpoint 제외 여부 확인"},
	},
	"Terminating": {
		cause:  "Pod가 종료 진행 중 — graceful shutdown 지연 또는 finalizer 대기",
		checks: []string{"deletionTimestamp·grace period 확인", "preStop hook·finalizer 확인", "노드/owner 상태 확인"},
	},
}

// BuildPodBriefing synthesizes the one-page diagnosis. Pure over its input.
func BuildPodBriefing(in PodBriefingInput) PodBriefing {
	band := in.Health.Band
	if band == "" {
		band = "healthy"
	}
	primary := in.Health.PrimarySymptom
	b := PodBriefing{Severity: band, FirstChecks: []string{}, WatchOuts: []string{}}

	if band == "healthy" && (primary == "" || primary == "Healthy") {
		b.Verdict = "정상 — 위험 신호 없음 (Health " + strconv.Itoa(in.Health.Score) + ")"
		b.LikelyCause = "특이 증상이 감지되지 않았습니다."
		b.FirstChecks = append(b.FirstChecks, "필요 시 최근 로그/이벤트만 확인")
		if in.RestartRecencyKnown && in.RestartCount > 0 && in.RecentRestartCount == 0 {
			b.WatchOuts = append(b.WatchOuts, "누적 재시작 "+strconv.Itoa(in.RestartCount)+"회는 있으나 최근 재시작 신호는 없어 안정 상태로 보정")
		}
		return b
	}

	label := "주의"
	if band == "critical" {
		label = "위험"
	}
	sym := primary
	if sym == "" || sym == "Degraded" {
		sym = "비정상 상태"
	}
	detail := ""
	if in.RestartCount > 0 {
		if in.RestartRecencyKnown {
			detail = " · 최근 재시작 신호 " + strconv.Itoa(in.RecentRestartCount) + "회/누적 " + strconv.Itoa(in.RestartCount) + "회"
		} else {
			detail = " · 재시작 " + strconv.Itoa(in.RestartCount) + "회"
		}
	}
	b.Verdict = label + ": " + sym + " (Health " + strconv.Itoa(in.Health.Score) + ")" + detail

	if g, ok := symptomGuidance[primary]; ok {
		b.LikelyCause = g.cause
		b.FirstChecks = append(b.FirstChecks, g.checks...)
	} else {
		b.LikelyCause = "Health 저하 — 컨테이너 상태와 최근 이벤트를 함께 확인하세요."
		b.FirstChecks = append(b.FirstChecks, "컨테이너 상태·이벤트·로그 확인")
	}

	// Recent change is the strongest single corroborating signal — surface it prominently.
	if in.RecentChange {
		msg := "장애 직전 배포/설정 변경 있음"
		if strings.TrimSpace(in.ChangeSummary) != "" {
			msg += " (" + strings.TrimSpace(in.ChangeSummary) + ")"
		}
		msg += " — 변경 타임라인·Diff를 먼저 확인하고 롤백을 검토하세요."
		b.FirstChecks = append([]string{msg}, b.FirstChecks...)
	}

	if in.WarningEvents > 0 {
		b.WatchOuts = append(b.WatchOuts, "Warning 이벤트 "+strconv.Itoa(in.WarningEvents)+"건")
	}
	if in.RestartRecencyKnown && in.RestartCount > 0 && in.RecentRestartCount == 0 {
		b.WatchOuts = append(b.WatchOuts, "누적 재시작 "+strconv.Itoa(in.RestartCount)+"회는 있으나 최근 재시작 신호는 없어 안정 상태로 보정")
	}
	if in.TopEventReason != "" {
		b.WatchOuts = append(b.WatchOuts, "주요 이벤트: "+in.TopEventReason)
	}
	if len(in.Health.Symptoms) > 1 {
		b.WatchOuts = append(b.WatchOuts, "복합 증상: "+strings.Join(in.Health.Symptoms, ", "))
	}
	return b
}
