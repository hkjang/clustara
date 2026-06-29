package analyzer

import "strconv"

// Runbook Orchestrator: turn a Pod's primary symptom into an ordered, phased remediation plan —
// pre-check → diagnose → remediate(승인 게이트) → post-check → rollback — so an operator runs a
// safe, repeatable sequence instead of an ad-hoc action. Pure builder; execution stays in the
// approval/executor flow.

// Runbook phases (fixed order).
const (
	PhasePrecheck  = "precheck"
	PhaseDiagnose  = "diagnose"
	PhaseRemediate = "remediate"
	PhasePostcheck = "postcheck"
	PhaseRollback  = "rollback"
)

// RunbookStep is one ordered step in the plan.
type RunbookStep struct {
	Order            int    `json:"order"`
	Phase            string `json:"phase"`
	Title            string `json:"title"`
	Detail           string `json:"detail"`
	Action           string `json:"action"`            // structured action hint (executor/UI maps it)
	RequiresApproval bool   `json:"requires_approval"` // remediation steps gate on approval
}

// RunbookPlan is the full staged plan for a symptom.
type RunbookPlan struct {
	Symptom           string        `json:"symptom"`
	Summary           string        `json:"summary"`
	Steps             []RunbookStep `json:"steps"`
	RollbackCandidate string        `json:"rollback_candidate"`
}

// RunbookContext carries the pod facts that shape the plan.
type RunbookContext struct {
	HasOwner     bool // controlled by a ReplicaSet/Deployment/... → restart/scale is safe
	RecentChange bool // a recent deploy/config change → rollback is a candidate
	Replicas     int
}

// symptomRemediation maps a symptom to its remediate step (title/detail/action).
var symptomRemediation = map[string]struct{ title, detail, action string }{
	"CrashLoopBackOff":     {"롤아웃 재시작 또는 Pod 삭제", "애플리케이션 시작 실패. 최근 변경이 원인이면 롤백, 아니면 owner를 rollout restart해 새 Pod로 교체합니다.", "rollout_restart"},
	"OOMKilled":            {"메모리 limit 상향 또는 누수 수정", "메모리 limit 초과. 사용량 기반으로 limit을 상향(Rightsizing)하거나 누수를 수정한 뒤 재배포합니다.", "patch_resources"},
	"ImagePullBackOff":     {"이미지/시크릿 수정 후 롤아웃", "이미지 pull 실패. tag·registry·imagePullSecret을 수정한 뒤 owner를 rollout restart합니다.", "fix_image_then_rollout"},
	"CreateContainerError": {"설정 참조 수정 후 롤아웃", "컨테이너 생성 실패. 누락된 ConfigMap/Secret/command를 수정한 뒤 재배포합니다.", "fix_config_then_rollout"},
	"Pending":              {"스케줄링 제약 해소", "스케줄링 불가. 노드 리소스 확보, taint/toleration·affinity·PVC 바인딩을 조정합니다.", "resolve_scheduling"},
	"Evicted":              {"노드 압박 해소 후 재스케줄", "노드 리소스 압박으로 축출. 노드 정리/확장 후 Pod를 재스케줄합니다.", "cordon_drain_or_scale_node"},
	"ProbeFailing":         {"probe/엔드포인트 점검", "Readiness/Liveness 실패. probe 임계값·initialDelay와 앱 응답을 점검 후 필요 시 재배포합니다.", "tune_probe_or_restart"},
}

// BuildRunbookPlan builds the staged plan for a primary symptom. Pure over its inputs.
func BuildRunbookPlan(symptom string, ctx RunbookContext) RunbookPlan {
	plan := RunbookPlan{Symptom: symptom}
	order := 0
	add := func(phase, title, detail, action string, approval bool) {
		order++
		plan.Steps = append(plan.Steps, RunbookStep{Order: order, Phase: phase, Title: title, Detail: detail, Action: action, RequiresApproval: approval})
	}

	// 1) Pre-check — always capture evidence + assess blast radius before touching anything.
	add(PhasePrecheck, "증적 고정", "조치 전 current/previous 로그·이벤트·manifest를 증적 번들로 고정합니다.", "evidence_bundle", false)
	add(PhasePrecheck, "조치 안전성 확인", "owner·replica·PDB·HPA·최근 이벤트로 조치가 안전한지 점검합니다.", "action_safety", false)

	// 2) Diagnose — symptom-specific first-look (reuse the briefing guidance).
	if g, ok := symptomGuidance[symptom]; ok {
		detail := g.cause
		if len(g.checks) > 0 {
			detail += " 먼저: " + g.checks[0]
		}
		add(PhaseDiagnose, "원인 진단", detail, "diagnose", false)
	} else {
		add(PhaseDiagnose, "원인 진단", "컨테이너 상태·이벤트·로그로 원인을 좁힙니다.", "diagnose", false)
	}

	// 3) Remediate — symptom-specific action behind an approval gate.
	if r, ok := symptomRemediation[symptom]; ok {
		add(PhaseRemediate, r.title, r.detail, r.action, true)
	} else {
		add(PhaseRemediate, "조치 검토", "표준 조치 후보가 없어 디버그 세션/관측을 권장합니다.", "observe_or_debug", true)
	}
	if !ctx.HasOwner {
		// A bare pod (no controller) cannot be safely restarted/scaled — flag it.
		add(PhaseRemediate, "주의: 컨트롤러 없음", "이 Pod는 owner(ReplicaSet/Deployment 등)가 없어 삭제 시 재생성되지 않습니다. 삭제 전 영향을 반드시 확인하세요.", "warn_bare_pod", true)
	}

	// 4) Post-check — confirm recovery.
	add(PhasePostcheck, "조치 후 확인", "Health Replay와 Pod Health로 회복 여부를 확인하고, 재발 시 롤백을 검토합니다.", "post_check_health_replay", false)

	// 5) Rollback — only when a recent change is the likely trigger.
	if ctx.RecentChange {
		add(PhaseRollback, "롤백 후보", "장애 직전 배포/설정 변경이 있습니다. 회복되지 않으면 직전 정상 revision으로 롤백하세요.", "rollback_to_previous_revision", true)
		plan.RollbackCandidate = "rollback_to_previous_revision"
	}

	repl := ""
	if ctx.Replicas > 0 {
		repl = " · replicas " + strconv.Itoa(ctx.Replicas)
	}
	plan.Summary = "증상 '" + firstNonEmptyStr(symptom, "비정상") + "' 대응 플랜: 증적→진단→조치(승인)→확인" + boolStr2(ctx.RecentChange, "→롤백", "") + repl
	return plan
}

func boolStr2(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
