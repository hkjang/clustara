package analyzer

import "strings"

// Agent Action Card: the floating agent never executes changes — it proposes them as a structured
// card (target, risk, rollback, approval-required) that the operator submits to the Action Center
// approval flow (FLOAT-REQ-09/10). This builder is pure; creating the approval request is a
// separate, explicit step in the handler/UI.

// AgentActionCard is a proposed remediation for operator approval.
type AgentActionCard struct {
	Action           string `json:"action"`
	Kind             string `json:"kind"`
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Title            string `json:"title"`
	Summary          string `json:"summary"`
	Risk             string `json:"risk"` // low | medium | high
	RequiresApproval bool   `json:"requires_approval"`
	Rollback         string `json:"rollback"`
	Executable       bool   `json:"executable"` // false → advisory only (no executor mapping)
}

type actionSpec struct {
	title, summary, risk, rollback string
	executable                     bool
}

// agentActionSpecs maps a proposed action key to its card metadata. Keys align with the executor /
// runbook vocabulary.
var agentActionSpecs = map[string]actionSpec{
	"rollout_restart":  {"롤아웃 재시작", "워크로드를 순차 재시작해 새 Pod로 교체합니다.", "medium", "이전 ReplicaSet revision으로 rollout undo", true},
	"scale":            {"replica 조정", "워크로드 replica 수를 조정합니다.", "medium", "이전 replica 수로 재조정", true},
	"delete_pod":       {"Pod 삭제", "Pod를 삭제해 컨트롤러가 새 Pod를 재생성하도록 합니다.", "medium", "컨트롤러가 자동 재생성(별도 롤백 불필요)", true},
	"cordon":           {"노드 cordon", "노드에 신규 스케줄링을 차단합니다.", "high", "uncordon으로 해제", true},
	"uncordon":         {"노드 uncordon", "노드 스케줄링 차단을 해제합니다.", "medium", "다시 cordon", true},
	"rollback_image":   {"이미지 롤백", "직전 정상 revision 이미지로 롤백합니다.", "high", "현재 revision으로 재적용", false},
	"patch_resources":  {"리소스 조정", "CPU/메모리 request·limit을 조정합니다(매니페스트 변경/승인).", "high", "이전 리소스 값으로 재적용", false},
	"debug_container":  {"Debug 컨테이너", "ephemeral debug container 주입을 요청합니다(승인 필요).", "medium", "세션 종료 후 정리", false},
}

// BuildAgentActionCard builds a proposed action card. Unknown actions yield an advisory-only card.
// All write actions require approval — the agent only proposes.
func BuildAgentActionCard(action, kind, namespace, name string) AgentActionCard {
	action = strings.TrimSpace(action)
	card := AgentActionCard{Action: action, Kind: kind, Namespace: namespace, Name: name, RequiresApproval: true}
	spec, ok := agentActionSpecs[action]
	target := strings.TrimSpace(namespace+"/"+kind+"/"+name)
	if !ok {
		card.Title = "조치 제안(검토 필요)"
		card.Summary = "표준 조치 매핑이 없어 운영자 검토가 필요합니다: " + action
		card.Risk = "high"
		card.Executable = false
		return card
	}
	card.Title = spec.title
	card.Summary = spec.summary + " 대상: " + target
	card.Risk = spec.risk
	card.Rollback = spec.rollback
	card.Executable = spec.executable
	return card
}

// AgentActionCatalog returns the proposable actions (for UI menus / docs).
func AgentActionCatalog() []string {
	out := make([]string, 0, len(agentActionSpecs))
	for k := range agentActionSpecs {
		out = append(out, k)
	}
	return out
}
