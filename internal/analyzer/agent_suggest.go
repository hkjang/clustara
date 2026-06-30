package analyzer

import "strings"

// Floating Ops Agent foundation: from the current screen's context, classify the intent domain and
// produce context-aware suggested prompts — so the embedded agent offers "다음 운영 액션" without the
// operator re-typing cluster/namespace/pod. Pure over the page context.

// AgentPageContext is the screen context the floating agent auto-collects.
type AgentPageContext struct {
	Route      string // hash route, e.g. "#/k8s-pods"
	ClusterID  string
	Namespace  string
	Pod        string
	Kind       string
	Name       string
	IncidentID string
	StackID    string
	ConfigName string
	Risk       string // current resource risk band, if known
}

// AgentPrompt is one suggested question and its intent domain.
type AgentPrompt struct {
	Text   string `json:"text"`
	Intent string `json:"intent"`
}

// Intent domains.
const (
	IntentIncident = "incident"
	IntentPod      = "pod"
	IntentConfig   = "config"
	IntentStack    = "stack"
	IntentCost     = "cost"
	IntentSLO      = "slo"
	IntentAction   = "action"
	IntentReport   = "report"
	IntentHome     = "home"
	IntentGeneral  = "general"
)

// RouteIntent maps a hash route to its primary intent domain.
func RouteIntent(route string) string {
	r := strings.ToLower(route)
	switch {
	case strings.Contains(r, "k8s-incident"):
		return IntentIncident
	case strings.Contains(r, "k8s-pods"):
		return IntentPod
	case strings.Contains(r, "k8s-cost"):
		return IntentCost
	case strings.Contains(r, "k8s-slo"):
		return IntentSLO
	case strings.Contains(r, "k8s-stacks"):
		return IntentStack
	case strings.Contains(r, "k8s-actions"):
		return IntentAction
	case strings.Contains(r, "k8s-reports"):
		return IntentReport
	case strings.Contains(r, "k8s-home") || r == "" || r == "#/":
		return IntentHome
	case strings.Contains(r, "k8s-policy") || strings.Contains(r, "k8s-security"):
		return IntentConfig
	default:
		return IntentGeneral
	}
}

// ClassifyAgentIntent infers intent from a free-text question, falling back to the page route.
func ClassifyAgentIntent(text, route string) string {
	t := strings.ToLower(text)
	switch {
	case containsAny(t, "incident", "장애", "워룸", "rca"):
		return IntentIncident
	case containsAny(t, "pod", "crashloop", "oom", "재시작", "로그"):
		return IntentPod
	case containsAny(t, "secret", "configmap", "config", "설정", "환경변수", "env"):
		return IntentConfig
	case containsAny(t, "stack", "배포", "manifest", "drift", "롤백", "rollback"):
		return IntentStack
	case containsAny(t, "cost", "비용", "rightsizing", "절감"):
		return IntentCost
	case containsAny(t, "slo", "에러버짓", "가용성", "burn"):
		return IntentSLO
	case containsAny(t, "approve", "승인", "action", "조치"):
		return IntentAction
	case containsAny(t, "report", "리포트", "요약", "보고서"):
		return IntentReport
	}
	return RouteIntent(route)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// SuggestAgentPrompts returns context-aware suggested prompts for the current screen. Resource-
// specific prompts come first when the context carries a focused resource.
func SuggestAgentPrompts(ctx AgentPageContext) []AgentPrompt {
	out := []AgentPrompt{}
	add := func(intent string, texts ...string) {
		for _, t := range texts {
			out = append(out, AgentPrompt{Text: t, Intent: intent})
		}
	}

	switch RouteIntent(ctx.Route) {
	case IntentIncident:
		if ctx.IncidentID != "" {
			add(IntentIncident, "이 장애의 원인·영향·조치 계획을 한 번에 정리해줘", "장애 보고서 초안을 만들어줘", "이 원인을 믿을 근거를 보여줘")
		} else {
			add(IntentIncident, "지금 가장 먼저 봐야 할 장애를 정리해줘", "오늘 위험도가 높아진 서비스만 요약해줘")
		}
	case IntentPod:
		if ctx.Pod != "" {
			add(IntentPod, "이 Pod가 비정상인 가장 가능성 높은 이유는?", "previous log 기준으로 원인 후보를 뽑아줘", "같은 workload의 정상 Pod와 차이를 설명해줘")
		} else {
			add(IntentPod, "위험 Pod를 우선순위로 정리해줘", "Restart Storm이 있는 워크로드를 알려줘")
		}
	case IntentConfig:
		if ctx.ConfigName != "" {
			add(IntentConfig, "이 변경 시 재시작이 필요한 workload를 정리해줘", "이 변경 승인자에게 보낼 요약문을 만들어줘")
		} else {
			add(IntentConfig, "정책 위반 워크로드를 설명해줘", "Secret 변경 영향 범위를 확인해줘")
		}
	case IntentStack:
		add(IntentStack, "운영 반영 전 위험 요소를 검토해줘", "이 drift를 재적용해야 할지 선언을 수정해야 할지 판단해줘", "rollback 후보를 알려줘")
	case IntentCost:
		add(IntentCost, "비용 증가 원인을 namespace별로 설명해줘", "rightsizing 후보를 정리해줘")
	case IntentSLO:
		add(IntentSLO, "SLO 위반 가능성이 높은 서비스를 알려줘", "장애가 SLO에 준 영향을 설명해줘")
	case IntentAction:
		add(IntentAction, "이 조치 실행 전 위험과 롤백 방법을 알려줘", "승인 대기 중인 조치를 요약해줘")
	case IntentReport:
		add(IntentReport, "오늘 운영 다이제스트를 만들어줘", "일일 장애 요약을 작성해줘")
	default: // home / general
		add(IntentHome, "지금 가장 먼저 봐야 할 장애를 정리해줘", "오늘 위험도가 높아진 서비스만 요약해줘", "승인 대기 작업을 요약해줘")
	}
	return out
}
