package analyzer

// Tool Planner (FLOAT-REQ-07): from the resolved intent + page context, decide which Clustara APIs
// the agent should consult, in order, to ground its answer. Pure — it returns the PLAN (not the
// results); the handler executes it and the trace records it. Read-only tools only.

// AgentToolCall is one planned read-only data source.
type AgentToolCall struct {
	Tool    string `json:"tool"`    // stable tool id
	API     string `json:"api"`     // backing API path (templated)
	Purpose string `json:"purpose"` // why this tool is used
}

// PlanAgentTools returns the ordered read-only tools for an intent. Context fills API path params;
// when a focused resource is absent the plan falls back to list/overview tools.
func PlanAgentTools(intent string, ctx AgentPageContext) []AgentToolCall {
	switch intent {
	case IntentIncident:
		if ctx.IncidentID != "" {
			return []AgentToolCall{
				{"incident_detail", "/admin/k8s/incidents/{id}", "장애 근거·confidence·영향 그래프"},
				{"resource_graph", "/admin/k8s/resource-graph", "blast radius"},
				{"remediation", "/admin/k8s/remediation/advice", "권장 조치"},
			}
		}
		return []AgentToolCall{{"incidents", "/admin/k8s/incidents?status=open", "미해결 인시던트"}, {"home", "/admin/k8s/home", "위험 TOP"}}
	case IntentPod:
		if ctx.Pod != "" {
			return []AgentToolCall{
				{"pod_detail", "/admin/k8s/pods/{ns}/{pod}", "상태·컨테이너·이벤트"},
				{"pod_logs", "/admin/k8s/pods/{ns}/{pod}/logs?previous=true", "이전 컨테이너 로그"},
				{"env", "/admin/k8s/pods/{ns}/{pod}/env", "환경변수 출처"},
				{"golden_diff", "/admin/k8s/pods/{ns}/{pod}/golden-diff", "정상 Pod 대비 차이"},
			}
		}
		return []AgentToolCall{{"pods", "/admin/k8s/pods", "위험 Pod 목록"}}
	case IntentConfig:
		if ctx.ConfigName != "" {
			return []AgentToolCall{{"config_impact", "/admin/k8s/config-impact?kind=&name=", "참조 워크로드·재시작 영향"}}
		}
		return []AgentToolCall{{"security", "/admin/k8s/security", "정책·Secret 포스처"}}
	case IntentStack:
		if ctx.StackID != "" {
			return []AgentToolCall{{"stack_detail", "/admin/k8s/stacks/{id}", "매니페스트·리비전"}, {"stack_drift", "/admin/k8s/stacks/{id}/drift", "선언 vs 실제"}}
		}
		return []AgentToolCall{{"stacks", "/admin/k8s/stacks", "Stack 목록"}}
	case IntentCost:
		return []AgentToolCall{{"cost", "/admin/k8s/cost", "비용 추세"}, {"rightsizing", "/admin/k8s/cost/recommendations", "rightsizing 후보"}}
	case IntentSLO:
		return []AgentToolCall{{"slo", "/admin/k8s/slo", "SLO·에러버짓"}}
	case IntentAction:
		return []AgentToolCall{{"actions", "/admin/k8s/actions", "조치 승인 대기"}, {"action_safety", "/admin/k8s/pods/{ns}/{pod}/action-safety", "조치 안전성"}}
	case IntentReport:
		return []AgentToolCall{{"reports", "/admin/k8s/reports", "운영 다이제스트"}}
	default: // home / general
		return []AgentToolCall{{"home", "/admin/k8s/home", "운영 홈 위험 요약"}, {"ai_ask", "/admin/k8s/ai/ask", "근거 기반 자연어 분석"}}
	}
}
