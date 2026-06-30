package analyzer

import "sort"

// Agent Regression Suite (CLU-REQ-08).
//
// The floating Ops Agent's UX/logic changes frequently (v0.9.4–v0.9.16). Its LLM answers are
// non-deterministic, but the *deterministic* behavior that drives answer quality — intent
// classification and the read-only tool plan — can silently regress when that code is edited. This
// runs a curated set of representative operator questions through ClassifyAgentIntent + PlanAgentTools
// and scores intent accuracy + expected-tool coverage, so a release can be compared to a baseline.
//
// Pure: it calls the in-package agent functions directly; no LLM, no IO.

// RegressionCase is one representative question with its expected deterministic outcome.
type RegressionCase struct {
	ID           string           `json:"id"`
	Question     string           `json:"question"`
	Context      AgentPageContext `json:"context"`
	ExpectIntent string           `json:"expect_intent"`
	ExpectTools  []string         `json:"expect_tools"` // tool names that MUST appear in the plan
}

// RegressionResult is the graded outcome for one case.
type RegressionResult struct {
	ID           string   `json:"id"`
	Question     string   `json:"question"`
	ExpectIntent string   `json:"expect_intent"`
	GotIntent    string   `json:"got_intent"`
	IntentOK     bool     `json:"intent_ok"`
	ExpectTools  []string `json:"expect_tools"`
	GotTools     []string `json:"got_tools"`
	MissingTools []string `json:"missing_tools"`
	ToolCoverage float64  `json:"tool_coverage"` // matched / expected (100 when none expected)
	Pass         bool     `json:"pass"`
}

// RegressionReport is the suite-level rollup.
type RegressionReport struct {
	Total           int                `json:"total"`
	Passed          int                `json:"passed"`
	PassRate        float64            `json:"pass_rate"`
	IntentAccuracy  float64            `json:"intent_accuracy"`
	AvgToolCoverage float64            `json:"avg_tool_coverage"`
	Results         []RegressionResult `json:"results"`
	Failures        []RegressionResult `json:"failures"`
}

// RunAgentRegression grades every case against the current deterministic agent behavior.
func RunAgentRegression(cases []RegressionCase) RegressionReport {
	rep := RegressionReport{Results: []RegressionResult{}, Failures: []RegressionResult{}}
	if len(cases) == 0 {
		return rep
	}
	intentHits := 0
	coverageSum := 0.0
	for _, c := range cases {
		gotIntent := ClassifyAgentIntent(c.Question, c.Context.Route)
		plan := PlanAgentTools(gotIntent, c.Context)
		got := make([]string, 0, len(plan))
		toolSet := map[string]bool{}
		for _, t := range plan {
			got = append(got, t.Tool)
			toolSet[t.Tool] = true
		}
		missing := []string{}
		for _, want := range c.ExpectTools {
			if !toolSet[want] {
				missing = append(missing, want)
			}
		}
		coverage := 100.0
		if len(c.ExpectTools) > 0 {
			coverage = rate(len(c.ExpectTools)-len(missing), len(c.ExpectTools))
		}
		res := RegressionResult{
			ID: c.ID, Question: c.Question, ExpectIntent: c.ExpectIntent, GotIntent: gotIntent,
			IntentOK: gotIntent == c.ExpectIntent, ExpectTools: c.ExpectTools, GotTools: got,
			MissingTools: missing, ToolCoverage: coverage,
		}
		res.Pass = res.IntentOK && len(missing) == 0
		if res.IntentOK {
			intentHits++
		}
		coverageSum += coverage
		if res.Pass {
			rep.Passed++
		} else {
			rep.Failures = append(rep.Failures, res)
		}
		rep.Results = append(rep.Results, res)
	}
	rep.Total = len(cases)
	rep.PassRate = rate(rep.Passed, rep.Total)
	rep.IntentAccuracy = rate(intentHits, rep.Total)
	rep.AvgToolCoverage = round2(coverageSum / float64(rep.Total))
	sort.SliceStable(rep.Failures, func(i, j int) bool { return rep.Failures[i].ID < rep.Failures[j].ID })
	return rep
}

// DefaultAgentRegressionCases is the curated representative operator-question set. Keep IDs stable
// so baselines stay comparable across releases.
func DefaultAgentRegressionCases() []RegressionCase {
	return []RegressionCase{
		{ID: "incident-triage", Question: "지금 가장 먼저 봐야 할 장애를 정리해줘",
			Context: AgentPageContext{Route: "#/k8s-home"}, ExpectIntent: IntentIncident, ExpectTools: []string{"incidents", "home"}},
		{ID: "incident-detail", Question: "이 인시던트 RCA 근거 보여줘",
			Context: AgentPageContext{Route: "#/k8s-incidents", IncidentID: "i1"}, ExpectIntent: IntentIncident, ExpectTools: []string{"incident_detail", "remediation"}},
		{ID: "pod-crashloop", Question: "이 Pod가 왜 CrashLoop 나는지 로그까지 봐줘",
			Context: AgentPageContext{Route: "#/k8s-pods", Namespace: "prod", Pod: "web-1"}, ExpectIntent: IntentPod, ExpectTools: []string{"pod_detail", "pod_logs"}},
		{ID: "pod-list", Question: "위험한 pod 있어?",
			Context: AgentPageContext{Route: "#/k8s-pods"}, ExpectIntent: IntentPod, ExpectTools: []string{"pods"}},
		{ID: "config-impact", Question: "이 ConfigMap 바꾸면 어디에 영향가?",
			Context: AgentPageContext{Route: "#/k8s-security", ConfigName: "app-config"}, ExpectIntent: IntentConfig, ExpectTools: []string{"config_impact"}},
		{ID: "stack-drift", Question: "이 stack의 drift 확인해줘",
			Context: AgentPageContext{Route: "#/k8s-stacks", StackID: "s1"}, ExpectIntent: IntentStack, ExpectTools: []string{"stack_detail", "stack_drift"}},
		{ID: "cost-increase", Question: "비용 증가 원인과 절감 후보 알려줘",
			Context: AgentPageContext{Route: "#/k8s-cost"}, ExpectIntent: IntentCost, ExpectTools: []string{"cost", "rightsizing"}},
		{ID: "slo-budget", Question: "SLO 에러버짓 얼마나 남았어?",
			Context: AgentPageContext{Route: "#/k8s-slo"}, ExpectIntent: IntentSLO, ExpectTools: []string{"slo"}},
		{ID: "action-approval", Question: "승인 대기 중인 조치 요약해줘",
			Context: AgentPageContext{Route: "#/k8s-actions"}, ExpectIntent: IntentAction, ExpectTools: []string{"actions"}},
		{ID: "report-digest", Question: "오늘 운영 리포트 요약 보고서 만들어줘",
			Context: AgentPageContext{Route: "#/k8s-reports"}, ExpectIntent: IntentReport, ExpectTools: []string{"reports"}},
		{ID: "home-general", Question: "전반적으로 클러스터 상태 어때?",
			Context: AgentPageContext{Route: "#/k8s-home"}, ExpectIntent: IntentHome, ExpectTools: []string{"home", "ai_ask"}},
	}
}
