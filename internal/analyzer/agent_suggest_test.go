package analyzer

import (
	"strings"
	"testing"
)

func TestRouteIntentAndSuggestions(t *testing.T) {
	cases := map[string]string{
		"#/k8s-home":          IntentHome,
		"#/k8s-incidents":     IntentIncident,
		"#/k8s-pods":          IntentPod,
		"#/k8s-cost":          IntentCost,
		"#/k8s-slo":           IntentSLO,
		"#/k8s-stacks":        IntentStack,
		"#/k8s-actions":       IntentAction,
		"#/k8s-reports":       IntentReport,
		"#/k8s-policy":        IntentConfig,
		"#/unknown":           IntentGeneral,
	}
	for route, want := range cases {
		if got := RouteIntent(route); got != want {
			t.Errorf("RouteIntent(%q) = %q, want %q", route, got, want)
		}
	}

	// Pod detail (focused pod) → pod-specific prompts.
	sp := SuggestAgentPrompts(AgentPageContext{Route: "#/k8s-pods", Pod: "web-1"})
	if len(sp) == 0 || sp[0].Intent != IntentPod || !strings.Contains(sp[0].Text, "Pod") {
		t.Fatalf("pod-detail suggestions: %+v", sp)
	}
	// Pod list (no focused pod) → list-level prompts (Restart Storm).
	spList := SuggestAgentPrompts(AgentPageContext{Route: "#/k8s-pods"})
	joined := ""
	for _, p := range spList {
		joined += p.Text
	}
	if !strings.Contains(joined, "위험 Pod") {
		t.Fatalf("pod-list suggestions should mention 위험 Pod: %+v", spList)
	}

	// Incident detail vs list differ.
	det := SuggestAgentPrompts(AgentPageContext{Route: "#/k8s-incidents", IncidentID: "i1"})
	if !strings.Contains(det[0].Text, "원인") {
		t.Fatalf("incident detail should suggest cause summary: %+v", det)
	}
}

func TestClassifyAgentIntent(t *testing.T) {
	cases := []struct{ text, route, want string }{
		{"이 Pod 왜 죽었어?", "#/k8s-home", IntentPod},
		{"비용 증가 원인 알려줘", "#/k8s-home", IntentCost},
		{"이 secret 바꾸면 영향은?", "#/k8s-home", IntentConfig},
		{"SLO 위반 서비스?", "#/k8s-home", IntentSLO},
		{"롤백 후보 알려줘", "#/k8s-home", IntentStack},
		{"안녕", "#/k8s-cost", IntentCost}, // no keyword → falls back to route
	}
	for _, c := range cases {
		if got := ClassifyAgentIntent(c.text, c.route); got != c.want {
			t.Errorf("ClassifyAgentIntent(%q,%q) = %q, want %q", c.text, c.route, got, c.want)
		}
	}
}
