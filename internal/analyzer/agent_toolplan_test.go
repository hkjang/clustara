package analyzer

import (
	"strings"
	"testing"
)

func TestPlanAgentTools(t *testing.T) {
	// Incident detail → incident_detail first, includes graph + remediation.
	inc := PlanAgentTools(IntentIncident, AgentPageContext{IncidentID: "i1"})
	if len(inc) == 0 || inc[0].Tool != "incident_detail" {
		t.Fatalf("incident detail plan: %+v", inc)
	}
	tools := map[string]bool{}
	for _, c := range inc {
		tools[c.Tool] = true
	}
	if !tools["resource_graph"] || !tools["remediation"] {
		t.Fatalf("incident plan should include graph+remediation: %+v", inc)
	}

	// Incident list (no id) → falls back to incidents/home.
	incList := PlanAgentTools(IntentIncident, AgentPageContext{})
	if incList[0].Tool != "incidents" {
		t.Fatalf("incident list plan should start with incidents: %+v", incList)
	}

	// Pod detail → logs use previous=true.
	pod := PlanAgentTools(IntentPod, AgentPageContext{Pod: "web-1"})
	foundPrev := false
	for _, c := range pod {
		if c.Tool == "pod_logs" && strings.Contains(c.API, "previous=true") {
			foundPrev = true
		}
	}
	if !foundPrev {
		t.Fatalf("pod plan should fetch previous logs: %+v", pod)
	}

	// Config with name → config_impact.
	cfg := PlanAgentTools(IntentConfig, AgentPageContext{ConfigName: "app-cfg"})
	if cfg[0].Tool != "config_impact" {
		t.Fatalf("config plan: %+v", cfg)
	}

	// Cost → cost + rightsizing.
	cost := PlanAgentTools(IntentCost, AgentPageContext{})
	if len(cost) != 2 {
		t.Fatalf("cost plan should have cost+rightsizing: %+v", cost)
	}

	// Every plan is non-empty (general falls back to home+ai_ask).
	for _, intent := range []string{IntentIncident, IntentPod, IntentConfig, IntentStack, IntentCost, IntentSLO, IntentAction, IntentReport, IntentHome, IntentGeneral} {
		if len(PlanAgentTools(intent, AgentPageContext{})) == 0 {
			t.Fatalf("intent %q produced empty plan", intent)
		}
	}
}
