package analyzer

import "testing"

func sampleResources() []APIResourceInfo {
	return []APIResourceInfo{
		{Group: "", Version: "v1", Resource: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get", "list", "watch"}, Listable: true},
		{Group: "", Version: "v1", Resource: "secrets", Kind: "Secret", Namespaced: true, Verbs: []string{"get", "list", "watch"}, Listable: true},
		{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment", Namespaced: true, Verbs: []string{"get", "list", "watch"}, Listable: true},
		{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheusrules", Kind: "PrometheusRule", Namespaced: true, Verbs: []string{"get", "list", "watch"}, Listable: true},
		// not listable → not a target, but get→tool candidate.
		{Group: "authentication.k8s.io", Version: "v1", Resource: "tokenreviews", Kind: "TokenReview", Namespaced: false, Verbs: []string{"create"}, Listable: false},
	}
}

func TestSuggestInventoryTargets(t *testing.T) {
	targets := SuggestInventoryTargets(sampleResources())
	// only listable (4 of 5)
	if len(targets) != 4 {
		t.Fatalf("expected 4 targets: %+v", targets)
	}
	// recommended first; pods + deployments recommended, secrets sensitive (not recommended), prometheusrules CRD
	if !targets[0].Recommended {
		t.Fatalf("first should be recommended: %+v", targets[0])
	}
	by := map[string]InventoryTargetSuggestion{}
	for _, t := range targets {
		by[t.Resource] = t
	}
	if !by["secrets"].Sensitive || by["secrets"].Recommended {
		t.Fatalf("secrets should be sensitive, not recommended: %+v", by["secrets"])
	}
	if !by["prometheusrules"].IsCRD {
		t.Fatalf("prometheusrules should be CRD: %+v", by["prometheusrules"])
	}
	if !by["pods"].Recommended || !by["deployments"].Recommended {
		t.Fatalf("core workloads should be recommended: %+v", by)
	}

	sum := SummarizeDiscoveryTargets(targets, nil)
	if sum.Recommended != 2 || sum.Sensitive != 1 || sum.CRDTargets != 1 {
		t.Fatalf("summary wrong: %+v", sum)
	}
}

func TestGenerateMCPToolCandidates(t *testing.T) {
	tools := GenerateMCPToolCandidates(sampleResources())
	names := map[string]MCPToolCandidate{}
	for _, c := range tools {
		names[c.ToolName] = c
	}
	// pods: list + get + explain
	if _, ok := names["k8s_list_pods"]; !ok {
		t.Fatalf("expected k8s_list_pods: %+v", tools)
	}
	if _, ok := names["k8s_get_pod"]; !ok {
		t.Fatalf("expected k8s_get_pod (singular): %+v", tools)
	}
	if _, ok := names["k8s_explain_pod"]; !ok {
		t.Fatalf("expected k8s_explain_pod: %+v", tools)
	}
	// secrets list tool must be masked.
	if names["k8s_list_secrets"].MaskingLevel != "secret-redacted" {
		t.Fatalf("secrets list should be masked: %+v", names["k8s_list_secrets"])
	}
	// explain is never masked (no cluster access).
	if names["k8s_explain_secret"].MaskingLevel != "none" {
		t.Fatalf("explain should not be masked: %+v", names["k8s_explain_secret"])
	}
	// tokenreviews: no list/get (only create) → only explain candidate.
	if _, ok := names["k8s_list_tokenreviews"]; ok {
		t.Fatalf("tokenreviews has no list verb — should have no list tool")
	}
	if _, ok := names["k8s_explain_tokenreview"]; !ok {
		t.Fatalf("expected explain for tokenreviews: %+v", tools)
	}
	// every candidate is read-only / low risk.
	for _, c := range tools {
		if c.RiskLevel != "low" {
			t.Fatalf("all candidates must be low risk: %+v", c)
		}
	}
}

func TestSingularResource(t *testing.T) {
	cases := map[string]string{"deployments": "deployment", "ingresses": "ingress", "policies": "policy", "pods": "pod", "endpoints": "endpoint"}
	for in, want := range cases {
		if got := singularResource(in); got != want {
			t.Fatalf("singular(%q)=%q want %q", in, got, want)
		}
	}
}
