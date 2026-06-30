package analyzer

import "testing"

func TestAnalyzeExposure(t *testing.T) {
	// Ingress, no TLS, sensitive path → high.
	ing := AnalyzeExposure(ExposureResourceInput{
		Kind: "Ingress", Namespace: "prod", Name: "api", Hosts: []string{"api.example.com"},
		Paths: []string{"/actuator/health"}, TargetServices: []string{"api-svc"}, HasTLS: false,
	})
	if ing.RiskLevel != "high" {
		t.Fatalf("plaintext + sensitive path should be high: %+v", ing)
	}
	hasPlain, hasPath := false, false
	for _, r := range ing.RiskReasons {
		if r == "TLS 미적용(평문 노출)" {
			hasPlain = true
		}
		if r == "민감 경로 노출: /actuator/health" {
			hasPath = true
		}
	}
	if !hasPlain || !hasPath {
		t.Fatalf("expected plaintext + sensitive-path reasons: %+v", ing.RiskReasons)
	}

	// Ingress with TLS covering its host, normal path → low.
	safe := AnalyzeExposure(ExposureResourceInput{
		Kind: "Ingress", Namespace: "prod", Name: "web", Hosts: []string{"web.example.com"},
		Paths: []string{"/"}, HasTLS: true, TLSHosts: []string{"web.example.com"},
	})
	if safe.RiskLevel != "low" || safe.TLS != true {
		t.Fatalf("TLS-covered normal ingress should be low: %+v", safe)
	}

	// Wildcard host adds risk.
	wild := AnalyzeExposure(ExposureResourceInput{
		Kind: "Ingress", Namespace: "prod", Name: "wild", Hosts: []string{"*.example.com"}, HasTLS: true, TLSHosts: []string{"*.example.com"},
	})
	foundWild := false
	for _, r := range wild.RiskReasons {
		if r == "wildcard host: *.example.com" {
			foundWild = true
		}
	}
	if !foundWild {
		t.Fatalf("wildcard host should be flagged: %+v", wild.RiskReasons)
	}

	// LoadBalancer service → medium.
	lb := AnalyzeExposure(ExposureResourceInput{Kind: "Service", Namespace: "prod", Name: "lb", ServiceType: "LoadBalancer"})
	if lb.RiskLevel != "medium" {
		t.Fatalf("LoadBalancer should be medium: %+v", lb)
	}
}

func TestSummarizeAndSortExposure(t *testing.T) {
	f := []ExposureFinding{
		{Name: "a", RiskLevel: "low", RiskScore: 0},
		{Name: "b", RiskLevel: "high", RiskScore: 55, RiskReasons: []string{"TLS 미적용(평문 노출)", "wildcard host: *.x"}},
		{Name: "c", RiskLevel: "medium", RiskScore: 25},
	}
	s := SummarizeExposure(f)
	if s.Total != 3 || s.High != 1 || s.Medium != 1 || s.Low != 1 || s.Plaintext != 1 || s.Wildcard != 1 {
		t.Fatalf("summary wrong: %+v", s)
	}
	SortExposureFindings(f)
	if f[0].Name != "b" || f[2].Name != "a" {
		t.Fatalf("should sort riskiest-first: %+v", f)
	}
}
