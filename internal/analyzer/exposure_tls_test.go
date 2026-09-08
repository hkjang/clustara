package analyzer

import "testing"

func hasReason(f ExposureFinding, want string) bool {
	for _, r := range f.RiskReasons {
		if r == want {
			return true
		}
	}
	return false
}

// spec.tls[].hosts accepts wildcards, and a wildcard covers one DNS label. Comparing the literal
// strings reported a wildcard-certificate Ingress as plaintext (+30 risk).
func TestExposureWildcardTLSCoversHost(t *testing.T) {
	f := AnalyzeExposure(ExposureResourceInput{
		Kind: "Ingress", Namespace: "prod", Name: "web", Hosts: []string{"app.example.com"},
		HasTLS: true, TLSHosts: []string{"*.example.com"},
	})
	if hasReason(f, exposureReasonPlaintext) {
		t.Fatalf("*.example.com covers app.example.com: %+v", f.RiskReasons)
	}
	if f.RiskLevel != "low" {
		t.Fatalf("TLS-covered host should stay low, got %s (%d)", f.RiskLevel, f.RiskScore)
	}
}

// A wildcard matches exactly one label, so a deeper host is genuinely uncovered.
func TestExposureWildcardTLSDoesNotCoverDeeperHost(t *testing.T) {
	f := AnalyzeExposure(ExposureResourceInput{
		Kind: "Ingress", Namespace: "prod", Name: "deep", Hosts: []string{"a.b.example.com"},
		HasTLS: true, TLSHosts: []string{"*.example.com"},
	})
	if !hasReason(f, exposureReasonPlaintext) {
		t.Fatalf("a.b.example.com is not covered by *.example.com: %+v", f.RiskReasons)
	}
}

// DNS names are case-insensitive; a host spelled with capitals is still covered.
func TestExposureTLSHostMatchIsCaseInsensitive(t *testing.T) {
	f := AnalyzeExposure(ExposureResourceInput{
		Kind: "Ingress", Namespace: "prod", Name: "case", Hosts: []string{"Web.Example.com"},
		HasTLS: true, TLSHosts: []string{"web.example.com"},
	})
	if hasReason(f, exposureReasonPlaintext) {
		t.Fatalf("host match should ignore case: %+v", f.RiskReasons)
	}
}

// Plaintext/Wildcard are finding counts. Tallying reasons made one Ingress with three wildcard
// hosts report Wildcard=3 out of Total=1.
func TestSummarizeExposureCountsFindingsNotReasons(t *testing.T) {
	one := AnalyzeExposure(ExposureResourceInput{
		Kind: "Ingress", Namespace: "prod", Name: "multi",
		Hosts: []string{"*.a.example.com", "*.b.example.com", "*.c.example.com"},
	})
	s := SummarizeExposure([]ExposureFinding{one})
	if s.Total != 1 {
		t.Fatalf("expected Total 1, got %+v", s)
	}
	if s.Wildcard != 1 {
		t.Fatalf("one Ingress is one wildcard finding, got Wildcard=%d (Total=%d)", s.Wildcard, s.Total)
	}
	if s.Plaintext != 1 {
		t.Fatalf("one plaintext Ingress should count once, got Plaintext=%d", s.Plaintext)
	}
	if s.Wildcard > s.Total || s.Plaintext > s.Total {
		t.Fatalf("subcounts must not exceed Total: %+v", s)
	}
}
