package analyzer

import (
	"sort"
	"strings"
)

// Exposure Center (CLU-OCP-02).
//
// Absorbs OpenShift's Route UX as a generic Kubernetes notion: analyzes how workloads are exposed
// externally (Ingress, Gateway/HTTPRoute, LoadBalancer/NodePort Services) and scores the risk —
// plaintext (no TLS), wildcard hosts, sensitive paths (/actuator, /swagger, /admin, /metrics,
// /debug), and broad Service exposure. Pure: the handler extracts the fields from inventory specs.

// ExposureResourceInput is one exposure-capable resource's parsed fields.
type ExposureResourceInput struct {
	Kind           string // Ingress | Service | Gateway | HTTPRoute
	Namespace      string
	Name           string
	Hosts          []string
	Paths          []string
	TargetServices []string
	HasTLS         bool
	TLSHosts       []string // hosts covered by a TLS block (for Ingress)
	ServiceType    string   // for Service: LoadBalancer | NodePort | ClusterIP
}

// ExposureFinding is the scored exposure analysis for one resource.
type ExposureFinding struct {
	Kind           string   `json:"kind"`
	Namespace      string   `json:"namespace"`
	Name           string   `json:"name"`
	Hosts          []string `json:"hosts"`
	Paths          []string `json:"paths"`
	TargetServices []string `json:"target_services"`
	TLS            bool     `json:"tls"`
	RiskScore      int      `json:"risk_score"` // 0..100 (higher = riskier)
	RiskLevel      string   `json:"risk_level"` // low | medium | high
	RiskReasons    []string `json:"risk_reasons"`
}

// sensitivePathPrefixes are paths that should rarely be publicly exposed.
var sensitivePathPrefixes = []string{"/actuator", "/swagger", "/admin", "/metrics", "/debug", "/.env", "/api-docs", "/wp-admin"}

// AnalyzeExposure scores one exposure resource.
func AnalyzeExposure(in ExposureResourceInput) ExposureFinding {
	f := ExposureFinding{
		Kind: in.Kind, Namespace: in.Namespace, Name: in.Name, Hosts: nonNil(in.Hosts), Paths: nonNil(in.Paths),
		TargetServices: nonNil(in.TargetServices), TLS: in.HasTLS, RiskReasons: []string{},
	}
	score := 0
	tlsHosts := map[string]bool{}
	for _, h := range in.TLSHosts {
		tlsHosts[h] = true
	}

	switch in.Kind {
	case "Ingress", "Gateway", "HTTPRoute":
		// Plaintext exposure: a host without TLS coverage.
		plaintext := false
		for _, h := range in.Hosts {
			if !in.HasTLS || (len(tlsHosts) > 0 && !tlsHosts[h]) {
				plaintext = true
			}
			if strings.HasPrefix(h, "*.") || h == "*" {
				score += 15
				f.RiskReasons = append(f.RiskReasons, "wildcard host: "+h)
			}
		}
		if plaintext || (len(in.Hosts) == 0 && !in.HasTLS) {
			score += 30
			f.RiskReasons = append(f.RiskReasons, "TLS 미적용(평문 노출)")
		}
	case "Service":
		switch strings.ToLower(in.ServiceType) {
		case "loadbalancer":
			score += 25
			f.RiskReasons = append(f.RiskReasons, "LoadBalancer(외부 공개)")
		case "nodeport":
			score += 20
			f.RiskReasons = append(f.RiskReasons, "NodePort(노드 포트 광범위 노출)")
		}
	}

	// Sensitive paths exposed.
	for _, p := range in.Paths {
		lp := strings.ToLower(p)
		for _, sp := range sensitivePathPrefixes {
			if strings.HasPrefix(lp, sp) {
				score += 25
				f.RiskReasons = append(f.RiskReasons, "민감 경로 노출: "+p)
				break
			}
		}
	}

	f.RiskScore = clampScore(score)
	switch {
	case f.RiskScore >= 50:
		f.RiskLevel = "high"
	case f.RiskScore >= 20:
		f.RiskLevel = "medium"
	default:
		f.RiskLevel = "low"
	}
	if len(f.RiskReasons) == 0 {
		f.RiskReasons = append(f.RiskReasons, "특이 위험 없음")
	}
	return f
}

// ExposureSummary is the fleet rollup.
type ExposureSummary struct {
	Total     int `json:"total"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
	Plaintext int `json:"plaintext"`
	Wildcard  int `json:"wildcard"`
}

// SummarizeExposure tallies findings + sorts them riskiest-first.
func SummarizeExposure(findings []ExposureFinding) ExposureSummary {
	s := ExposureSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.RiskLevel {
		case "high":
			s.High++
		case "medium":
			s.Medium++
		default:
			s.Low++
		}
		for _, r := range f.RiskReasons {
			if strings.Contains(r, "평문") {
				s.Plaintext++
			}
			if strings.Contains(r, "wildcard") {
				s.Wildcard++
			}
		}
	}
	return s
}

// SortExposureFindings orders riskiest-first.
func SortExposureFindings(findings []ExposureFinding) {
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].RiskLevel] != rank[findings[j].RiskLevel] {
			return rank[findings[i].RiskLevel] < rank[findings[j].RiskLevel]
		}
		if findings[i].RiskScore != findings[j].RiskScore {
			return findings[i].RiskScore > findings[j].RiskScore
		}
		return findings[i].Namespace+findings[i].Name < findings[j].Namespace+findings[j].Name
	})
}
