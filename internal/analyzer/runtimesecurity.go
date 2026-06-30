package analyzer

import (
	"sort"
	"strings"
)

// Runtime Security Profile (CLU-OCP-03).
//
// Absorbs OpenShift's SCC UX as a generic Kubernetes notion: scores a pod's runtime security from
// its SecurityContext / host namespaces / volumes / capabilities and classifies it against the Pod
// Security Standard levels (restricted / baseline / privileged). Pure: the handler extracts fields.

// PodSecurityInput is one pod's parsed runtime-security signals.
type PodSecurityInput struct {
	Namespace       string
	Pod             string
	Owner           string
	HostNetwork     bool
	HostPID         bool
	HostIPC         bool
	HostPathVolumes int
	Privileged      bool     // any container privileged
	AllowPrivEsc    bool     // any container allowPrivilegeEscalation
	RunAsRoot       bool     // runAsUser 0 / runAsNonRoot false
	AddedCaps       []string // added Linux capabilities
}

// dangerousCaps materially expand a container's host access.
var dangerousCaps = map[string]bool{"SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "ALL": true}

// PodSecurityFinding is the scored runtime-security result for one pod.
type PodSecurityFinding struct {
	Namespace string   `json:"namespace"`
	Pod       string   `json:"pod"`
	Owner     string   `json:"owner,omitempty"`
	RiskScore int      `json:"risk_score"` // 0..100 (higher = riskier)
	RiskLevel string   `json:"risk_level"` // low | medium | high
	Profile   string   `json:"profile"`    // restricted | baseline | privileged
	Findings  []string `json:"findings"`
}

// ScorePodSecurity rates one pod's runtime security and classifies its Pod Security profile.
func ScorePodSecurity(in PodSecurityInput) PodSecurityFinding {
	f := PodSecurityFinding{Namespace: in.Namespace, Pod: in.Pod, Owner: in.Owner, Findings: []string{}}
	score := 0
	profile := "restricted"
	demote := func(p string) {
		// privileged is the weakest, restricted the strongest; only move toward weaker.
		order := map[string]int{"restricted": 0, "baseline": 1, "privileged": 2}
		if order[p] > order[profile] {
			profile = p
		}
	}

	if in.Privileged {
		score += 40
		f.Findings = append(f.Findings, "privileged 컨테이너")
		demote("privileged")
	}
	if in.HostNetwork {
		score += 20
		f.Findings = append(f.Findings, "hostNetwork")
		demote("privileged")
	}
	if in.HostPID {
		score += 15
		f.Findings = append(f.Findings, "hostPID")
		demote("privileged")
	}
	if in.HostIPC {
		score += 15
		f.Findings = append(f.Findings, "hostIPC")
		demote("privileged")
	}
	if in.HostPathVolumes > 0 {
		score += 15
		f.Findings = append(f.Findings, "hostPath 볼륨")
		demote("baseline")
	}
	for _, c := range in.AddedCaps {
		if dangerousCaps[strings.ToUpper(strings.TrimSpace(c))] {
			score += 20
			f.Findings = append(f.Findings, "위험 capability: "+c)
			demote("privileged")
			break
		}
	}
	if in.RunAsRoot {
		score += 15
		f.Findings = append(f.Findings, "root(runAsUser 0)로 실행")
		demote("baseline")
	}
	if in.AllowPrivEsc {
		score += 10
		f.Findings = append(f.Findings, "allowPrivilegeEscalation")
		demote("baseline")
	}

	f.RiskScore = clampScore(score)
	f.Profile = profile
	switch {
	case f.RiskScore >= 40:
		f.RiskLevel = "high"
	case f.RiskScore >= 15:
		f.RiskLevel = "medium"
	default:
		f.RiskLevel = "low"
	}
	if len(f.Findings) == 0 {
		f.Findings = append(f.Findings, "위험 설정 없음")
	}
	return f
}

// PodSecuritySummary is the fleet rollup.
type PodSecuritySummary struct {
	Total      int `json:"total"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Privileged int `json:"privileged"` // profile == privileged
	Baseline   int `json:"baseline"`
	Restricted int `json:"restricted"`
}

// SummarizePodSecurity tallies findings by risk + profile.
func SummarizePodSecurity(findings []PodSecurityFinding) PodSecuritySummary {
	s := PodSecuritySummary{Total: len(findings)}
	for _, f := range findings {
		switch f.RiskLevel {
		case "high":
			s.High++
		case "medium":
			s.Medium++
		default:
			s.Low++
		}
		switch f.Profile {
		case "privileged":
			s.Privileged++
		case "baseline":
			s.Baseline++
		default:
			s.Restricted++
		}
	}
	return s
}

// SortPodSecurityFindings orders riskiest-first.
func SortPodSecurityFindings(findings []PodSecurityFinding) {
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].RiskLevel] != rank[findings[j].RiskLevel] {
			return rank[findings[i].RiskLevel] < rank[findings[j].RiskLevel]
		}
		if findings[i].RiskScore != findings[j].RiskScore {
			return findings[i].RiskScore > findings[j].RiskScore
		}
		return findings[i].Namespace+findings[i].Pod < findings[j].Namespace+findings[j].Pod
	})
}
