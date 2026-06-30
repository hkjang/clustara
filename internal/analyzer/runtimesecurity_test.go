package analyzer

import "testing"

func TestScorePodSecurity(t *testing.T) {
	// Clean pod → restricted, low.
	clean := ScorePodSecurity(PodSecurityInput{Namespace: "p", Pod: "ok"})
	if clean.Profile != "restricted" || clean.RiskLevel != "low" {
		t.Fatalf("clean pod should be restricted/low: %+v", clean)
	}

	// Privileged + hostNetwork + SYS_ADMIN → privileged profile, high.
	priv := ScorePodSecurity(PodSecurityInput{
		Namespace: "p", Pod: "bad", Privileged: true, HostNetwork: true, AddedCaps: []string{"SYS_ADMIN"},
	})
	if priv.Profile != "privileged" || priv.RiskLevel != "high" {
		t.Fatalf("privileged pod should be privileged/high: %+v", priv)
	}
	if priv.RiskScore < 40 {
		t.Fatalf("privileged risk should be >=40: %+v", priv)
	}

	// hostPath + runAsRoot only → baseline.
	base := ScorePodSecurity(PodSecurityInput{Namespace: "p", Pod: "mid", HostPathVolumes: 1, RunAsRoot: true})
	if base.Profile != "baseline" {
		t.Fatalf("hostPath+runAsRoot should be baseline: %+v", base)
	}

	// allowPrivEsc only → medium-ish baseline.
	esc := ScorePodSecurity(PodSecurityInput{Namespace: "p", Pod: "esc", AllowPrivEsc: true})
	if esc.Profile != "baseline" {
		t.Fatalf("allowPrivEsc should demote to baseline: %+v", esc)
	}
}

func TestSummarizePodSecurity(t *testing.T) {
	f := []PodSecurityFinding{
		{Pod: "a", RiskLevel: "low", Profile: "restricted"},
		{Pod: "b", RiskLevel: "high", Profile: "privileged", RiskScore: 60},
		{Pod: "c", RiskLevel: "medium", Profile: "baseline", RiskScore: 25},
	}
	s := SummarizePodSecurity(f)
	if s.Total != 3 || s.High != 1 || s.Medium != 1 || s.Low != 1 || s.Privileged != 1 || s.Baseline != 1 || s.Restricted != 1 {
		t.Fatalf("summary wrong: %+v", s)
	}
	SortPodSecurityFindings(f)
	if f[0].Pod != "b" || f[2].Pod != "a" {
		t.Fatalf("should sort riskiest-first: %+v", f)
	}
}
