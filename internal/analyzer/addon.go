package analyzer

import (
	"sort"
	"strings"
)

// Add-on Marketplace — install-plan risk preview (CLU-OCP-06).
//
// Clustara does not install Operators/Helm charts (that needs live cluster + package handling). But
// previewing *what an install would create* and scoring its blast radius is pure and high-value:
// CRDs, cluster-scoped RBAC, webhooks, APIServices, and privileged/hostPath workloads materially
// expand a cluster's attack surface. Pure over the parsed bundle's resources.

// InstallResource is one object an install bundle would create.
type InstallResource struct {
	Kind          string
	Name          string
	ClusterScoped bool   // ClusterRole/ClusterRoleBinding/CRD/APIService/...
	GrantsAdmin   bool   // RBAC rule with * verbs/resources or cluster-admin ref
	Privileged    bool   // workload runs privileged / hostPath
}

// InstallPlanRisk is the scored preview.
type InstallPlanRisk struct {
	TotalResources int      `json:"total_resources"`
	CRDs           int      `json:"crds"`
	ClusterRBAC    int      `json:"cluster_rbac"`
	Webhooks       int      `json:"webhooks"`
	APIServices    int      `json:"api_services"`
	Privileged     int      `json:"privileged"`
	AdminGrants    int      `json:"admin_grants"`
	RiskScore      int      `json:"risk_score"`
	RiskLevel      string   `json:"risk_level"` // low | medium | high
	RequiresApproval bool   `json:"requires_approval"`
	Reasons        []string `json:"reasons"`
}

// AnalyzeInstallPlan scores the blast radius of installing the given resources.
func AnalyzeInstallPlan(resources []InstallResource) InstallPlanRisk {
	r := InstallPlanRisk{TotalResources: len(resources), Reasons: []string{}}
	score := 0
	for _, res := range resources {
		switch {
		case strings.EqualFold(res.Kind, "CustomResourceDefinition"):
			r.CRDs++
		case strings.EqualFold(res.Kind, "ClusterRole") || strings.EqualFold(res.Kind, "ClusterRoleBinding"):
			r.ClusterRBAC++
		case strings.EqualFold(res.Kind, "ValidatingWebhookConfiguration") || strings.EqualFold(res.Kind, "MutatingWebhookConfiguration"):
			r.Webhooks++
		case strings.EqualFold(res.Kind, "APIService"):
			r.APIServices++
		}
		if res.GrantsAdmin {
			r.AdminGrants++
		}
		if res.Privileged {
			r.Privileged++
		}
	}
	if r.CRDs > 0 {
		score += 10
		r.Reasons = append(r.Reasons, "CRD 추가 "+itoaLifecycle(r.CRDs)+"개")
	}
	if r.ClusterRBAC > 0 {
		score += 15
		r.Reasons = append(r.Reasons, "cluster 범위 RBAC "+itoaLifecycle(r.ClusterRBAC)+"개")
	}
	if r.AdminGrants > 0 {
		score += 30
		r.Reasons = append(r.Reasons, "광범위(admin/*) 권한 부여 "+itoaLifecycle(r.AdminGrants)+"개")
	}
	if r.Webhooks > 0 {
		score += 20
		r.Reasons = append(r.Reasons, "admission webhook "+itoaLifecycle(r.Webhooks)+"개(클러스터 전역 영향)")
	}
	if r.APIServices > 0 {
		score += 15
		r.Reasons = append(r.Reasons, "APIService 추가(aggregated API)")
	}
	if r.Privileged > 0 {
		score += 25
		r.Reasons = append(r.Reasons, "privileged/hostPath 워크로드 "+itoaLifecycle(r.Privileged)+"개")
	}
	r.RiskScore = clampScore(score)
	switch {
	case r.RiskScore >= 45:
		r.RiskLevel = "high"
	case r.RiskScore >= 20:
		r.RiskLevel = "medium"
	default:
		r.RiskLevel = "low"
	}
	r.RequiresApproval = r.RiskLevel == "high"
	if len(r.Reasons) == 0 {
		r.Reasons = append(r.Reasons, "고위험 요소 없음")
	}
	sort.Strings(r.Reasons)
	return r
}
