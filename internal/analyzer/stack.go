package analyzer

import (
	"sort"
	"strconv"
	"strings"
)

// Application Stack dry-run: validate a multi-document Kubernetes manifest BEFORE applying it —
// enumerate the resources, run the policy pack against pod-bearing resources, and flag the changes
// that should gate on approval (Secret/PVC/Ingress/RBAC/...). Pure over the decoded docs; no apply,
// no cluster state required. The "impact preview" foundation for Portainer-style Stack deploys.

// StackResource is one resource in the manifest.
type StackResource struct {
	Kind           string `json:"kind"`
	APIVersion     string `json:"api_version"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	Approval       bool   `json:"approval"`
	ApprovalReason string `json:"approval_reason,omitempty"`
}

// StackPlan is the dry-run result.
type StackPlan struct {
	Resources        []StackResource `json:"resources"`
	PolicyViolations []PolicyResult  `json:"policy_violations"`
	RequiresApproval bool            `json:"requires_approval"`
	ApprovalReasons  []string        `json:"approval_reasons"`
	Warnings         []string        `json:"warnings"`
	Denied           bool            `json:"denied"` // a Deny policy matched → block before apply
}

// approvalKinds are resource kinds whose creation/change is sensitive enough to require approval.
var approvalKinds = map[string]string{
	"Secret":             "Secret 변경",
	"PersistentVolumeClaim": "스토리지(PVC) 변경",
	"Ingress":            "외부 노출(Ingress) 변경",
	"NetworkPolicy":      "네트워크 정책 변경",
	"Role":               "RBAC 변경",
	"RoleBinding":        "RBAC 바인딩 변경",
	"ClusterRole":        "클러스터 RBAC 변경",
	"ClusterRoleBinding": "클러스터 RBAC 바인딩 변경",
	"ResourceQuota":      "리소스 쿼터 변경",
	"Namespace":          "네임스페이스 변경",
}

// AnalyzeStackManifest validates the decoded manifest documents against the policy pack and flags
// approval-gating resources. Pure over its inputs.
func AnalyzeStackManifest(docs []map[string]any, policies []Policy) StackPlan {
	plan := StackPlan{Resources: []StackResource{}, PolicyViolations: []PolicyResult{}, ApprovalReasons: []string{}, Warnings: []string{}}
	reasonSeen := map[string]bool{}
	for i, doc := range docs {
		if len(doc) == 0 {
			continue
		}
		kind := strings.TrimSpace(str(doc["kind"]))
		meta := asAnyMap(doc["metadata"])
		name := strings.TrimSpace(str(meta["name"]))
		ns := strings.TrimSpace(str(meta["namespace"]))
		if kind == "" || name == "" {
			plan.Warnings = append(plan.Warnings, "문서 #"+strconv.Itoa(i+1)+": kind/metadata.name 누락 — 유효한 리소스가 아닙니다")
			continue
		}
		res := StackResource{Kind: kind, APIVersion: strings.TrimSpace(str(doc["apiVersion"])), Namespace: ns, Name: name}
		if reason, ok := approvalKinds[kind]; ok {
			res.Approval = true
			res.ApprovalReason = reason
			if !reasonSeen[reason] {
				reasonSeen[reason] = true
				plan.ApprovalReasons = append(plan.ApprovalReasons, reason)
			}
		}
		plan.Resources = append(plan.Resources, res)

		// Policy pack: evaluate pod-bearing resources (and bare Pods) against the guardrails.
		spec := asAnyMap(doc["spec"])
		for _, pr := range EvaluatePolicies(kind, spec, policies) {
			if pr.Violated {
				plan.PolicyViolations = append(plan.PolicyViolations, pr)
				if strings.EqualFold(pr.Action, "Deny") {
					plan.Denied = true
				}
			}
		}
	}
	if len(plan.Resources) == 0 && len(plan.Warnings) == 0 {
		plan.Warnings = append(plan.Warnings, "유효한 Kubernetes 리소스를 찾지 못했습니다")
	}
	plan.RequiresApproval = plan.Denied || len(plan.ApprovalReasons) > 0
	sort.Strings(plan.ApprovalReasons)
	return plan
}
