package analyzer

import "fmt"

// Workspace Template (CLU-NEXT-10).
//
// Generates the standard manifest set for a new business Workspace (namespace) — Namespace with
// owner labels, a ResourceQuota, a LimitRange, and a default-deny NetworkPolicy — so new workspaces
// start governed by default. Pure string generation; the operator applies it via Stack Apply.

// WorkspaceTemplateRequest describes the workspace to scaffold.
type WorkspaceTemplateRequest struct {
	Namespace   string
	OwnerTeam   string
	Environment string
	CostCenter  string
	CPUQuota    string // e.g. "10" cores
	MemQuota    string // e.g. "20Gi"
	PodQuota    string // e.g. "50"
	DefaultDeny bool   // add a default-deny NetworkPolicy
}

// WorkspaceTemplate is the generated bundle.
type WorkspaceTemplate struct {
	Namespace string   `json:"namespace"`
	Manifest  string   `json:"manifest"`
	Resources []string `json:"resources"`
	Notes     []string `json:"notes"`
}

// GenerateWorkspaceTemplate builds the standard governed-namespace manifest set.
func GenerateWorkspaceTemplate(req WorkspaceTemplateRequest) WorkspaceTemplate {
	ns := orDefault(req.Namespace, "new-workspace")
	team := orDefault(req.OwnerTeam, "unassigned")
	env := orDefault(req.Environment, "dev")
	cpu := orDefault(req.CPUQuota, "10")
	mem := orDefault(req.MemQuota, "20Gi")
	pods := orDefault(req.PodQuota, "50")

	out := WorkspaceTemplate{Namespace: ns, Resources: []string{"Namespace", "ResourceQuota", "LimitRange"}, Notes: []string{}}
	m := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    clustara.io/workspace: "%s"
    clustara.io/team: "%s"
    clustara.io/environment: "%s"
    clustara.io/cost-center: "%s"
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: %s-quota
  namespace: %s
spec:
  hard:
    requests.cpu: "%s"
    requests.memory: "%s"
    limits.cpu: "%s"
    limits.memory: "%s"
    pods: "%s"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: %s-limits
  namespace: %s
spec:
  limits:
    - type: Container
      default:
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
`, ns, ns, team, env, orDefault(req.CostCenter, "none"),
		ns, ns, cpu, mem, cpu, mem, pods,
		ns, ns)

	if req.DefaultDeny {
		m += fmt.Sprintf(`---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s-default-deny
  namespace: %s
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
`, ns, ns)
		out.Resources = append(out.Resources, "NetworkPolicy")
		out.Notes = append(out.Notes, "default-deny NetworkPolicy 포함 — 필요한 통신은 별도 NetworkPolicy로 허용하세요.")
	}
	out.Manifest = m
	out.Notes = append(out.Notes, "이 매니페스트를 앱 배포(Stack)로 검증·승인 후 적용하세요. Clustara는 직접 생성하지 않습니다.")
	return out
}
