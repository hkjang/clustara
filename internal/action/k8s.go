package action

import (
	"errors"
	"fmt"
	"strings"
)

type Decision struct {
	RiskLevel        string `json:"risk_level"`
	RequiresApproval bool   `json:"requires_approval"`
	DryRunRequired   bool   `json:"dry_run_required"`
	Reason           string `json:"reason"`
}

func Classify(action string) Decision {
	name := strings.ToLower(strings.TrimSpace(action))
	switch name {
	case "scale", "rollout_restart":
		return Decision{RiskLevel: "medium", RequiresApproval: false, DryRunRequired: true, Reason: "workload-scoped reversible action"}
	case "jupyter_server_start", "jupyter_server_stop":
		return Decision{RiskLevel: "medium", RequiresApproval: true, DryRunRequired: true, Reason: "user-scoped JupyterHub server lifecycle action"}
	case "cordon", "uncordon":
		return Decision{RiskLevel: "high", RequiresApproval: true, DryRunRequired: true, Reason: "node scheduling state change"}
	case "delete_pod":
		return Decision{RiskLevel: "high", RequiresApproval: true, DryRunRequired: true, Reason: "destructive pod lifecycle action"}
	case "drain":
		return Decision{RiskLevel: "critical", RequiresApproval: true, DryRunRequired: true, Reason: "node drain can evict many workloads"}
	case "apply_manifest":
		return Decision{RiskLevel: "high", RequiresApproval: true, DryRunRequired: true, Reason: "manifest mutation requires server-side dry-run review"}
	default:
		return Decision{RiskLevel: "medium", RequiresApproval: true, DryRunRequired: true, Reason: "unknown or custom action requires operator approval"}
	}
}

// TargetKindIssue reports why an action cannot address a resource kind, or "" when the kind fits.
//
// Every executable action addresses ONE fixed resource type: delete_pod issues
// DELETE /api/v1/namespaces/{ns}/pods/{name}, cordon PATCHes /api/v1/nodes/{name}. But
// resource_kind is free input that nothing validates, so a request recorded — and approved —
// as "Deployment/web delete_pod" executes as a delete of the *Pod* named web: the approval
// record and the audit trail then name a different object than the one that was touched.
// A blank kind claims nothing, so there is nothing to contradict and it is not judged.
func TargetKindIssue(actionName, kind string) string {
	k := normalizeKind(kind)
	if k == "" {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(actionName)) {
	case "scale":
		switch k {
		case "deployment", "statefulset":
			return ""
		case "daemonset":
			return "scale은 DaemonSet에 적용할 수 없습니다 — 노드마다 1개씩 실행되어 replicas가 없습니다(실행기가 거절합니다)."
		}
		return kindMismatch("scale", "Deployment/StatefulSet", kind)
	case "rollout_restart":
		switch k {
		case "deployment", "statefulset", "daemonset":
			return ""
		}
		return kindMismatch("rollout_restart", "Deployment/StatefulSet/DaemonSet", kind)
	case "delete_pod":
		if k == "pod" {
			return ""
		}
		return kindMismatch("delete_pod", "Pod", kind)
	case "cordon", "uncordon", "drain":
		if k == "node" {
			return ""
		}
		return kindMismatch(strings.ToLower(strings.TrimSpace(actionName)), "Node", kind)
	}
	return ""
}

// TargetKindIssueErr is TargetKindIssue for callers on an error path (the executor dispatch).
func TargetKindIssueErr(actionName, kind string) error {
	if issue := TargetKindIssue(actionName, kind); issue != "" {
		return errors.New(issue)
	}
	return nil
}

func kindMismatch(action, want, got string) string {
	return fmt.Sprintf("%s은 %s만 대상으로 할 수 있는데 요청 대상 kind는 %q입니다 — 승인 기록과 다른 리소스가 변경될 수 있습니다.", action, want, strings.TrimSpace(got))
}

// normalizeKind folds the spellings a resource_kind actually arrives in (kubectl short names,
// plurals, "apps/v1/Deployment") onto one lowercase singular kind.
func normalizeKind(kind string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	if i := strings.LastIndex(k, "/"); i >= 0 {
		k = k[i+1:] // apps/v1/Deployment, v1/Pod
	}
	if i := strings.Index(k, "."); i > 0 {
		k = k[:i] // deployments.apps
	}
	switch k {
	case "deploy", "deployment", "deployments":
		return "deployment"
	case "sts", "statefulset", "statefulsets":
		return "statefulset"
	case "ds", "daemonset", "daemonsets":
		return "daemonset"
	case "po", "pod", "pods":
		return "pod"
	case "no", "node", "nodes":
		return "node"
	}
	return k
}
