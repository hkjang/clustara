package action

import "strings"

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
