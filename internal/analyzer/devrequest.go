package analyzer

import "strings"

// Developer Self-Service Request Center (CLU-NEXT-01/02).
//
// Lets a developer raise an operational request from the Developer View, and maps it onto an
// EXISTING approval flow rather than a new parallel system: action requests go to the Action Center
// (approve → live executor), config edits go to Config Change Control, and read-only requests (log
// access) need no approval. This planner is the pure decision layer; the handler creates the entry.

// Developer request types.
const (
	DevReqRestart      = "restart"
	DevReqScale        = "scale"
	DevReqRollback     = "rollback"
	DevReqCordon       = "cordon"
	DevReqUncordon     = "uncordon"
	DevReqConfigChange = "config_change"
	DevReqLogAccess    = "log_access"
)

// Request flows (which existing subsystem handles approval/execution).
const (
	FlowAction       = "action"        // Action Center (approve → executor)
	FlowConfigChange = "config_change" // Config Change Control Center
	FlowReadOnly     = "readonly"      // no approval (read-only)
)

// DevRequestInput is a developer's request.
type DevRequestInput struct {
	Type         string
	ClusterID    string
	Namespace    string
	ResourceKind string
	ResourceName string
	Replicas     int    // for scale
	Reason       string
}

// DevRequestPlan is how the request maps onto an existing flow.
type DevRequestPlan struct {
	Type             string `json:"type"`
	Flow             string `json:"flow"`
	Action           string `json:"action"`            // action name when Flow==action
	RiskLevel        string `json:"risk_level"`        // low | medium | high
	RequiresApproval bool   `json:"requires_approval"`
	Executable       bool   `json:"executable"`        // can the live executor run it (vs manual)
	Summary          string `json:"summary"`
	TargetEndpoint   string `json:"target_endpoint"`   // where the request lands
	Valid            bool   `json:"valid"`
	Error            string `json:"error,omitempty"`
}

// PlanDevRequest maps a developer request to its approval flow + risk. Pure.
func PlanDevRequest(in DevRequestInput) DevRequestPlan {
	p := DevRequestPlan{Type: in.Type}
	target := strings.TrimSpace(in.Namespace) + "/" + strings.TrimSpace(in.ResourceKind) + "/" + strings.TrimSpace(in.ResourceName)
	switch in.Type {
	case DevReqRestart:
		p.Flow, p.Action, p.RiskLevel, p.RequiresApproval, p.Executable = FlowAction, "rollout_restart", "medium", true, true
		p.Summary = "롤아웃 재시작 요청 — " + target
		p.TargetEndpoint = "/admin/k8s/actions"
		p.Valid = in.ResourceName != ""
	case DevReqScale:
		p.Flow, p.Action, p.RiskLevel, p.RequiresApproval, p.Executable = FlowAction, "scale", "medium", true, true
		p.Summary = "스케일 요청 — " + target
		p.TargetEndpoint = "/admin/k8s/actions"
		p.Valid = in.ResourceName != "" && in.Replicas >= 0
		if !p.Valid && in.Replicas < 0 {
			p.Error = "scale 요청에는 replicas(>=0)가 필요합니다"
		}
	case DevReqCordon, DevReqUncordon:
		p.Flow, p.Action, p.RiskLevel, p.RequiresApproval, p.Executable = FlowAction, in.Type, "high", true, true
		p.Summary = in.Type + " 요청 — " + strings.TrimSpace(in.ResourceName)
		p.TargetEndpoint = "/admin/k8s/actions"
		p.Valid = in.ResourceName != ""
	case DevReqRollback:
		// No live rollback executor — tracked as an action request for manual operator handling.
		p.Flow, p.Action, p.RiskLevel, p.RequiresApproval, p.Executable = FlowAction, "rollback", "high", true, false
		p.Summary = "이전 리비전 롤백 요청(수동 처리) — " + target
		p.TargetEndpoint = "/admin/k8s/actions"
		p.Valid = in.ResourceName != ""
	case DevReqConfigChange:
		p.Flow, p.RiskLevel, p.RequiresApproval = FlowConfigChange, "high", true
		p.Summary = "Config 변경 요청 — " + target
		p.TargetEndpoint = "/admin/k8s/config-changes"
		p.Valid = in.ResourceName != ""
	case DevReqLogAccess:
		p.Flow, p.RiskLevel, p.RequiresApproval = FlowReadOnly, "low", false
		p.Summary = "로그 조회(읽기 전용) — " + target
		p.TargetEndpoint = "/admin/k8s/pods/{ns}/{pod}/logs"
		p.Valid = in.ResourceName != ""
	default:
		p.Error = "지원하지 않는 요청 유형: " + in.Type
		return p
	}
	if !p.Valid && p.Error == "" {
		p.Error = "대상 리소스(resource_name 등)가 필요합니다"
	}
	return p
}

// SupportedDevRequestTypes lists the request types the Developer Request Center offers.
func SupportedDevRequestTypes() []string {
	return []string{DevReqRestart, DevReqScale, DevReqRollback, DevReqCordon, DevReqUncordon, DevReqConfigChange, DevReqLogAccess}
}
