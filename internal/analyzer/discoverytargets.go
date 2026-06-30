package analyzer

import (
	"sort"
	"strings"
)

// Dynamic Inventory Target + CRD Auto + MCP Tool Candidate Generator (CLU-DISC-06/07/11).
//
// Turns the discovered API resource catalog into actionable suggestions: which resources are
// collectable inventory targets (with CRD + sensitivity hints), and which read-only MCP tools an
// AI agent could safely call. Pure over []APIResourceInfo.

// coreWorkloadKinds are the built-in kinds Clustara already treats as primary operational inventory.
var coreWorkloadKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true, "ReplicaSet": true,
	"Service": true, "Ingress": true, "ConfigMap": true, "Job": true, "CronJob": true,
	"Node": true, "Namespace": true, "PersistentVolumeClaim": true, "HorizontalPodAutoscaler": true,
	"Event": true, "Endpoints": true, "ReplicationController": true,
}

// sensitiveResources hold secret material and should be opt-in / masked.
var sensitiveResources = map[string]bool{"secrets": true, "serviceaccounts": true}

// InventoryTargetSuggestion is one collectable resource the operator can enable/skip.
type InventoryTargetSuggestion struct {
	GroupVersion string `json:"group_version"`
	Resource     string `json:"resource"`
	Kind         string `json:"kind"`
	Namespaced   bool   `json:"namespaced"`
	Recommended  bool   `json:"recommended"` // core workload kind → default-on
	Sensitive    bool   `json:"sensitive"`   // secret material → opt-in
	IsCRD        bool   `json:"is_crd"`
	Reason       string `json:"reason"`
}

// SuggestInventoryTargets derives collection-target candidates from list+watch-capable resources.
func SuggestInventoryTargets(resources []APIResourceInfo) []InventoryTargetSuggestion {
	out := []InventoryTargetSuggestion{}
	for _, r := range resources {
		if !r.Listable {
			continue
		}
		isCRD := strings.Contains(r.Group, ".")
		sensitive := sensitiveResources[r.Resource]
		sug := InventoryTargetSuggestion{
			GroupVersion: r.GroupVersion(), Resource: r.Resource, Kind: r.Kind, Namespaced: r.Namespaced,
			Recommended: coreWorkloadKinds[r.Kind] && !sensitive, Sensitive: sensitive, IsCRD: isCRD,
		}
		switch {
		case sensitive:
			sug.Reason = "민감 리소스 — 기본 제외, 필요 시 마스킹 적용 후 수집"
		case sug.Recommended:
			sug.Reason = "핵심 운영 워크로드 — 기본 수집 권장"
		case isCRD:
			sug.Reason = "CRD/확장 리소스 — 운영 관련 시 선택 수집"
		default:
			sug.Reason = "list/watch 가능 — 선택 수집"
		}
		out = append(out, sug)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Recommended != out[j].Recommended {
			return out[i].Recommended // recommended first
		}
		if out[i].GroupVersion != out[j].GroupVersion {
			return out[i].GroupVersion < out[j].GroupVersion
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

// MCPToolCandidate is a proposed read-only MCP tool for a resource.
type MCPToolCandidate struct {
	ToolName     string `json:"tool_name"`
	Verb         string `json:"verb"` // list | get | explain
	Resource     string `json:"resource"`
	Kind         string `json:"kind"`
	GroupVersion string `json:"group_version"`
	Scope        string `json:"scope"` // namespaced | cluster
	RiskLevel    string `json:"risk_level"`
	MaskingLevel string `json:"masking_level"` // none | secret-redacted
	Reason       string `json:"reason"`
}

// GenerateMCPToolCandidates produces read-only tool candidates (list/get/explain) per resource,
// skipping resources without read verbs. Secret material is marked for redaction.
func GenerateMCPToolCandidates(resources []APIResourceInfo) []MCPToolCandidate {
	out := []MCPToolCandidate{}
	for _, r := range resources {
		scope := "cluster"
		if r.Namespaced {
			scope = "namespaced"
		}
		masking := "none"
		if sensitiveResources[r.Resource] {
			masking = "secret-redacted"
		}
		base := MCPToolCandidate{
			Resource: r.Resource, Kind: r.Kind, GroupVersion: r.GroupVersion(), Scope: scope,
			RiskLevel: "low", MaskingLevel: masking,
		}
		if hasVerb(r.Verbs, "list") {
			c := base
			c.ToolName, c.Verb, c.Reason = "k8s_list_"+r.Resource, "list", "read-only 목록 조회"
			out = append(out, c)
		}
		if hasVerb(r.Verbs, "get") {
			c := base
			c.ToolName, c.Verb, c.Reason = "k8s_get_"+singularResource(r.Resource), "get", "read-only 단건 조회"
			out = append(out, c)
		}
		// explain reads only the cached schema (never the cluster), so it's always safe.
		ce := base
		ce.ToolName, ce.Verb, ce.MaskingLevel, ce.Reason = "k8s_explain_"+singularResource(r.Resource), "explain", "none", "스키마 필드 설명(클러스터 미접근)"
		out = append(out, ce)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ToolName < out[j].ToolName })
	return out
}

// singularResource is a light pluralizer-inverse for tool naming (deployments→deployment, ingresses→ingress).
func singularResource(resource string) string {
	switch {
	case strings.HasSuffix(resource, "ies"):
		return resource[:len(resource)-3] + "y"
	case strings.HasSuffix(resource, "ses"), strings.HasSuffix(resource, "xes"), strings.HasSuffix(resource, "ches"):
		return resource[:len(resource)-2]
	case strings.HasSuffix(resource, "s"):
		return resource[:len(resource)-1]
	default:
		return resource
	}
}

// DiscoveryTargetsSummary tallies suggestions for the UI header.
type DiscoveryTargetsSummary struct {
	TotalTargets   int `json:"total_targets"`
	Recommended    int `json:"recommended"`
	Sensitive      int `json:"sensitive"`
	CRDTargets     int `json:"crd_targets"`
	ToolCandidates int `json:"tool_candidates"`
}

// SummarizeDiscoveryTargets rolls up target + tool-candidate counts.
func SummarizeDiscoveryTargets(targets []InventoryTargetSuggestion, tools []MCPToolCandidate) DiscoveryTargetsSummary {
	s := DiscoveryTargetsSummary{TotalTargets: len(targets), ToolCandidates: len(tools)}
	for _, t := range targets {
		if t.Recommended {
			s.Recommended++
		}
		if t.Sensitive {
			s.Sensitive++
		}
		if t.IsCRD {
			s.CRDTargets++
		}
	}
	return s
}
