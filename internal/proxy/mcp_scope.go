package proxy

import (
	"encoding/json"
	"strings"

	"clustara/internal/store"
)

// MCP Tool Scope Enforcement (CLU-REQ-11): evaluate a per-tool least-privilege policy. Scopes are
// opt-in — when none is configured for a (server, tool) the gateway behaviour is unchanged. When a
// scope exists and is enabled it constrains the caller's role and the namespace/cluster its
// arguments may target, and can force or skip the approval gate.

type mcpScopeDecision struct {
	Blocked       bool
	Reason        string
	ForceApproval bool   // approval_rule = always
	SkipApproval  bool   // approval_rule = never
	MaskingLevel  string // surfaced for response masking + audit
}

// evaluateMCPToolScope applies a tool scope to a call's role + target namespace/cluster. Pure.
// An empty allow-list means "any"; a '*' entry also means "any". Namespace/cluster are only checked
// when the call actually carries that target (tools without such args are not constrained on it).
func evaluateMCPToolScope(scope store.MCPToolScope, role, namespace, cluster string) mcpScopeDecision {
	d := mcpScopeDecision{MaskingLevel: scope.MaskingLevel}
	if !scope.Enabled {
		return d
	}
	if !csvAllows(scope.AllowedRoles, role) {
		d.Blocked = true
		d.Reason = "role '" + role + "' is not allowed for this tool"
		return d
	}
	if namespace != "" && !csvAllows(scope.AllowedNamespaces, namespace) {
		d.Blocked = true
		d.Reason = "namespace '" + namespace + "' is outside this tool's allowed scope"
		return d
	}
	if cluster != "" && !csvAllows(scope.AllowedClusters, cluster) {
		d.Blocked = true
		d.Reason = "cluster '" + cluster + "' is outside this tool's allowed scope"
		return d
	}
	switch strings.ToLower(strings.TrimSpace(scope.ApprovalRule)) {
	case "always":
		d.ForceApproval = true
	case "never":
		d.SkipApproval = true
	}
	return d
}

// csvAllows reports whether value is permitted by a CSV allow-list. Empty list = allow all; a '*'
// entry = allow all; otherwise value must match an entry (case-insensitive). An empty value against
// a non-empty list is denied (a restricted tool needs a known role/target).
func csvAllows(csv, value string) bool {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return true
	}
	value = strings.TrimSpace(value)
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item == "*" {
			return true
		}
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

// extractScopeTargets pulls the namespace and cluster a tool call targets from its arguments, if
// present. Tolerant of the common key spellings used across MCP tools.
func extractScopeTargets(args json.RawMessage) (namespace, cluster string) {
	if len(args) == 0 {
		return "", ""
	}
	var m map[string]any
	if json.Unmarshal(args, &m) != nil {
		return "", ""
	}
	namespace = strings.TrimSpace(strAny(m["namespace"]))
	if namespace == "" {
		namespace = strings.TrimSpace(strAny(m["ns"]))
	}
	cluster = strings.TrimSpace(firstNonEmpty(strAny(m["cluster_id"]), strAny(m["cluster"]), strAny(m["clusterId"])))
	return namespace, cluster
}
