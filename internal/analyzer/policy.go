package analyzer

import (
	"strings"

	"clustara/internal/store"
)

// Policy is a declarative guardrail (a pragmatic alternative to CEL ValidatingAdmissionPolicy).
// Action mirrors Kubernetes admission actions: Deny | Warn | Audit (SEC-05 / SEC-10).
type Policy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	RuleType string `json:"rule_type"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
}

// PolicyResult is the outcome of evaluating one policy against a resource.
type PolicyResult struct {
	PolicyID string `json:"policy_id"`
	Name     string `json:"name"`
	RuleType string `json:"rule_type"`
	Action   string `json:"action"`
	Violated bool   `json:"violated"`
	Detail   string `json:"detail"`
}

// PolicyRuleTypes are the supported guardrail checks.
var PolicyRuleTypes = []string{
	"disallow_privileged", "disallow_host_network", "disallow_host_path",
	"disallow_latest_tag", "require_resource_limits", "require_run_as_non_root",
	"disallow_wildcard_rbac",
}

// EvaluatePolicies checks a resource (by kind + raw spec, e.g. from a manifest) against the
// enabled policies and returns one result per policy. Pure + testable.
func EvaluatePolicies(kind string, spec map[string]any, policies []Policy) []PolicyResult {
	ps := podSpecFromKindSpec(kind, spec)
	out := []PolicyResult{}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		violated, detail := evalPolicyRule(p.RuleType, kind, spec, ps)
		out = append(out, PolicyResult{PolicyID: p.ID, Name: p.Name, RuleType: p.RuleType, Action: p.Action, Violated: violated, Detail: detail})
	}
	return out
}

func podSpecFromKindSpec(kind string, spec map[string]any) map[string]any {
	return podSpecOf(store.K8sInventoryItem{Kind: kind, Spec: spec})
}

func evalPolicyRule(ruleType, kind string, spec, ps map[string]any) (bool, string) {
	containers := func() []any {
		if ps == nil {
			return nil
		}
		return append(asAnySlice(ps["containers"]), asAnySlice(ps["initContainers"])...)
	}
	switch ruleType {
	case "disallow_privileged":
		for _, raw := range containers() {
			if asBool(asAnyMap(asAnyMap(raw)["securityContext"])["privileged"]) {
				return true, str(asAnyMap(raw)["name"]) + ": privileged=true"
			}
		}
	case "disallow_host_network":
		if asBool(ps["hostNetwork"]) {
			return true, "hostNetwork=true"
		}
	case "disallow_host_path":
		for _, raw := range asAnySlice(ps["volumes"]) {
			if _, ok := asAnyMap(raw)["hostPath"]; ok {
				return true, "hostPath volume 사용"
			}
		}
	case "disallow_latest_tag":
		for _, img := range ExtractImages(ps) {
			if strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":") {
				return true, "mutable 태그: " + img
			}
		}
	case "require_resource_limits":
		for _, raw := range containers() {
			lim := asAnyMap(asAnyMap(asAnyMap(raw)["resources"])["limits"])
			if len(lim) == 0 {
				return true, str(asAnyMap(raw)["name"]) + ": resources.limits 미설정"
			}
		}
	case "require_run_as_non_root":
		podNonRoot := asBool(asAnyMap(ps["securityContext"])["runAsNonRoot"])
		for _, raw := range containers() {
			if !podNonRoot && !asBool(asAnyMap(asAnyMap(raw)["securityContext"])["runAsNonRoot"]) {
				return true, str(asAnyMap(raw)["name"]) + ": runAsNonRoot 미설정"
			}
		}
	case "disallow_wildcard_rbac":
		if kind == "Role" || kind == "ClusterRole" {
			for _, raw := range asAnySlice(spec["rules"]) {
				rule := asAnyMap(raw)
				if hasWildcard(rule["verbs"]) || hasWildcard(rule["resources"]) || hasWildcard(rule["apiGroups"]) {
					return true, "wildcard(*) 권한"
				}
			}
		}
	}
	return false, ""
}

func hasWildcard(v any) bool {
	for _, s := range stringSlice(v) {
		if s == "*" {
			return true
		}
	}
	return false
}

// PolicyComplianceViolation is one resource that violates a policy across the inventory (SEC-10).
type PolicyComplianceViolation struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	PolicyID  string `json:"policy_id"`
	RuleType  string `json:"rule_type"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
}

// CheckPolicyCompliance runs the enabled policies across the whole inventory (SEC-10 정책 팩).
func CheckPolicyCompliance(items []store.K8sInventoryItem, policies []Policy) []PolicyComplianceViolation {
	out := []PolicyComplianceViolation{}
	for _, it := range items {
		if !workloadKinds[it.Kind] && it.Kind != "Role" && it.Kind != "ClusterRole" {
			continue
		}
		for _, res := range EvaluatePolicies(it.Kind, it.Spec, policies) {
			if res.Violated {
				out = append(out, PolicyComplianceViolation{
					Namespace: it.Namespace, Kind: it.Kind, Name: it.Name,
					PolicyID: res.PolicyID, RuleType: res.RuleType, Action: res.Action, Detail: res.Detail,
				})
			}
		}
	}
	return out
}
