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
	"disallow_unsigned_image", "require_image_digest", "require_sbom",
	"require_vuln_scan_attestation", "deny_critical_vulnerability", "warn_high_vulnerability",
	"deny_unfixed_exception_expired", "deny_privileged_runtime", "enforce_pss_restricted",
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
	annotations := policyAnnotations(kind, spec)
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
	case "require_image_digest":
		for _, img := range ExtractImages(ps) {
			if !strings.Contains(img, "@sha256:") {
				return true, "digest 미고정 이미지: " + img
			}
		}
	case "disallow_unsigned_image":
		if annotations["cosign.sigstore.dev/signature"] == "" && annotations["clustara.io/image-signature"] == "" {
			return true, "이미지 서명 attestation 없음"
		}
	case "require_sbom":
		if annotations["clustara.io/sbom-ref"] == "" && annotations["clustara.io/sbom-digest"] == "" {
			return true, "SBOM 연결 정보 없음"
		}
	case "require_vuln_scan_attestation":
		if annotations["clustara.io/vuln-scan-id"] == "" && annotations["clustara.io/vuln-scan-attestation"] == "" {
			return true, "취약점 스캔 attestation 없음"
		}
	case "deny_critical_vulnerability":
		if n := strings.TrimSpace(annotations["clustara.io/critical-vulnerabilities"]); n != "" && n != "0" {
			return true, "Critical 취약점 attestation: " + n
		}
	case "warn_high_vulnerability":
		if n := strings.TrimSpace(annotations["clustara.io/high-vulnerabilities"]); n != "" && n != "0" {
			return true, "High 취약점 attestation: " + n
		}
	case "deny_unfixed_exception_expired":
		if strings.EqualFold(annotations["clustara.io/exception-expired"], "true") {
			return true, "만료된 보안 예외"
		}
	case "deny_privileged_runtime", "enforce_pss_restricted":
		if asBool(ps["hostNetwork"]) || asBool(ps["hostPID"]) || asBool(ps["hostIPC"]) {
			return true, "host namespace 사용"
		}
		for _, raw := range asAnySlice(ps["volumes"]) {
			if _, ok := asAnyMap(raw)["hostPath"]; ok {
				return true, "hostPath volume 사용"
			}
		}
		for _, raw := range containers() {
			sc := asAnyMap(asAnyMap(raw)["securityContext"])
			if asBool(sc["privileged"]) || asBool(sc["allowPrivilegeEscalation"]) {
				return true, str(asAnyMap(raw)["name"]) + ": privileged/privesc"
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

func policyAnnotations(kind string, spec map[string]any) map[string]string {
	out := map[string]string{}
	add := func(raw any) {
		for k, v := range asAnyMap(raw) {
			if s := strings.TrimSpace(str(v)); s != "" {
				out[k] = s
			}
		}
	}
	add(asAnyMap(asAnyMap(spec["metadata"])["annotations"]))
	tmpl := asAnyMap(spec["template"])
	add(asAnyMap(asAnyMap(tmpl["metadata"])["annotations"]))
	if strings.EqualFold(kind, "Pod") {
		add(asAnyMap(spec["annotations"]))
	}
	return out
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
