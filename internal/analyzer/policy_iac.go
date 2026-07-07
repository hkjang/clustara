package analyzer

import (
	"fmt"
	"sort"
	"strings"
)

// Policy as Code: export Clustara guardrails to Kyverno / OPA-Rego and import (best-effort) policy
// definitions back into Clustara rule types. This is self-contained — no OPA/Kyverno runtime is
// required; exports are representative manifests and imports map known signatures to rule types.

// PolicyRuleMeta describes how one Clustara rule type maps to external policy languages.
type PolicyRuleMeta struct {
	RuleType string
	Title    string
	// kyvernoValidate is the `validate` body (message + pattern/deny) for a Kyverno rule.
	kyvernoValidate string
	// regoBody is the body of an OPA deny rule (without the `deny[msg] {` wrapper).
	regoBody string
	// keywords are lowercased signatures used to recognize foreign policies on import.
	keywords []string
}

// policyRuleCatalog maps each supported rule type to its IaC representation. Keys match
// analyzer.PolicyRuleTypes.
var policyRuleCatalog = map[string]PolicyRuleMeta{
	"disallow_privileged": {
		RuleType: "disallow_privileged", Title: "특권 컨테이너 금지",
		kyvernoValidate: "      message: \"privileged 컨테이너는 금지됩니다\"\n      pattern:\n        spec:\n          containers:\n          - =(securityContext):\n              =(privileged): \"false\"",
		regoBody:        "  some c\n  input.spec.containers[c].securityContext.privileged == true\n  msg := sprintf(\"container %v is privileged\", [input.spec.containers[c].name])",
		keywords:        []string{"privileged"},
	},
	"disallow_host_network": {
		RuleType: "disallow_host_network", Title: "hostNetwork 금지",
		kyvernoValidate: "      message: \"hostNetwork 사용은 금지됩니다\"\n      pattern:\n        spec:\n          =(hostNetwork): \"false\"",
		regoBody:        "  input.spec.hostNetwork == true\n  msg := \"hostNetwork is not allowed\"",
		keywords:        []string{"hostnetwork"},
	},
	"disallow_host_path": {
		RuleType: "disallow_host_path", Title: "hostPath 볼륨 금지",
		kyvernoValidate: "      message: \"hostPath 볼륨은 금지됩니다\"\n      pattern:\n        spec:\n          =(volumes):\n          - X(hostPath): \"null\"",
		regoBody:        "  some v\n  input.spec.volumes[v].hostPath\n  msg := sprintf(\"volume %v uses hostPath\", [input.spec.volumes[v].name])",
		keywords:        []string{"hostpath"},
	},
	"disallow_latest_tag": {
		RuleType: "disallow_latest_tag", Title: ":latest 태그 금지",
		kyvernoValidate: "      message: \"이미지 :latest 태그는 금지됩니다\"\n      pattern:\n        spec:\n          containers:\n          - image: \"!*:latest\"",
		regoBody:        "  some c\n  endswith(input.spec.containers[c].image, \":latest\")\n  msg := sprintf(\"container %v uses :latest\", [input.spec.containers[c].name])",
		keywords:        []string{":latest", "latest tag", "disallow-latest", "require-image-tag"},
	},
	"require_resource_limits": {
		RuleType: "require_resource_limits", Title: "리소스 limits 필수",
		kyvernoValidate: "      message: \"CPU/메모리 limits를 설정해야 합니다\"\n      pattern:\n        spec:\n          containers:\n          - resources:\n              limits:\n                memory: \"?*\"\n                cpu: \"?*\"",
		regoBody:        "  some c\n  not input.spec.containers[c].resources.limits\n  msg := sprintf(\"container %v has no resource limits\", [input.spec.containers[c].name])",
		keywords:        []string{"require-limits", "resource limits", "resources.limits", "require-requests-limits"},
	},
	"require_run_as_non_root": {
		RuleType: "require_run_as_non_root", Title: "runAsNonRoot 필수",
		kyvernoValidate: "      message: \"runAsNonRoot=true 가 필요합니다\"\n      pattern:\n        spec:\n          =(securityContext):\n            =(runAsNonRoot): \"true\"\n          containers:\n          - =(securityContext):\n              =(runAsNonRoot): \"true\"",
		regoBody:        "  not input.spec.securityContext.runAsNonRoot == true\n  msg := \"runAsNonRoot must be true\"",
		keywords:        []string{"runasnonroot", "run-as-non-root"},
	},
	"disallow_wildcard_rbac": {
		RuleType: "disallow_wildcard_rbac", Title: "RBAC 와일드카드 금지",
		kyvernoValidate: "      message: \"RBAC 규칙에 와일드카드(*)는 금지됩니다\"\n      deny:\n        conditions:\n          any:\n          - key: \"{{ contains(request.object.rules[].verbs[], '*') }}\"\n            operator: Equals\n            value: true",
		regoBody:        "  some r\n  input.rules[r].verbs[_] == \"*\"\n  msg := \"wildcard verb in RBAC rule\"",
		keywords:        []string{"wildcard", "rbac wildcard", "disallow-wildcard"},
	},
	"require_image_digest": {
		RuleType: "require_image_digest", Title: "이미지 digest 고정 필수",
		kyvernoValidate: "      message: \"이미지는 tag가 아니라 digest(@sha256)로 고정해야 합니다\"\n      deny:\n        conditions:\n          any:\n          - key: \"{{ images.containers.*.referenceWithTag || '' }}\"\n            operator: NotEquals\n            value: \"\"",
		regoBody:        "  some c\n  not contains(input.spec.containers[c].image, \"@sha256:\")\n  msg := sprintf(\"container %v image is not digest pinned\", [input.spec.containers[c].name])",
		keywords:        []string{"require-image-digest", "digest pinned", "@sha256", "image digest"},
	},
	"disallow_unsigned_image": {
		RuleType: "disallow_unsigned_image", Title: "서명 없는 이미지 금지",
		kyvernoValidate: "      message: \"서명 attestation 없는 이미지는 금지됩니다\"\n      deny:\n        conditions:\n          any:\n          - key: \"{{ request.object.metadata.annotations.\\\"clustara.io/image-signature\\\" || '' }}\"\n            operator: Equals\n            value: \"\"",
		regoBody:        "  not input.metadata.annotations[\"clustara.io/image-signature\"]\n  msg := \"missing image signature attestation\"",
		keywords:        []string{"cosign", "sigstore", "image-signature", "unsigned image"},
	},
	"require_sbom": {
		RuleType: "require_sbom", Title: "SBOM 필수",
		kyvernoValidate: "      message: \"이미지 SBOM 참조가 필요합니다\"\n      pattern:\n        metadata:\n          annotations:\n            clustara.io/sbom-ref: \"?*\"",
		regoBody:        "  not input.metadata.annotations[\"clustara.io/sbom-ref\"]\n  msg := \"missing SBOM reference\"",
		keywords:        []string{"sbom", "cyclonedx", "spdx", "require-sbom"},
	},
	"require_vuln_scan_attestation": {
		RuleType: "require_vuln_scan_attestation", Title: "취약점 스캔 attestation 필수",
		kyvernoValidate: "      message: \"취약점 스캔 attestation이 필요합니다\"\n      pattern:\n        metadata:\n          annotations:\n            clustara.io/vuln-scan-id: \"?*\"",
		regoBody:        "  not input.metadata.annotations[\"clustara.io/vuln-scan-id\"]\n  msg := \"missing vulnerability scan attestation\"",
		keywords:        []string{"vuln-scan", "vulnerability scan", "attestation"},
	},
	"deny_critical_vulnerability": {
		RuleType: "deny_critical_vulnerability", Title: "Critical CVE 이미지 차단",
		kyvernoValidate: "      message: \"예외 없는 Critical 취약 이미지 배포는 차단됩니다\"\n      deny:\n        conditions:\n          any:\n          - key: \"{{ request.object.metadata.annotations.\\\"clustara.io/critical-vulnerabilities\\\" || '0' }}\"\n            operator: NotEquals\n            value: \"0\"",
		regoBody:        "  input.metadata.annotations[\"clustara.io/critical-vulnerabilities\"] != \"0\"\n  msg := \"critical vulnerabilities found\"",
		keywords:        []string{"critical vulnerability", "critical cve", "deny-critical"},
	},
	"warn_high_vulnerability": {
		RuleType: "warn_high_vulnerability", Title: "High CVE 승인 필요",
		kyvernoValidate: "      message: \"High 취약점 이미지는 승인 또는 SLA 관리가 필요합니다\"\n      deny:\n        conditions:\n          any:\n          - key: \"{{ request.object.metadata.annotations.\\\"clustara.io/high-vulnerabilities\\\" || '0' }}\"\n            operator: NotEquals\n            value: \"0\"",
		regoBody:        "  input.metadata.annotations[\"clustara.io/high-vulnerabilities\"] != \"0\"\n  msg := \"high vulnerabilities require approval\"",
		keywords:        []string{"high vulnerability", "high cve", "warn-high"},
	},
	"deny_unfixed_exception_expired": {
		RuleType: "deny_unfixed_exception_expired", Title: "만료 예외 차단",
		kyvernoValidate: "      message: \"만료된 취약점 예외는 사용할 수 없습니다\"\n      deny:\n        conditions:\n          any:\n          - key: \"{{ request.object.metadata.annotations.\\\"clustara.io/exception-expired\\\" || 'false' }}\"\n            operator: Equals\n            value: \"true\"",
		regoBody:        "  input.metadata.annotations[\"clustara.io/exception-expired\"] == \"true\"\n  msg := \"security exception has expired\"",
		keywords:        []string{"exception expired", "expired exception", "deny-unfixed-exception"},
	},
	"deny_privileged_runtime": {
		RuleType: "deny_privileged_runtime", Title: "런타임 권한 위험 차단",
		kyvernoValidate: "      message: \"privileged, hostPath, host namespace 사용은 금지됩니다\"\n      pattern:\n        spec:\n          =(hostNetwork): \"false\"\n          =(hostPID): \"false\"\n          =(volumes):\n          - X(hostPath): \"null\"\n          containers:\n          - =(securityContext):\n              =(privileged): \"false\"",
		regoBody:        "  input.spec.hostNetwork == true\n  msg := \"privileged runtime setting is not allowed\"",
		keywords:        []string{"privileged runtime", "hostnamespace", "deny-privileged-runtime"},
	},
	"enforce_pss_restricted": {
		RuleType: "enforce_pss_restricted", Title: "Pod Security Restricted 강제",
		kyvernoValidate: "      message: \"Restricted Pod Security 기준을 만족해야 합니다\"\n      pattern:\n        spec:\n          =(hostNetwork): \"false\"\n          =(hostPID): \"false\"\n          =(hostIPC): \"false\"\n          =(volumes):\n          - X(hostPath): \"null\"",
		regoBody:        "  input.spec.hostPID == true\n  msg := \"PSS restricted violation\"",
		keywords:        []string{"pod security restricted", "pss restricted", "enforce-pss"},
	},
}

const policyAnnotationKey = "clustara.io/rule-type"

func kyvernoFailureAction(action string) string {
	if strings.EqualFold(action, "Deny") {
		return "Enforce"
	}
	return "Audit"
}

func kyvernoRuleName(rt string) string { return strings.ReplaceAll(rt, "_", "-") }

// ExportKyverno renders the given policies as a single Kyverno ClusterPolicy manifest. Disabled
// policies and unknown rule types are skipped. Returns "" if nothing to export.
func ExportKyverno(policies []Policy) string {
	rules := []string{}
	enforce := false
	for _, p := range sortedPolicies(policies) {
		meta, ok := policyRuleCatalog[p.RuleType]
		if !ok || !p.Enabled {
			continue
		}
		if strings.EqualFold(p.Action, "Deny") {
			enforce = true
		}
		matchKind := "Pod"
		if p.RuleType == "disallow_wildcard_rbac" {
			matchKind = "ClusterRole"
		}
		rule := fmt.Sprintf("  - name: %s\n    match:\n      any:\n      - resources:\n          kinds:\n          - %s\n    validate:\n%s",
			kyvernoRuleName(p.RuleType), matchKind, meta.kyvernoValidate)
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return ""
	}
	action := "Audit"
	if enforce {
		action = "Enforce"
	}
	var b strings.Builder
	b.WriteString("apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: clustara-guardrails\n  annotations:\n    clustara.io/generated: \"true\"\nspec:\n")
	fmt.Fprintf(&b, "  validationFailureAction: %s\n  background: true\n  rules:\n", action)
	b.WriteString(strings.Join(rules, "\n"))
	b.WriteString("\n")
	return b.String()
}

// ExportRego renders the given policies as an OPA/Gatekeeper-style Rego module. Each enabled
// policy becomes a `deny` rule annotated with its Clustara rule type for lossless re-import.
func ExportRego(policies []Policy) string {
	rules := []string{}
	for _, p := range sortedPolicies(policies) {
		meta, ok := policyRuleCatalog[p.RuleType]
		if !ok || !p.Enabled {
			continue
		}
		rule := fmt.Sprintf("# %s: %s (action=%s)\n# %s: %s\ndeny[msg] {\n%s\n}",
			meta.RuleType, meta.Title, p.Action, policyAnnotationKey, p.RuleType, meta.regoBody)
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return ""
	}
	return "package clustara.guardrails\n\n" + strings.Join(rules, "\n\n") + "\n"
}

// ImportedPolicy is a policy recognized from external IaC text.
type ImportedPolicy struct {
	RuleType string `json:"rule_type"`
	Title    string `json:"title"`
	Match    string `json:"match"` // "annotation" (exact) | "heuristic"
}

// ImportPolicyText recognizes Clustara rule types from a Kyverno/Rego/text policy document.
// It first honors explicit `clustara.io/rule-type: <rt>` annotations (lossless round-trip), then
// falls back to keyword heuristics. Returns recognized policies (deduped) and warnings.
func ImportPolicyText(text string) ([]ImportedPolicy, []string) {
	lower := strings.ToLower(text)
	seen := map[string]bool{}
	out := []ImportedPolicy{}
	warnings := []string{}

	// 1) Exact: explicit annotations.
	for _, rt := range PolicyRuleTypes {
		if strings.Contains(lower, strings.ToLower(policyAnnotationKey+": "+rt)) ||
			strings.Contains(lower, strings.ToLower(policyAnnotationKey+":"+rt)) {
			if !seen[rt] {
				seen[rt] = true
				out = append(out, ImportedPolicy{RuleType: rt, Title: policyRuleCatalog[rt].Title, Match: "annotation"})
			}
		}
	}

	// 2) Heuristic: keyword signatures for anything not already matched.
	for _, rt := range PolicyRuleTypes {
		if seen[rt] {
			continue
		}
		meta := policyRuleCatalog[rt]
		for _, kw := range meta.keywords {
			if strings.Contains(lower, kw) {
				seen[rt] = true
				out = append(out, ImportedPolicy{RuleType: rt, Title: meta.Title, Match: "heuristic"})
				warnings = append(warnings, fmt.Sprintf("'%s' 규칙을 키워드(%q) 기반으로 추정 매핑했습니다 — 확인 후 활성화하세요.", rt, kw))
				break
			}
		}
	}

	if len(out) == 0 {
		warnings = append(warnings, "인식 가능한 정책 규칙을 찾지 못했습니다. 지원: "+strings.Join(PolicyRuleTypes, ", "))
	}
	return out, warnings
}

func sortedPolicies(policies []Policy) []Policy {
	out := append([]Policy(nil), policies...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleType < out[j].RuleType })
	return out
}
