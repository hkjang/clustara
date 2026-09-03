package analyzer

import (
	"sort"
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

// kindsWithTopLevelPayload are the kinds whose policy-relevant fields sit at the
// document root instead of under `spec`: RBAC rules and subjects, ConfigMap and
// Secret data, ServiceAccount token settings. Inventory items already store those
// fields in Spec, so only decoded manifest documents need the distinction.
var kindsWithTopLevelPayload = map[string]bool{
	"configmap": true, "secret": true, "serviceaccount": true,
	"role": true, "clusterrole": true, "rolebinding": true, "clusterrolebinding": true,
}

// PolicySpecOfDoc returns the map policy rules should read for a decoded manifest
// document. Handing rules doc["spec"] for an RBAC object yields an empty map, which
// silently disarms every rule reading those fields — a ClusterRole granting */*/* was
// evaluated as clean on the manifest path while the live-inventory scan flagged it.
func PolicySpecOfDoc(kind string, doc map[string]any) map[string]any {
	if spec := asAnyMap(doc["spec"]); len(spec) > 0 {
		return spec
	}
	if kindsWithTopLevelPayload[strings.ToLower(strings.TrimSpace(kind))] {
		return doc
	}
	return map[string]any{}
}

// EvaluatePolicies checks a resource (by kind + raw spec, e.g. from a manifest) against the
// enabled policies and returns one result per policy. Pure + testable.
//
// annotations are the resource's own metadata annotations. They must be passed in
// rather than read out of spec: in a manifest document metadata is a sibling of
// spec, and on an inventory item annotations are a separate field, so a resource's
// own annotations are not reachable from spec at all. The attestation rules
// (vulnerability counts, expired exceptions) fire only when an annotation is present
// with a bad value, so without this they could never fire on a bare Pod.
func EvaluatePolicies(kind string, spec map[string]any, annotations map[string]string, policies []Policy) []PolicyResult {
	ps := podSpecFromKindSpec(kind, spec)
	merged := policyAnnotations(kind, spec, annotations)
	out := []PolicyResult{}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		violated, detail := evalPolicyRule(p.RuleType, kind, spec, ps, merged)
		out = append(out, PolicyResult{PolicyID: p.ID, Name: p.Name, RuleType: p.RuleType, Action: p.Action, Violated: violated, Detail: detail})
	}
	return out
}

func podSpecFromKindSpec(kind string, spec map[string]any) map[string]any {
	return podSpecOf(store.K8sInventoryItem{Kind: kind, Spec: spec})
}

func evalPolicyRule(ruleType, kind string, spec, ps map[string]any, annotations map[string]string) (bool, string) {
	containers := func() []any {
		if ps == nil {
			return nil
		}
		return securityRelevantContainers(ps)
	}
	// The image supply-chain rules fire on the *absence* of an attestation annotation,
	// so without a scope they fire on every resource that has none — and a Service, a
	// ConfigMap or a ClusterRole never has one. On the deploy path that Denies a whole
	// stack because its Service carries no image signature; on the compliance path every
	// ClusterRole in the cluster contributes three findings about images it does not
	// reference. Scope them to resources that actually pull an image, which is what the
	// rule catalog (and the exported Kyverno/Rego form) already says they cover.
	images := func() []string {
		if ps == nil {
			return nil
		}
		return ExtractImages(ps)
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
		for _, img := range images() {
			if tag, digest := imageTagAndDigest(img); digest == "" && (tag == "" || tag == "latest") {
				return true, "mutable 태그: " + img
			}
		}
	case "require_image_digest":
		for _, img := range images() {
			if !strings.Contains(img, "@sha256:") {
				return true, "digest 미고정 이미지: " + img
			}
		}
	case "disallow_unsigned_image":
		if len(images()) > 0 && annotations["cosign.sigstore.dev/signature"] == "" && annotations["clustara.io/image-signature"] == "" {
			return true, "이미지 서명 attestation 없음"
		}
	case "require_sbom":
		if len(images()) > 0 && annotations["clustara.io/sbom-ref"] == "" && annotations["clustara.io/sbom-digest"] == "" {
			return true, "SBOM 연결 정보 없음"
		}
	case "require_vuln_scan_attestation":
		if len(images()) > 0 && annotations["clustara.io/vuln-scan-id"] == "" && annotations["clustara.io/vuln-scan-attestation"] == "" {
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
		for _, raw := range resourceDeclaringContainers(ps) {
			lim := asAnyMap(asAnyMap(asAnyMap(raw)["resources"])["limits"])
			if len(lim) == 0 {
				return true, str(asAnyMap(raw)["name"]) + ": resources.limits 미설정"
			}
		}
	case "require_run_as_non_root":
		// A container's own securityContext overrides the pod's, so runAsNonRoot=false
		// on one container defeats runAsNonRoot=true on the pod — that container still
		// runs as root. Reading only the pod value reports the workload as compliant.
		podNonRoot := asBool(asAnyMap(ps["securityContext"])["runAsNonRoot"])
		for _, raw := range containers() {
			if set, ok := asAnyMap(asAnyMap(raw)["securityContext"])["runAsNonRoot"].(bool); ok {
				if !set {
					return true, str(asAnyMap(raw)["name"]) + ": runAsNonRoot=false (Pod 설정을 덮어씀)"
				}
				continue
			}
			if !podNonRoot {
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

// policyAnnotations merges every annotation source a rule may legitimately consult:
// the pod template's annotations, any metadata carried inside the map itself (true
// for the kinds PolicySpecOfDoc hands the whole document), and the resource's own
// annotations supplied by the caller. The resource's own values win on conflict.
func policyAnnotations(kind string, spec map[string]any, own map[string]string) map[string]string {
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
	for k, v := range own {
		if s := strings.TrimSpace(v); s != "" {
			out[k] = s
		}
	}
	return out
}

// imageTagAndDigest splits `[registry[:port]/]repo[:tag][@digest]`. A `:` introduces a tag
// only when it follows the last `/`, so a registry port is not mistaken for one.
//
// The substring test this replaces read any `:` as "carries a tag", so
// `registry.corp.local:5000/app` — untagged, and therefore `:latest` as far as the
// kubelet is concerned — passed the mutable-tag guardrail on the strength of its
// registry port. Registries with an explicit port are the norm in the closed networks
// this product targets.
func imageTagAndDigest(ref string) (tag, digest string) {
	rest := ref
	if i := strings.Index(rest, "@"); i >= 0 {
		digest = rest[i+1:]
		rest = rest[:i]
	}
	name := rest
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		name = rest[i+1:]
	}
	if i := strings.LastIndex(name, ":"); i > 0 {
		tag = name[i+1:]
	}
	return tag, digest
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
		if !policyEvaluable(it) {
			continue
		}
		for _, res := range EvaluatePolicies(it.Kind, it.Spec, it.Annotations, policies) {
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

// policyEvaluable reports whether a policy run would look at this resource at
// all. Most of an inventory is not a workload or an RBAC object, so the number
// of items fetched says little about how much was actually examined.
func policyEvaluable(it store.K8sInventoryItem) bool {
	return workloadKinds[it.Kind] || it.Kind == "Role" || it.Kind == "ClusterRole"
}

// CountPolicyEvaluable returns how many of these resources a policy run would
// evaluate. A compliance report needs it: "0 violations" over nothing examined
// is not a pass, and an empty or unreported inventory looks exactly like a clean
// one otherwise.
func CountPolicyEvaluable(items []store.K8sInventoryItem) int {
	n := 0
	for _, it := range items {
		if policyEvaluable(it) {
			n++
		}
	}
	return n
}

// UncoveredPolicyRule is one enabled rule that had no candidate resource to run
// against: the kinds it can fire on were entirely absent from the scanned inventory.
type UncoveredPolicyRule struct {
	RuleType string   `json:"rule_type"`
	Kinds    []string `json:"kinds"`
	Policies int      `json:"policies"`
}

// policyRuleKinds lists the kinds a rule type can ever fire on. Every rule but the
// RBAC one reads a pod spec, so a workload is the only thing it can find anything in.
func policyRuleKinds(ruleType string) []string {
	if ruleType == "disallow_wildcard_rbac" {
		return []string{"ClusterRole", "Role"}
	}
	kinds := make([]string, 0, len(workloadKinds))
	for kind := range workloadKinds {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// UncoveredPolicyRules returns the enabled rules that had nothing to look at, because
// every kind they can fire on was missing from the inventory that was scanned.
//
// This is the gap the resource count cannot show. A cluster whose Deployments were
// collected but whose RBAC objects were not still reports plenty of evaluable
// resources, so the run looks complete — and disallow_wildcard_rbac, the only rule
// that reads Role/ClusterRole, evaluates zero objects and contributes zero findings.
// A ClusterRole granting */*/* is then reported as compliant. The collector reaches
// this state normally, not exceptionally: RBAC lists are Optional, an authorization
// failure on them is skipped silently, and the shipped agent ClusterRole does not
// request rbac.authorization.k8s.io at all.
func UncoveredPolicyRules(items []store.K8sInventoryItem, policies []Policy) []UncoveredPolicyRule {
	present := map[string]bool{}
	for _, it := range items {
		present[it.Kind] = true
	}
	counts := map[string]int{}
	order := []string{}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		covered := false
		for _, kind := range policyRuleKinds(p.RuleType) {
			if present[kind] {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		if counts[p.RuleType] == 0 {
			order = append(order, p.RuleType)
		}
		counts[p.RuleType]++
	}
	sort.Strings(order)
	out := make([]UncoveredPolicyRule, 0, len(order))
	for _, ruleType := range order {
		out = append(out, UncoveredPolicyRule{RuleType: ruleType, Kinds: policyRuleKinds(ruleType), Policies: counts[ruleType]})
	}
	return out
}

// PolicyEvaluableKinds lists the resource kinds a policy run examines, so a
// caller can fetch only those rather than spending a row limit on kinds the
// evaluation ignores.
func PolicyEvaluableKinds() []string {
	kinds := make([]string, 0, len(workloadKinds)+2)
	for kind := range workloadKinds {
		kinds = append(kinds, kind)
	}
	kinds = append(kinds, "Role", "ClusterRole")
	sort.Strings(kinds)
	return kinds
}
