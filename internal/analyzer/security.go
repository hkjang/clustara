package analyzer

import (
	"fmt"
	"strings"
	"time"

	"clustara/internal/store"
)

// DetectActionAnomalies flags requesters who issued many high/critical-risk K8s actions within a
// short window — a sign of a runaway script or compromised credential (SEC-09 감사 이상 탐지).
func DetectActionAnomalies(actions []store.K8sActionRequest, now time.Time, window time.Duration, threshold int) []SecFinding {
	if threshold < 1 {
		threshold = 5
	}
	byUser := map[string]int{}
	for _, a := range actions {
		if a.RiskLevel != "high" && a.RiskLevel != "critical" {
			continue
		}
		when, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
		if err != nil || now.Sub(when) > window {
			continue
		}
		byUser[firstNonEmptyStr(a.RequestedBy, "(unknown)")]++
	}
	out := []SecFinding{}
	for user, n := range byUser {
		if n >= threshold {
			out = append(out, SecFinding{
				ResourceKind: "User", ResourceName: user, Rule: "audit-action-burst", Severity: "high",
				Message:  fmt.Sprintf("%s가 최근 %s 동안 위험 액션을 %d회 요청했습니다.", user, window.String(), n),
				Evidence: []string{fmt.Sprintf("위험 액션 요청 %d회 (임계 %d)", n, threshold)},
			})
		}
	}
	return out
}

// SecFinding is one security/policy issue (SEC-02/03/04/06).
type SecFinding struct {
	Namespace    string   `json:"namespace"`
	ResourceKind string   `json:"resource_kind"`
	ResourceName string   `json:"resource_name"`
	Rule         string   `json:"rule"`
	Severity     string   `json:"severity"`
	Message      string   `json:"message"`
	Evidence     []string `json:"evidence"`
}

// PodSecurityResult is the Pod Security Standards classification of one workload (SEC-01).
type PodSecurityResult struct {
	Namespace  string   `json:"namespace"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Level      string   `json:"level"` // restricted | baseline | privileged
	Violations []string `json:"violations"`
}

// SecurityReport is the aggregate posture returned by AnalyzeSecurity.
type SecurityReport struct {
	PodSecurity []PodSecurityResult `json:"pod_security"`
	RBAC        []SecFinding        `json:"rbac"`
	Images      []SecFinding        `json:"images"`
	Secrets     []SecFinding        `json:"secrets"`
	Network     []SecFinding        `json:"network"`
	Summary     SecuritySummary     `json:"summary"`
}

type SecuritySummary struct {
	Workloads    int `json:"workloads"`
	Privileged   int `json:"privileged"`
	Baseline     int `json:"baseline"`
	Restricted   int `json:"restricted"`
	RBACFindings int `json:"rbac_findings"`
	ImageIssues  int `json:"image_issues"`
	NetGaps      int `json:"network_gaps"`
	Score        int `json:"score"` // 0-100 cluster posture
}

var workloadKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Pod": true, "Job": true, "CronJob": true}

// AnalyzeSecurity computes the full security posture from a stored inventory snapshot.
func AnalyzeSecurity(items []store.K8sInventoryItem) SecurityReport {
	rep := SecurityReport{PodSecurity: []PodSecurityResult{}, RBAC: []SecFinding{}, Images: []SecFinding{}, Secrets: []SecFinding{}, Network: []SecFinding{}}

	nsWithWorkload := map[string]bool{}
	nsWithNetPol := map[string]bool{}
	for _, it := range items {
		if it.Kind == "NetworkPolicy" {
			nsWithNetPol[it.Namespace] = true
		}
	}

	for _, it := range items {
		switch {
		case workloadKinds[it.Kind]:
			ps := podSpecOf(it)
			if ps == nil {
				continue
			}
			if it.Namespace != "" {
				nsWithWorkload[it.Namespace] = true
			}
			res := classifyPodSecurity(it, ps)
			rep.PodSecurity = append(rep.PodSecurity, res)
			rep.Images = append(rep.Images, imageFindings(it, ps)...)
			rep.Secrets = append(rep.Secrets, secretRefFindings(it, ps)...)
		case it.Kind == "Role" || it.Kind == "ClusterRole":
			rep.RBAC = append(rep.RBAC, rbacFindings(it)...)
		}
	}

	// SEC-06: namespaces running workloads but with no NetworkPolicy (no default deny).
	for ns := range nsWithWorkload {
		if !nsWithNetPol[ns] {
			rep.Network = append(rep.Network, SecFinding{
				Namespace: ns, ResourceKind: "Namespace", ResourceName: ns,
				Rule: "no-network-policy", Severity: "medium",
				Message:  "워크로드가 있지만 NetworkPolicy가 없어 기본 deny가 적용되지 않습니다.",
				Evidence: []string{"namespace에 NetworkPolicy 리소스 없음"},
			})
		}
	}

	rep.Summary = summarize(rep)
	return rep
}

func summarize(rep SecurityReport) SecuritySummary {
	s := SecuritySummary{Workloads: len(rep.PodSecurity), RBACFindings: len(rep.RBAC), ImageIssues: len(rep.Images), NetGaps: len(rep.Network)}
	for _, p := range rep.PodSecurity {
		switch p.Level {
		case "privileged":
			s.Privileged++
		case "baseline":
			s.Baseline++
		case "restricted":
			s.Restricted++
		}
	}
	// Posture score: start at 100, subtract for privileged workloads, RBAC criticals, net gaps.
	score := 100
	score -= s.Privileged * 8
	score -= s.Baseline * 2
	for _, f := range rep.RBAC {
		if f.Severity == "critical" {
			score -= 6
		} else if f.Severity == "high" {
			score -= 3
		}
	}
	score -= s.NetGaps * 2
	score -= s.ImageIssues
	if score < 0 {
		score = 0
	}
	s.Score = score
	return s
}

// podSpecOf returns the pod spec for a workload (handles Deployment/StatefulSet/DaemonSet/Job
// via .template.spec, CronJob via .jobTemplate..., and a bare Pod via .spec).
func podSpecOf(it store.K8sInventoryItem) map[string]any {
	spec := it.Spec
	if it.Kind == "Pod" {
		return spec
	}
	if it.Kind == "CronJob" {
		jt := asAnyMap(spec["jobTemplate"])
		spec = asAnyMap(jt["spec"])
	}
	tmpl := asAnyMap(spec["template"])
	return asAnyMap(tmpl["spec"])
}

func classifyPodSecurity(it store.K8sInventoryItem, ps map[string]any) PodSecurityResult {
	res := PodSecurityResult{Namespace: it.Namespace, Kind: it.Kind, Name: it.Name}
	priv := []string{}    // privileged-level violations (worst)
	baseline := []string{} // baseline-level violations
	restricted := []string{} // restricted-level violations

	if asBool(ps["hostNetwork"]) {
		priv = append(priv, "hostNetwork=true")
	}
	if asBool(ps["hostPID"]) {
		priv = append(priv, "hostPID=true")
	}
	if asBool(ps["hostIPC"]) {
		priv = append(priv, "hostIPC=true")
	}
	for _, raw := range asAnySlice(ps["volumes"]) {
		v := asAnyMap(raw)
		if _, ok := v["hostPath"]; ok {
			baseline = append(baseline, "hostPath volume")
			break
		}
	}

	containers := []any{}
	containers = append(containers, asAnySlice(ps["containers"])...)
	containers = append(containers, asAnySlice(ps["initContainers"])...)
	podSC := asAnyMap(ps["securityContext"])
	podRunAsNonRoot := asBool(podSC["runAsNonRoot"])

	for _, raw := range containers {
		c := asAnyMap(raw)
		sc := asAnyMap(c["securityContext"])
		cname := str(c["name"])
		if asBool(sc["privileged"]) {
			priv = append(priv, cname+": privileged=true")
		}
		if numVal(sc["runAsUser"]) == 0 && hasKey(sc, "runAsUser") {
			baseline = append(baseline, cname+": runAsUser=0")
		}
		// restricted-level expectations
		if !asBool(sc["runAsNonRoot"]) && !podRunAsNonRoot {
			restricted = append(restricted, cname+": runAsNonRoot 미설정")
		}
		if !hasKey(sc, "allowPrivilegeEscalation") || asBool(sc["allowPrivilegeEscalation"]) {
			restricted = append(restricted, cname+": allowPrivilegeEscalation!=false")
		}
		caps := asAnyMap(sc["capabilities"])
		if !dropsAll(caps) {
			restricted = append(restricted, cname+": capabilities drop ALL 아님")
		}
		for _, ad := range stringSlice(asAnyMap(sc["capabilities"])["add"]) {
			if up := strings.ToUpper(ad); up != "NET_BIND_SERVICE" {
				baseline = append(baseline, cname+": 추가 capability "+up)
			}
		}
		// hostPort
		for _, p := range asAnySlice(c["ports"]) {
			if numVal(asAnyMap(p)["hostPort"]) > 0 {
				baseline = append(baseline, cname+": hostPort 사용")
			}
		}
	}

	res.Violations = append(append(append([]string{}, priv...), baseline...), restricted...)
	switch {
	case len(priv) > 0:
		res.Level = "privileged"
	case len(baseline) > 0:
		res.Level = "baseline"
	default:
		res.Level = "restricted"
	}
	return res
}

func imageFindings(it store.K8sInventoryItem, ps map[string]any) []SecFinding {
	out := []SecFinding{}
	for _, img := range ExtractImages(ps) {
		bad := []string{}
		if strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":") {
			bad = append(bad, "mutable/누락 태그(:latest 또는 태그 없음)")
		}
		if !strings.Contains(img, "@sha256:") && (strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":")) {
			bad = append(bad, "digest 고정 안 됨")
		}
		if len(bad) > 0 {
			out = append(out, SecFinding{
				Namespace: it.Namespace, ResourceKind: it.Kind, ResourceName: it.Name,
				Rule: "image-tag-policy", Severity: "medium",
				Message:  "이미지 태그 정책 위반: " + img,
				Evidence: bad,
			})
		}
	}
	return out
}

func secretRefFindings(it store.K8sInventoryItem, ps map[string]any) []SecFinding {
	secrets := map[string]bool{}
	for _, raw := range asAnySlice(ps["volumes"]) {
		v := asAnyMap(raw)
		if s := asAnyMap(v["secret"]); s != nil {
			if n := str(s["secretName"]); n != "" {
				secrets[n] = true
			}
		}
	}
	containers := append(asAnySlice(ps["containers"]), asAnySlice(ps["initContainers"])...)
	for _, raw := range containers {
		c := asAnyMap(raw)
		for _, ef := range asAnySlice(c["envFrom"]) {
			if sr := asAnyMap(asAnyMap(ef)["secretRef"]); sr != nil {
				if n := str(sr["name"]); n != "" {
					secrets[n] = true
				}
			}
		}
		for _, e := range asAnySlice(c["env"]) {
			vf := asAnyMap(asAnyMap(e)["valueFrom"])
			if skr := asAnyMap(vf["secretKeyRef"]); skr != nil {
				if n := str(skr["name"]); n != "" {
					secrets[n] = true
				}
			}
		}
	}
	if len(secrets) == 0 {
		return nil
	}
	names := []string{}
	for n := range secrets {
		names = append(names, n)
	}
	return []SecFinding{{
		Namespace: it.Namespace, ResourceKind: it.Kind, ResourceName: it.Name,
		Rule: "secret-access", Severity: "low",
		Message:  "워크로드가 Secret을 참조합니다.",
		Evidence: names,
	}}
}

func rbacFindings(it store.K8sInventoryItem) []SecFinding {
	out := []SecFinding{}
	for _, raw := range asAnySlice(it.Spec["rules"]) {
		rule := asAnyMap(raw)
		verbs := lowerSet(stringSlice(rule["verbs"]))
		resources := lowerSet(stringSlice(rule["resources"]))
		apiGroups := lowerSet(stringSlice(rule["apiGroups"]))

		if verbs["*"] && resources["*"] {
			out = append(out, secf(it, "rbac-cluster-admin", "critical", "모든 verb/resource를 허용합니다(cluster-admin 수준).", []string{"verbs=* resources=*"}))
			continue
		}
		if verbs["*"] || resources["*"] || apiGroups["*"] {
			out = append(out, secf(it, "rbac-wildcard", "high", "wildcard(*) 권한이 포함되어 있습니다.", []string{"verbs/resources/apiGroups에 * 포함"}))
		}
		if resources["secrets"] && (verbs["list"] || verbs["watch"] || verbs["get"] || verbs["*"]) {
			out = append(out, secf(it, "rbac-secret-access", "high", "Secret에 대한 get/list/watch 권한이 있습니다.", []string{"resources=secrets verbs=get/list/watch"}))
		}
		for _, danger := range []string{"escalate", "bind", "impersonate"} {
			if verbs[danger] {
				out = append(out, secf(it, "rbac-privilege-escalation", "high", "권한 상승 verb("+danger+")가 부여되어 있습니다.", []string{"verbs include " + danger}))
			}
		}
	}
	return out
}

// rbacPermissionSet flattens a Role/ClusterRole's rules into a set of "apiGroup|resource|verb"
// triples for set-difference comparison.
func rbacPermissionSet(spec map[string]any) map[string]bool {
	set := map[string]bool{}
	for _, raw := range asAnySlice(spec["rules"]) {
		rule := asAnyMap(raw)
		groups := stringSlice(rule["apiGroups"])
		if len(groups) == 0 {
			groups = []string{""}
		}
		resources := stringSlice(rule["resources"])
		verbs := stringSlice(rule["verbs"])
		for _, g := range groups {
			for _, r := range resources {
				for _, v := range verbs {
					set[g+"|"+r+"|"+v] = true
				}
			}
		}
	}
	return set
}

// RBACDiffExpansions returns the permission triples present in `to` but not in `from` — i.e.
// the permissions a Role/ClusterRole change ADDED (SEC-08 RBAC Diff). Sorted; risky ones
// (wildcard, secrets) are surfaced first by the handler.
func RBACDiffExpansions(from, to store.K8sResourceRevision) []string {
	fromSet := rbacPermissionSet(from.Spec)
	added := []string{}
	for k := range rbacPermissionSet(to.Spec) {
		if !fromSet[k] {
			added = append(added, k)
		}
	}
	sortStrings(added)
	return added
}

// IsRiskyPermission reports whether an "apiGroup|resource|verb" triple is high-risk (wildcards,
// secret access, privilege escalation verbs).
func IsRiskyPermission(triple string) bool {
	parts := strings.Split(triple, "|")
	if len(parts) != 3 {
		return false
	}
	_, resource, verb := parts[0], parts[1], parts[2]
	if resource == "*" || verb == "*" {
		return true
	}
	if resource == "secrets" && (verb == "get" || verb == "list" || verb == "watch") {
		return true
	}
	switch verb {
	case "escalate", "bind", "impersonate":
		return true
	}
	return false
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}

func secf(it store.K8sInventoryItem, rule, severity, msg string, evidence []string) SecFinding {
	return SecFinding{Namespace: it.Namespace, ResourceKind: it.Kind, ResourceName: it.Name, Rule: rule, Severity: severity, Message: msg, Evidence: evidence}
}

// --- helpers ---

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func hasKey(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	_, ok := m[k]
	return ok
}

func dropsAll(caps map[string]any) bool {
	for _, d := range stringSlice(caps["drop"]) {
		if strings.EqualFold(d, "ALL") {
			return true
		}
	}
	return false
}

func lowerSet(ss []string) map[string]bool {
	out := map[string]bool{}
	for _, s := range ss {
		out[strings.ToLower(s)] = true
	}
	return out
}
