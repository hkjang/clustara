package analyzer

import "sort"

// Operational RBAC model: a capability catalog + role→capability matrix for Clustara's K8s ops
// (SEC-REQ-03/04/05). This is the reference/preflight layer — it answers "이 역할이 이 작업을 할 수
// 있는가" without (yet) changing auth enforcement, so teams can design role separation safely.
// Pure over its static catalog.

// K8sCapability is one operational permission.
type K8sCapability struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Risk  string `json:"risk"` // read | write | approve | admin
}

// k8sCapabilities is the catalog of operational capabilities.
var k8sCapabilities = []K8sCapability{
	{"pod:view", "Pod·워크로드 조회", "read"},
	{"logs:view", "로그 조회", "read"},
	{"env:view", "환경변수 출처 조회", "read"},
	{"stack:view", "Stack 조회", "read"},
	{"audit:view", "감사·증적 조회", "read"},
	{"secret:view-meta", "Secret 메타(키명) 조회", "read"},
	{"terminal:request", "터미널 세션 요청", "write"},
	{"debug:request", "Debug 컨테이너 요청", "write"},
	{"action:request", "조치(scale/restart/delete) 요청", "write"},
	{"stack:deploy", "Stack 배포/적용", "write"},
	{"terminal:fulltty", "Full TTY 인터랙티브 셸", "write"},
	{"terminal:approve", "터미널 세션 승인", "approve"},
	{"debug:approve", "Debug 컨테이너 승인", "approve"},
	{"action:approve", "조치 승인", "approve"},
	{"policy:manage", "정책·터미널 정책 관리", "admin"},
	{"registry:manage", "레지스트리 자격증명 관리", "admin"},
	{"settings:manage", "운영 설정 관리", "admin"},
}

// k8sRoleCaps maps a built-in operational role to its capability keys.
var k8sRoleCaps = map[string][]string{
	"viewer":    {"pod:view", "logs:view", "env:view", "stack:view", "audit:view"},
	"developer": {"pod:view", "logs:view", "env:view", "stack:view", "terminal:request", "debug:request", "action:request"},
	"operator":  {"pod:view", "logs:view", "env:view", "stack:view", "audit:view", "terminal:request", "debug:request", "action:request", "stack:deploy", "terminal:fulltty"},
	"approver":  {"pod:view", "logs:view", "env:view", "stack:view", "audit:view", "terminal:approve", "debug:approve", "action:approve"},
	"security":  {"pod:view", "logs:view", "env:view", "stack:view", "audit:view", "secret:view-meta", "policy:manage", "terminal:approve"},
	"finops":    {"pod:view", "stack:view", "audit:view"},
	"admin":     nil, // all (resolved dynamically)
}

// K8sCapabilityCatalog returns the full capability catalog.
func K8sCapabilityCatalog() []K8sCapability { return append([]K8sCapability(nil), k8sCapabilities...) }

// K8sRoles returns the built-in operational role names (sorted).
func K8sRoles() []string {
	out := make([]string, 0, len(k8sRoleCaps))
	for r := range k8sRoleCaps {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// allCapabilityKeys returns every capability key (for admin).
func allCapabilityKeys() []string {
	out := make([]string, 0, len(k8sCapabilities))
	for _, c := range k8sCapabilities {
		out = append(out, c.Key)
	}
	return out
}

// RoleCapabilities returns the capability keys granted to a role (sorted). Unknown role → none.
func RoleCapabilities(role string) []string {
	caps, ok := k8sRoleCaps[role]
	if !ok {
		return []string{}
	}
	if role == "admin" || caps == nil {
		out := allCapabilityKeys()
		sort.Strings(out)
		return out
	}
	out := append([]string(nil), caps...)
	sort.Strings(out)
	return out
}

// RoleHasCapability reports whether a role is granted a capability.
func RoleHasCapability(role, capability string) bool {
	for _, c := range RoleCapabilities(role) {
		if c == capability {
			return true
		}
	}
	return false
}

// RoleMatrix returns the role→capabilities mapping for every built-in role.
func RoleMatrix() map[string][]string {
	out := map[string][]string{}
	for _, r := range K8sRoles() {
		out[r] = RoleCapabilities(r)
	}
	return out
}
