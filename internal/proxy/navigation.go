package proxy

import (
	"net/http"
	"strings"
)

// menuVersion is bumped whenever the menu registry or its access rules change, so the
// SPA can detect a stale navigation and refresh /me/navigation without a full reload.
const menuVersion = 40

// menuItem is one navigable destination in the admin SPA. Access is decided server-side
// from the caller's scopes + enabled feature flags — the same registry drives both the
// rendered menu (/me/navigation) and the SPA's route guard, so hiding a menu and blocking
// its route can never drift apart.
type menuItem struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Path      string   `json:"path"`            // hash route, e.g. "#/dashboard"
	Tab       string   `json:"tab"`             // SPA data-tab value
	Group     string   `json:"group"`           // me | ops | security | settings
	Scopes    []string `json:"required_scopes"` // any-of; empty = any authenticated user
	Features  []string `json:"required_features"`
	DataScope string   `json:"data_scope"` // self | team | all
}

// menuRegistry is the single source of truth for navigation. Order = display order.
var menuRegistry = []menuItem{
	// 개인 영역 — 현재 로그인 사용자 기준의 업무와 자격증명.
	{ID: "me.home", Label: "내 홈", Path: "#/me", Tab: "me", Group: "me", DataScope: "self"},
	{ID: "me.calendar", Label: "내 업무 캘린더", Path: "#/my-calendar", Tab: "my-calendar", Group: "me", DataScope: "self"},
	{ID: "me.keys", Label: "개인 키 관리", Path: "#/mykeys", Tab: "mykeys", Group: "me", DataScope: "self"},
	{ID: "me.integrations", Label: "나의 외부 연동", Path: "#/my-integrations", Tab: "my-integrations", Group: "me", DataScope: "self"},
	{ID: "me.profile", Label: "개인화 설정", Path: "#/my-profile", Tab: "my-profile", Group: "me", DataScope: "self"},
	// 운영 영역 — Kubernetes 운영 허브 (admin:read).
	{ID: "ops.k8s_home", Label: "운영 홈", Path: "#/k8s-home", Tab: "k8s-home", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.work_calendar", Label: "전체 업무 캘린더", Path: "#/work-calendar", Tab: "work-calendar", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.fleet", Label: "FleetOps", Path: "#/fleet", Tab: "fleet", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s", Label: "클러스터", Path: "#/k8s", Tab: "k8s", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_collector", Label: "수집 상태", Path: "#/k8s-collector", Tab: "k8s-collector", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_resources", Label: "리소스 전체", Path: "#/k8s-resources", Tab: "k8s-resources", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_workloads", Label: "워크로드", Path: "#/k8s-workloads", Tab: "k8s-workloads", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_network", Label: "네트워크", Path: "#/k8s-network", Tab: "k8s-network", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_storage", Label: "스토리지", Path: "#/k8s-storage", Tab: "k8s-storage", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_components", Label: "구성요소", Path: "#/k8s-components", Tab: "k8s-components", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_devtools", Label: "개발자 도구", Path: "#/k8s-devtools", Tab: "k8s-devtools", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_auth", Label: "인증·권한", Path: "#/k8s-auth", Tab: "k8s-auth", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_pods", Label: "Pod 관리", Path: "#/k8s-pods", Tab: "k8s-pods", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_nodes", Label: "노드 관리", Path: "#/k8s-nodes", Tab: "k8s-nodes", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_developer", Label: "개발자 뷰", Path: "#/k8s-developer", Tab: "k8s-developer", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.service_catalog", Label: "서비스 카탈로그", Path: "#/service-catalog", Tab: "service-catalog", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_stacks", Label: "앱 배포", Path: "#/k8s-stacks", Tab: "k8s-stacks", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_manifest_changes", Label: "YAML 변경/생성", Path: "#/k8s-manifest-changes", Tab: "k8s-manifest-changes", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.harbor", Label: "Harbor 레지스트리", Path: "#/harbor", Tab: "harbor", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.harbor_robots", Label: "Harbor Robot", Path: "#/harbor-robots", Tab: "harbor-robots", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.app_launcher", Label: "앱 런처", Path: "#/app-launcher", Tab: "app-launcher", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.app_launch_history", Label: "런칭 이력", Path: "#/app-launch-history", Tab: "app-launch-history", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.gitops", Label: "GitOps 변경관리", Path: "#/gitops", Tab: "gitops", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_timeline", Label: "변경 타임라인", Path: "#/k8s-timeline", Tab: "k8s-timeline", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.problems", Label: "Problem Inbox", Path: "#/problems", Tab: "problems", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_rca", Label: "장애 분석", Path: "#/k8s-rca", Tab: "k8s-rca", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_incidents", Label: "장애 워룸", Path: "#/k8s-incidents", Tab: "k8s-incidents", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_graph", Label: "리소스 그래프", Path: "#/k8s-graph", Tab: "k8s-graph", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_conn", Label: "연결성 점검", Path: "#/k8s-conn", Tab: "k8s-conn", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_actions", Label: "액션 승인함", Path: "#/k8s-actions", Tab: "k8s-actions", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_agentops", Label: "에이전트 품질", Path: "#/k8s-agentops", Tab: "k8s-agentops", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_capacity", Label: "용량·자동확장", Path: "#/k8s-capacity", Tab: "k8s-capacity", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_meta", Label: "그룹·오너십", Path: "#/k8s-meta", Tab: "k8s-meta", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_ai", Label: "AI 분석", Path: "#/k8s-ai", Tab: "k8s-ai", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_reports", Label: "리포트 센터", Path: "#/k8s-reports", Tab: "k8s-reports", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ops.k8s_slo", Label: "SLO 센터", Path: "#/k8s-slo", Tab: "k8s-slo", Group: "ops", Scopes: []string{"admin:read"}, DataScope: "all"},
	// 비용 영역.
	{ID: "bill.finops", Label: "FinOps", Path: "#/finops", Tab: "finops", Group: "billing", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "bill.k8s_cost", Label: "비용", Path: "#/k8s-cost", Tab: "k8s-cost", Group: "billing", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "ai.gateway_governance", Label: "AI Governance", Path: "#/ai-governance", Tab: "ai-governance", Group: "billing", Scopes: []string{"admin:read"}, DataScope: "all"},
	// 보안 영역.
	{ID: "sec.k8s_security", Label: "보안", Path: "#/k8s-security", Tab: "k8s-security", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_vulnerabilities", Label: "이미지 취약점", Path: "#/k8s-security-vulnerabilities", Tab: "k8s-security-vulnerabilities", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_sbom", Label: "SBOM 분석", Path: "#/k8s-security-sbom", Tab: "k8s-security-sbom", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_cluster_scan", Label: "클러스터 지속 스캔", Path: "#/k8s-security-cluster-scan", Tab: "k8s-security-cluster-scan", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_admission", Label: "배포 차단 정책", Path: "#/k8s-security-admission", Tab: "k8s-security-admission", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_image_launch", Label: "이미지 런칭 보안", Path: "#/k8s-security-image-launch", Tab: "k8s-security-image-launch", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_runtime", Label: "런타임 탐지", Path: "#/k8s-security-runtime", Tab: "k8s-security-runtime", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_benchmark", Label: "CIS Benchmark", Path: "#/k8s-security-benchmark", Tab: "k8s-security-benchmark", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_security_exceptions", Label: "예외 승인", Path: "#/k8s-security-exceptions", Tab: "k8s-security-exceptions", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	{ID: "sec.k8s_policy", Label: "정책 센터", Path: "#/k8s-policy", Tab: "k8s-policy", Group: "security", Scopes: []string{"security:read"}, DataScope: "all"},
	// 설정 영역.
	{ID: "set.enterprise", Label: "엔터프라이즈", Path: "#/enterprise", Tab: "enterprise", Group: "settings", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "set.governance_hub", Label: "Governance Hub", Path: "#/governance", Tab: "governance", Group: "settings", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "set.k8s_settings", Label: "운영 설정", Path: "#/k8s-settings", Tab: "k8s-settings", Group: "settings", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "set.settings", Label: "설정", Path: "#/settings", Tab: "settings", Group: "settings", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "set.external_integrations", Label: "외부연동 설정", Path: "#/external-integrations", Tab: "external-integrations", Group: "settings", Scopes: []string{"admin:read"}, DataScope: "all"},
	{ID: "set.k8s_configrollback", Label: "설정 롤백 센터", Path: "#/k8s-configrollback", Tab: "k8s-configrollback", Group: "settings", Scopes: []string{"admin:read"}, DataScope: "all"},
}

// childTabs maps a parent tab to the nested route tabs that share its permission. The
// route guard treats a child as accessible exactly when its parent menu is accessible.
var childTabs = map[string][]string{
	"settings": {"runtimesettings", "errors", "changesets"},
}

// featureFlags reports which optional features are enabled, for both /auth/me and menu
// gating. personal_home is always on (it is this feature); team_dashboard is reserved.
func (s *Server) featureFlags() map[string]bool {
	return map[string]bool{
		"self_service_keys": s.cfg.Auth.SelfServiceKeys,
		"personal_home":     true,
		"team_dashboard":    false,
	}
}

// menuAccessible reports whether a caller with the given scopes/features may see an item.
func menuAccessible(item menuItem, scopes []string, features map[string]bool) bool {
	for _, f := range item.Features {
		if !features[f] {
			return false
		}
	}
	if len(item.Scopes) == 0 {
		return true // any authenticated user
	}
	for _, want := range item.Scopes {
		if hasScope(scopes, want) {
			return true
		}
	}
	return false
}

// menuDecision returns whether a menu is allowed for the caller and a human reason — the
// data behind /permissions/effective so an operator can see exactly why a menu is hidden.
func menuDecision(item menuItem, scopes []string, features map[string]bool) (bool, string) {
	for _, f := range item.Features {
		if !features[f] {
			return false, "feature '" + f + "' disabled"
		}
	}
	if len(item.Scopes) == 0 {
		return true, "any authenticated user"
	}
	for _, want := range item.Scopes {
		if hasScope(scopes, want) {
			return true, "has scope '" + want + "'"
		}
	}
	return false, "missing any of scopes: " + strings.Join(item.Scopes, ", ")
}

// accessibleMenus returns the registry filtered to what the caller may see.
func accessibleMenus(scopes []string, features map[string]bool) []menuItem {
	out := make([]menuItem, 0, len(menuRegistry))
	for _, item := range menuRegistry {
		if menuAccessible(item, scopes, features) {
			out = append(out, item)
		}
	}
	return out
}

// allowedTabs is the flat set of SPA tabs the caller may route to: each accessible menu's
// tab plus that tab's nested children. Drives the SPA route guard.
func allowedTabs(scopes []string, features map[string]bool) []string {
	tabs := []string{}
	seen := map[string]bool{}
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			tabs = append(tabs, t)
		}
	}
	for _, item := range accessibleMenus(scopes, features) {
		add(item.Tab)
		for _, c := range childTabs[item.Tab] {
			add(c)
		}
	}
	return tabs
}

// roleHomeOverride pins specific built-in roles to a role-tailored landing that scope
// alone can't distinguish (e.g. security_admin and readonly_admin both hold admin:read +
// security:read, but the former lands on the security dashboard).
var roleHomeOverride = map[string]string{
	"security_admin": "#/k8s-security",
}

// resolveDefaultHome picks the landing route from scopes alone: operators (admin:read) →
// operational dashboard; team managers (team:read, no admin:read) → team dashboard; else
// the personalized home.
func resolveDefaultHome(scopes []string) string {
	if hasScope(scopes, "admin:read") {
		return "#/k8s-home"
	}
	if hasScope(scopes, "security:read") {
		return "#/k8s-security"
	}
	return "#/me"
}

// resolveHome is the role-aware landing: a per-role override wins, otherwise scope-based.
func resolveHome(role string, scopes []string) string {
	if h := roleHomeOverride[strings.TrimSpace(role)]; h != "" {
		return h
	}
	return resolveDefaultHome(scopes)
}

// navigationFor builds the full navigation payload for a caller's scopes/features.
func (s *Server) navigationFor(scopes []string, role string) map[string]any {
	features := s.featureFlags()
	return map[string]any{
		"menus":        accessibleMenus(scopes, features),
		"allowed_tabs": allowedTabs(scopes, features),
		"default_home": resolveHome(role, scopes),
		"role":         role,
		"scopes":       scopes,
		"features":     features,
		"menu_version": menuVersion,
	}
}

// handleMeNavigation returns the caller's accessible menu set, computed server-side. The
// SPA renders only these items and guards routes against allowed_tabs, so menu hiding and
// route blocking share one policy. In legacy mode (auth disabled) the full operator menu
// is returned, matching the admin-token surface.
func (s *Server) handleMeNavigation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.cfg.Auth.Enabled {
		writeJSON(w, http.StatusOK, s.navigationFor(append([]string{}, allScopes...), "admin"))
		return
	}
	claims, ok := s.currentAccessClaims(r)
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid access token", "invalid_request_error", "invalid_access_token")
		return
	}
	writeJSON(w, http.StatusOK, s.navigationFor(claims.Scopes, claims.Role))
}
