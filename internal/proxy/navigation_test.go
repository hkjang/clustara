package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

func tabSet(scopes []string, features map[string]bool) map[string]bool {
	set := map[string]bool{}
	for _, t := range allowedTabs(scopes, features) {
		set[t] = true
	}
	return set
}

func TestResolveDefaultHome(t *testing.T) {
	// Clustara is an admin-oriented K8s tool: admin:read lands on the ops home; everyone
	// else also lands on the ops home (a security-only role would get the security view).
	cases := []struct {
		role string
		want string
	}{
		{"admin", "#/k8s-home"},
		{"viewer", "#/k8s-home"},
		{"readonly_admin", "#/k8s-home"},
		{"security_admin", "#/k8s-home"}, // has admin:read (role override applies via resolveHome)
		{"developer", "#/k8s-home"},
		{"service_account", "#/k8s-home"},
	}
	for _, c := range cases {
		if got := resolveDefaultHome(roleScopes[c.role]); got != c.want {
			t.Errorf("resolveDefaultHome(%s) = %q, want %q", c.role, got, c.want)
		}
	}
}

func TestAccessibleMenusByRole(t *testing.T) {
	features := map[string]bool{}

	// developer: no admin:read/security:read → sees no K8s menu at all.
	devTabs := tabSet(roleScopes["developer"], features)
	for _, forbidden := range []string{"k8s-home", "k8s", "k8s-security", "settings"} {
		if devTabs[forbidden] {
			t.Errorf("developer must NOT see %q", forbidden)
		}
	}

	// ai_admin: admin:read but NOT security:read → ops tabs + settings, but no security.
	aiTabs := tabSet(roleScopes["ai_admin"], features)
	for _, want := range []string{"k8s-home", "fleet", "k8s", "k8s-resources", "k8s-workloads", "k8s-network", "k8s-storage", "k8s-components", "k8s-devtools", "k8s-auth", "k8s-pods", "k8s-nodes", "service-catalog", "gitops", "problems", "k8s-rca", "finops", "ai-governance", "enterprise", "settings"} {
		if !aiTabs[want] {
			t.Errorf("ai_admin should see %q", want)
		}
	}
	if aiTabs["k8s-security"] {
		t.Error("ai_admin lacks security:read → must NOT see k8s-security")
	}

	// admin: every K8s area incl. security + nested settings children.
	adminTabs := tabSet(roleScopes["admin"], features)
	for _, want := range []string{"k8s-home", "fleet", "k8s-resources", "k8s-workloads", "k8s-network", "k8s-storage", "k8s-components", "k8s-devtools", "k8s-auth", "k8s-timeline", "gitops", "problems", "k8s-conn", "k8s-actions", "k8s-nodes", "service-catalog", "k8s-meta", "finops", "ai-governance", "k8s-security", "enterprise", "settings"} {
		if !adminTabs[want] {
			t.Errorf("admin should see %q", want)
		}
	}
	if !adminTabs["runtimesettings"] {
		t.Error("admin allowed_tabs should include nested settings children (runtimesettings)")
	}
}

func TestMeNavigationLegacyModeReturnsFullMenu(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "nav.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/me/navigation")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /me/navigation = %d", resp.StatusCode)
	}
	var nav struct {
		Menus       []menuItem `json:"menus"`
		AllowedTabs []string   `json:"allowed_tabs"`
		DefaultHome string     `json:"default_home"`
		MenuVersion int        `json:"menu_version"`
	}
	json.NewDecoder(resp.Body).Decode(&nav)
	resp.Body.Close()
	// Legacy (auth disabled) = admin-equivalent: full menu, ops home.
	if nav.DefaultHome != "#/k8s-home" {
		t.Errorf("legacy default_home = %q, want #/k8s-home", nav.DefaultHome)
	}
	// No menu items are feature-gated anymore, so all are exposed.
	if len(nav.Menus) != len(menuRegistry) {
		t.Errorf("legacy mode should expose all %d menus, got %d", len(menuRegistry), len(nav.Menus))
	}
	tabs := map[string]bool{}
	for _, tb := range nav.AllowedTabs {
		tabs[tb] = true
	}
	for _, want := range []string{"k8s-home", "fleet", "gitops", "problems", "finops", "ai-governance", "enterprise", "settings", "k8s-resources", "k8s-workloads", "k8s-network", "k8s-storage", "k8s-components", "k8s-devtools", "k8s-auth", "k8s-nodes", "service-catalog", "k8s-security", "runtimesettings"} {
		if !tabs[want] {
			t.Errorf("legacy allowed_tabs missing %q", want)
		}
	}
}

func TestRoleCatalog(t *testing.T) {
	cat := roleCatalog()
	if len(cat) != len(roleScopes) {
		t.Fatalf("catalog should list all %d roles, got %d", len(roleScopes), len(cat))
	}
	byRole := map[string]roleInfo{}
	for _, c := range cat {
		byRole[c.Role] = c
	}
	if !byRole["admin"].IsAdmin || byRole["admin"].DefaultHome != "#/k8s-home" {
		t.Errorf("admin should be is_admin with ops home: %+v", byRole["admin"])
	}
	if byRole["developer"].IsAdmin || byRole["developer"].DefaultHome != "#/k8s-home" {
		t.Errorf("developer should be non-admin with ops home: %+v", byRole["developer"])
	}
	// Highest rank first.
	if cat[0].Rank < cat[len(cat)-1].Rank {
		t.Errorf("catalog should be ranked high→low, got %d..%d", cat[0].Rank, cat[len(cat)-1].Rank)
	}
}

func TestPermissionsEffectiveLegacyMode(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "perm.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/permissions/effective")
	var eff struct {
		Role    string `json:"role"`
		IsAdmin bool   `json:"is_admin"`
		Menus   []struct {
			ID      string `json:"id"`
			Allowed bool   `json:"allowed"`
			Reason  string `json:"reason"`
		} `json:"menus"`
	}
	json.NewDecoder(resp.Body).Decode(&eff)
	resp.Body.Close()
	if !eff.IsAdmin {
		t.Errorf("legacy mode should be admin-equivalent, got role=%q", eff.Role)
	}
	// Every menu carries an allow/deny reason.
	for _, m := range eff.Menus {
		if m.Reason == "" {
			t.Errorf("menu %q missing decision reason", m.ID)
		}
	}
}

func TestTeamManagerNavigation(t *testing.T) {
	features := map[string]bool{}
	scopes := roleScopes["team_manager"]
	// team_manager has neither admin:read nor security:read → lands on the ops home and
	// sees no K8s menu (this is now an admin-oriented K8s tool).
	if got := resolveDefaultHome(scopes); got != "#/k8s-home" {
		t.Errorf("team_manager default_home = %q, want #/k8s-home", got)
	}
	tabs := tabSet(scopes, features)
	for _, forbidden := range []string{"k8s-home", "k8s", "settings", "k8s-security"} {
		if tabs[forbidden] {
			t.Errorf("team_manager must NOT see %q", forbidden)
		}
	}
}

func TestRoleHomeOverrides(t *testing.T) {
	features := map[string]bool{}
	// security_admin keeps a tailored landing; admin-scoped roles fall back to the ops home.
	if got := resolveHome("security_admin", roleScopes["security_admin"]); got != "#/k8s-security" {
		t.Errorf("security_admin home = %q, want #/k8s-security", got)
	}
	for _, role := range []string{"admin", "readonly_admin", "billing_admin"} {
		if got := resolveHome(role, roleScopes[role]); got != "#/k8s-home" {
			t.Errorf("resolveHome(%s) = %q, want #/k8s-home", role, got)
		}
	}
	// security_admin sees the security tab; billing_admin (no security:read) does not.
	if !tabSet(roleScopes["security_admin"], features)["k8s-security"] {
		t.Error("security_admin should see k8s-security")
	}
	if tabSet(roleScopes["billing_admin"], features)["k8s-security"] {
		t.Error("billing_admin should not see k8s-security")
	}
}

func TestRedactPromptDetails(t *testing.T) {
	prompts := []store.PromptDetail{
		{Role: "user", ContentText: "secret original text", RedactedText: "[redacted]"},
		{Role: "system", ContentText: "same", RedactedText: "same"},
		{Role: "user", ContentText: "", RedactedText: "x"},
	}
	redactPromptDetails(prompts)
	if prompts[0].ContentText != "[redacted]" {
		t.Errorf("raw content should be collapsed to redacted, got %q", prompts[0].ContentText)
	}
	if prompts[1].ContentText != "same" {
		t.Errorf("already-equal content untouched, got %q", prompts[1].ContentText)
	}
	// rawPromptViewerRoles: only full admins + security_admin.
	for _, role := range []string{"admin", "super_admin", "security_admin"} {
		if !rawPromptViewerRoles[role] {
			t.Errorf("%s should be allowed to view raw prompts", role)
		}
	}
	for _, role := range []string{"viewer", "readonly_admin", "ops_admin", "ai_admin", "team_admin", "team_manager", "developer"} {
		if rawPromptViewerRoles[role] {
			t.Errorf("%s must NOT view raw prompts", role)
		}
	}
}
