package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSettingPermissionGroup(t *testing.T) {
	cases := []struct {
		name string
		def  settingDef
		want string
	}{
		{"secret is security", settingDef{Key: "text2sql.exec_dsn", Category: "text2sql", Secret: true}, "security"},
		{"mask_results is security", settingDef{Key: "text2sql.mask_results", Category: "text2sql"}, "security"},
		{"daily_risk_limit is security", settingDef{Key: "text2sql.daily_risk_limit", Category: "text2sql"}, "security"},
		{"daily_risk_warn is security", settingDef{Key: "text2sql.daily_risk_warn", Category: "text2sql"}, "security"},
		{"replay_bundles is security", settingDef{Key: "text2sql.replay_bundles", Category: "text2sql"}, "security"},
		{"clickhouse is ops", settingDef{Key: "clickhouse.batch_size", Category: "clickhouse"}, "ops"},
		{"retention is ops", settingDef{Key: "retention.days", Category: "retention"}, "ops"},
		{"cache is ops", settingDef{Key: "cache.ttl", Category: "cache"}, "ops"},
		{"text2sql model is ai", settingDef{Key: "text2sql.preview_model", Category: "text2sql"}, "ai"},
		{"carbon is billing", settingDef{Key: "carbon.pue", Category: "carbon"}, "billing"},
		{"insurance is billing", settingDef{Key: "insurance.rate", Category: "insurance"}, "billing"},
		{"pricing is billing", settingDef{Key: "pricing.usd_krw", Category: "pricing"}, "billing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := settingPermissionGroup(tc.def); got != tc.want {
				t.Errorf("settingPermissionGroup(%s) = %q, want %q", tc.def.Key, got, tc.want)
			}
		})
	}
}

func TestRoleCanWriteGroup(t *testing.T) {
	groups := []string{"ops", "ai", "security", "billing", "admin"}
	// want[role] = set of groups the role may write.
	want := map[string]map[string]bool{
		"":               {"ops": true, "ai": true, "security": true, "billing": true, "admin": true},
		"super_admin":    {"ops": true, "ai": true, "security": true, "billing": true, "admin": true},
		"admin":          {"ops": true, "ai": true, "security": true, "billing": true, "admin": true},
		"ops_admin":      {"ops": true},
		"ai_admin":       {"ai": true},
		"security_admin": {"security": true},
		"billing_admin":  {"billing": true},
		"readonly_admin": {},
		"user":           {},
	}
	for role, allowed := range want {
		for _, g := range groups {
			got := roleCanWriteGroup(role, g)
			exp := allowed[g]
			if got != exp {
				t.Errorf("roleCanWriteGroup(%q, %q) = %v, want %v", role, g, got, exp)
			}
		}
	}
}

func TestSettingsSubAdminRole(t *testing.T) {
	for _, r := range []string{"ops_admin", "ai_admin", "security_admin", "billing_admin"} {
		if !settingsSubAdminRole(r) {
			t.Errorf("settingsSubAdminRole(%q) = false, want true", r)
		}
	}
	for _, r := range []string{"admin", "super_admin", "readonly_admin", "user", ""} {
		if settingsSubAdminRole(r) {
			t.Errorf("settingsSubAdminRole(%q) = true, want false", r)
		}
	}
}

func TestLegacyReadonlySettingsRoleIsNotWritable(t *testing.T) {
	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.Auth.AdminToken = "write-token"
	cfg.Auth.AdminReadonlyToken = "read-token"
	server := &Server{cfg: cfg}
	req := httptest.NewRequest(http.MethodGet, "/admin/settings/effective", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	if role := server.callerSettingsRole(req); role != "readonly_admin" {
		t.Fatalf("legacy readonly caller role=%q", role)
	}
	if server.canWriteSetting(req, settingDef{Key: "k8s.monitoring.enabled", Category: "k8s.monitoring"}) {
		t.Fatal("legacy readonly token must not be shown as writable")
	}
}

func TestDomainAdminWriteExceptionsStayNarrow(t *testing.T) {
	cases := []struct {
		role, path, scope string
		want              bool
	}{
		{"security_admin", "/admin/policies", "admin:write", true},
		{"security_admin", "/admin/k8s/security-exceptions", "admin:write", true},
		{"security_admin", "/admin/k8s/actions", "admin:write", false},
		{"billing_admin", "/admin/budgets", "admin:write", true},
		{"billing_admin", "/admin/pricing", "admin:write", true},
		{"billing_admin", "/admin/users", "admin:write", false},
		{"billing_admin", "/admin/budgets", "admin:read", false},
	}
	for _, tc := range cases {
		if got := adminRoleWriteException(tc.role, tc.path, tc.scope); got != tc.want {
			t.Errorf("adminRoleWriteException(%q,%q,%q)=%v want %v", tc.role, tc.path, tc.scope, got, tc.want)
		}
	}
}
