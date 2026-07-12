package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestPasswordLifecycleResetForcedChangeAndSessionRevocation(t *testing.T) {
	_, proxy := newAuthTestServer(t, "http://example.invalid")
	defer proxy.Close()

	login := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "correct-password"})
	var root struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(login.Body).Decode(&root)
	login.Body.Close()

	weak := postJSON(t, proxy.URL+"/admin/users", root.AccessToken, map[string]string{
		"email": "weak@example.com", "password": "short", "role": "developer",
	})
	weak.Body.Close()
	if weak.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak initial password should be rejected, got %d", weak.StatusCode)
	}

	createdResp := postJSON(t, proxy.URL+"/admin/users", root.AccessToken, map[string]string{
		"email": "lifecycle@example.com", "password": "Initial-pass-2026!", "role": "developer",
	})
	var created struct {
		User store.AuthUser `json:"user"`
	}
	_ = json.NewDecoder(createdResp.Body).Decode(&created)
	createdResp.Body.Close()
	if createdResp.StatusCode != http.StatusCreated || !created.User.MustChangePassword {
		t.Fatalf("created account should require password change: status=%d user=%+v", createdResp.StatusCode, created.User)
	}

	initialLogin := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": created.User.Email, "password": "Initial-pass-2026!"})
	var initialTokens struct {
		AccessToken string `json:"access_token"`
		User        struct {
			PasswordChangeRequired bool `json:"password_change_required"`
		} `json:"user"`
	}
	_ = json.NewDecoder(initialLogin.Body).Decode(&initialTokens)
	initialLogin.Body.Close()
	if !initialTokens.User.PasswordChangeRequired {
		t.Fatal("temporary credential login should carry password_change_required")
	}
	restricted := getWithBearer(t, proxy.URL+"/me/dashboard", initialTokens.AccessToken)
	restricted.Body.Close()
	if restricted.StatusCode != http.StatusForbidden {
		t.Fatalf("forced-change token should be restricted, got %d", restricted.StatusCode)
	}

	changed := postJSON(t, proxy.URL+"/auth/password/change", initialTokens.AccessToken, map[string]string{
		"current_password": "Initial-pass-2026!", "new_password": "Personal-pass-2026!",
	})
	changed.Body.Close()
	if changed.StatusCode != http.StatusOK {
		t.Fatalf("initial forced change failed: %d", changed.StatusCode)
	}
	stale := getWithBearer(t, proxy.URL+"/auth/me", initialTokens.AccessToken)
	stale.Body.Close()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password change should revoke current session, got %d", stale.StatusCode)
	}

	personalLogin := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": created.User.Email, "password": "Personal-pass-2026!"})
	var personalTokens struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(personalLogin.Body).Decode(&personalTokens)
	personalLogin.Body.Close()

	weakReset := postJSON(t, proxy.URL+"/admin/users/"+created.User.ID+"/password-reset", root.AccessToken, map[string]string{"temporary_password": "weak"})
	weakReset.Body.Close()
	if weakReset.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak reset password should be rejected, got %d", weakReset.StatusCode)
	}
	reset := postJSON(t, proxy.URL+"/admin/users/"+created.User.ID+"/password-reset", root.AccessToken, map[string]string{"temporary_password": "Reset-temp-2026!"})
	reset.Body.Close()
	if reset.StatusCode != http.StatusOK {
		t.Fatalf("administrator reset failed: %d", reset.StatusCode)
	}
	oldSession := getWithBearer(t, proxy.URL+"/auth/me", personalTokens.AccessToken)
	oldSession.Body.Close()
	if oldSession.StatusCode != http.StatusUnauthorized {
		t.Fatalf("administrator reset should revoke existing sessions, got %d", oldSession.StatusCode)
	}
	oldLogin := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": created.User.Email, "password": "Personal-pass-2026!"})
	oldLogin.Body.Close()
	if oldLogin.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password should stop working after reset, got %d", oldLogin.StatusCode)
	}
	resetLogin := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": created.User.Email, "password": "Reset-temp-2026!"})
	var resetTokens struct {
		AccessToken string `json:"access_token"`
		User        struct {
			PasswordChangeRequired bool `json:"password_change_required"`
		} `json:"user"`
	}
	_ = json.NewDecoder(resetLogin.Body).Decode(&resetTokens)
	resetLogin.Body.Close()
	if resetLogin.StatusCode != http.StatusOK || !resetTokens.User.PasswordChangeRequired {
		t.Fatalf("reset credential should log in only for forced change: status=%d payload=%+v", resetLogin.StatusCode, resetTokens)
	}
}

func getWithBearer(t *testing.T, target, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAdminIPResolutionIgnoresUntrustedForwardingHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	got := resolvePolicyClientIP(req, mustNetworks(t, "10.0.0.0/8"))
	if got.Text != "198.51.100.20" || got.Source != "remote_addr" {
		t.Fatalf("untrusted peer must not control forwarded IP: %+v", got)
	}

	req.RemoteAddr = "10.10.0.8:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.10.0.7")
	got = resolvePolicyClientIP(req, mustNetworks(t, "10.0.0.0/8"))
	if got.Text != "203.0.113.99" || got.Source != "x_forwarded_for" || !got.TrustedProxy {
		t.Fatalf("trusted proxy chain should resolve first untrusted client: %+v", got)
	}
}

func mustNetworks(t *testing.T, value string) []*net.IPNet {
	t.Helper()
	networks, err := parseIPCIDRList(value)
	if err != nil {
		t.Fatal(err)
	}
	return networks
}

func TestAdminIPPolicyEnforcementBreakGlassAndLockoutGuard(t *testing.T) {
	t.Setenv("ADMIN_IP_ALLOWLIST_ENABLED", "true")
	t.Setenv("ADMIN_IP_ALLOWED_CIDRS", "203.0.113.0/24")
	t.Setenv("ADMIN_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("ADMIN_IP_EMERGENCY_TOKEN", "emergency-test-token")

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://example.invalid", "secret")
	cfg.Auth.AdminToken = "admin-test-token"
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodGet, proxy.URL+"/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer admin-test-token")
	denied, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	deniedBody, _ := io.ReadAll(denied.Body)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden || !strings.Contains(string(deniedBody), "admin_ip_denied") {
		t.Fatalf("non-allowed admin IP should be denied: status=%d body=%s", denied.StatusCode, deniedBody)
	}

	req, _ = http.NewRequest(http.MethodGet, proxy.URL+"/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer admin-test-token")
	req.Header.Set(adminBreakGlassHeader, "emergency-test-token")
	bypassed, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bypassed.Body.Close()
	if bypassed.StatusCode != http.StatusOK {
		t.Fatalf("valid break-glass token should allow request, got %d", bypassed.StatusCode)
	}

	payload := `{"enabled":true,"allowed_cidrs":"192.0.2.0/24","trusted_proxy_cidrs":""}`
	put, _ := http.NewRequest(http.MethodPut, proxy.URL+"/admin/security/access-policy", strings.NewReader(payload))
	put.Header.Set("Authorization", "Bearer admin-test-token")
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set(adminBreakGlassHeader, "emergency-test-token") // reach the currently denying policy
	// Remove the header before handler lockout evaluation by using an invalid value would prevent
	// reaching the handler; instead validate the guard directly with a policy whose current request
	// is allowed, covered below.
	put.Header.Set(adminBreakGlassHeader, "emergency-test-token")
	putResp, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("break-glass should permit an intentional recovery policy update, got %d", putResp.StatusCode)
	}

	events, _ := db.ListAuditEvents(context.Background(), 100)
	foundBypass := false
	for _, event := range events {
		if event.EventType == "admin_ip_break_glass" {
			foundBypass = true
			break
		}
	}
	if !foundBypass {
		t.Fatal("break-glass use should be audit logged")
	}
}

func TestAdminIPPolicyRejectsSelfLockout(t *testing.T) {
	t.Setenv("ADMIN_IP_ALLOWLIST_ENABLED", "false")
	t.Setenv("ADMIN_IP_ALLOWED_CIDRS", "")
	t.Setenv("ADMIN_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("ADMIN_IP_EMERGENCY_TOKEN", "")
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://example.invalid", "secret")
	cfg.Auth.AdminToken = "admin-test-token"
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	payload := `{"enabled":true,"allowed_cidrs":"192.0.2.0/24","trusted_proxy_cidrs":""}`
	req, _ := http.NewRequest(http.MethodPut, proxy.URL+"/admin/security/access-policy", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer admin-test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "ip_policy_lockout_risk") {
		t.Fatalf("policy must reject current-client lockout: status=%d body=%s", resp.StatusCode, body)
	}

	direct, _ := http.NewRequest(http.MethodPut, proxy.URL+"/admin/settings/by-key/security.admin_access.ip_allowlist_enabled", strings.NewReader(`{"value":"true"}`))
	direct.Header.Set("Authorization", "Bearer admin-test-token")
	direct.Header.Set("Content-Type", "application/json")
	directResp, err := http.DefaultClient.Do(direct)
	if err != nil {
		t.Fatal(err)
	}
	directBody, _ := io.ReadAll(directResp.Body)
	directResp.Body.Close()
	if directResp.StatusCode != http.StatusMethodNotAllowed || !strings.Contains(string(directBody), "setting_managed_endpoint") {
		t.Fatalf("generic settings endpoint must not bypass IP lockout checks: status=%d body=%s", directResp.StatusCode, directBody)
	}
}

func TestAdminIPPolicyAppliesBeforeAdministratorLogin(t *testing.T) {
	t.Setenv("ADMIN_IP_ALLOWLIST_ENABLED", "true")
	t.Setenv("ADMIN_IP_ALLOWED_CIDRS", "203.0.113.0/24")
	t.Setenv("ADMIN_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("ADMIN_IP_EMERGENCY_TOKEN", "")
	_, proxy := newAuthTestServer(t, "http://example.invalid")
	defer proxy.Close()

	login := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "correct-password"})
	body, _ := io.ReadAll(login.Body)
	login.Body.Close()
	if login.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "admin_ip_denied") {
		t.Fatalf("administrator login should honor source IP policy: status=%d body=%s", login.StatusCode, body)
	}
}
