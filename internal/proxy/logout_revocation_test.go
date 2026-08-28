package proxy

import (
	"encoding/json"
	"net/http"
	"testing"
)

// RP-initiated SSO logout revoked only the presented refresh token. The session
// row is what actually stops an issued access token — verifyAccessToken
// re-checks AuthSessionActive on every request — so the caller stayed logged in
// for the remainder of the access-token TTL after clicking "log out", the
// session kept showing as active, and the audit recorded "sso_logout". The
// handler's own comment said "revoke the internal refresh token / session"; only
// the first half was true.
func TestSSOLogoutRevokesTheSessionNotJustTheRefreshToken(t *testing.T) {
	proxy, _, _ := newRevocationTestServer(t)
	token, _ := loginForAccessToken(t, proxy, "root@example.com", "correct-password")

	// The token works before logout — otherwise the assertion below proves nothing.
	if code := getWithToken(t, proxy.URL+"/auth/me", token); code != http.StatusOK {
		t.Fatalf("access token should work before logout, got %d", code)
	}

	resp := postJSON(t, proxy.URL+"/auth/keycloak/logout", token, map[string]string{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sso logout: got %d, want 200", resp.StatusCode)
	}

	if code := getWithToken(t, proxy.URL+"/auth/me", token); code == http.StatusOK {
		t.Fatal("the access token still works after SSO logout: the session was not revoked, " +
			"so anyone holding this token keeps access until it expires")
	}
}

// Plain logout answered {"status":"logged_out"} whether or not the revocation
// succeeded. On a shared machine that tells someone they are signed out while
// their token still works.
func TestLogoutDoesNotClaimSuccessWhenRevocationFails(t *testing.T) {
	proxy, _, dbPath := newRevocationTestServer(t)
	token, _ := loginForAccessToken(t, proxy, "root@example.com", "correct-password")
	failSessionRevocation(t, dbPath)

	resp := postJSON(t, proxy.URL+"/auth/logout", token, map[string]string{})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var body map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&body)
		t.Fatalf("logout reported %v after the revocation failed; the session is still active", body)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500", resp.StatusCode)
	}
}

// The healthy path must be unchanged.
func TestLogoutSucceedsNormally(t *testing.T) {
	proxy, _, _ := newRevocationTestServer(t)
	token, _ := loginForAccessToken(t, proxy, "root@example.com", "correct-password")

	resp := postJSON(t, proxy.URL+"/auth/logout", token, map[string]string{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: got %d, want 200", resp.StatusCode)
	}
	if code := getWithToken(t, proxy.URL+"/auth/me", token); code == http.StatusOK {
		t.Fatal("the access token still works after a successful logout")
	}
}

func getWithToken(t *testing.T, url, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
