package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

// MCP 를 개인 키 없이 Keycloak 토큰으로.
//
// The authorization flow itself — PKCE, the redirect, the code exchange — is
// Keycloak's and the client's. What is this server's is the resource-server
// half of the specification, and that is what these tests hold it to: it says
// where the authorization server is, it turns a 401 into a pointer there, and
// it accepts exactly the tokens that server issued for this resource, for a
// person Clustara already knows, with the powers a key would have and no more.

// fakeIDP is a Keycloak stand-in: real RSA keys, discovery, JWKS.
type fakeIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{key: key, kid: "mcp-oauth-test-kid"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 idp.server.URL,
			"authorization_endpoint": idp.server.URL + "/authorize",
			"token_endpoint":         idp.server.URL + "/token",
			"jwks_uri":               idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": idp.kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	// The discovery and JWKS caches are process-wide; start this issuer from a
	// clean slate so a key seeded by another test is not what verifies ours.
	discMu.Lock()
	discCache, discFetch = oidcDiscovery{}, time.Time{}
	discMu.Unlock()
	jwksMu.Lock()
	jwksKeys, jwksFetch = nil, time.Time{}
	jwksMu.Unlock()
	return idp
}

// accessToken is what Keycloak would hand an MCP client after the person
// signed in: signed by the realm key, issued by the issuer, for an audience.
func (idp *fakeIDP) accessToken(t *testing.T, audience any, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": idp.server.URL, "aud": audience, "sub": "subject-mcp", "typ": "Bearer",
		"exp": float64(time.Now().Add(time.Hour).Unix()), "iat": float64(time.Now().Unix()),
		"preferred_username": "ssomember", "email": "ssomember@example.com",
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signRS256(t, idp.key, idp.kid, claims)
}

const mcpListTools = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

// newMCPOAuthServer is an SSO-configured server whose issuer is the fake IdP,
// with one registered account linked to the IdP subject the tokens carry.
func newMCPOAuthServer(t *testing.T, idp *fakeIDP) (*Server, *store.SQLStore) {
	t.Helper()
	db, err := store.Open(context.Background(), config.DatabaseConfig{
		Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "gateway.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := testConfig("http://example.invalid", "secret")
	cfg.Auth.Enabled = true
	cfg.Auth.JWTSecret = "test-jwt-secret"
	cfg.Keycloak.Enabled = true
	cfg.Keycloak.IssuerURL = idp.server.URL
	cfg.Keycloak.ClientID = "clustara-web"
	cfg.Keycloak.RedirectURI = "https://gateway.example.test/auth/keycloak/callback"
	cfg.Keycloak.DefaultRole = "developer"
	srv, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	mustCreateUser(t, db, "usr_sso", "ssomember@example.com", "developer")
	if err := db.UpsertAuthIdentity(context.Background(), store.AuthIdentity{
		ID: "idn_sso", UserID: "usr_sso", Provider: "keycloak", Issuer: idp.server.URL, Subject: "subject-mcp",
	}); err != nil {
		t.Fatal(err)
	}
	return srv, db
}

func mcpCall(srv *Server, path, bearer, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Host = "127.0.0.1:9090" // the pod address behind the proxy, which must never leak into the identifier
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, r)
	return w
}

// errorMessage is the human-readable half of the product's error envelope.
func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not an error envelope: %s", w.Body.String())
	}
	return body.Error.Message
}

func metadataCall(srv *Server, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "127.0.0.1:9090" // the pod address behind the proxy, which must never leak into the identifier
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, r)
	return w
}

// guards: handleMCPOAuthMetadata, mcpOAuthChallenge, authenticateProxyContext
func TestARefusedMCPClientIsToldWhereToSignIn(t *testing.T) {
	idp := newFakeIDP(t)
	srv, _ := newMCPOAuthServer(t, idp)

	// Off by default: a deployment without the switch advertises nothing, and a
	// refusal is the refusal it always was — even for a token that would
	// otherwise be perfect.
	if w := metadataCall(srv, "/.well-known/oauth-protected-resource/mcp"); w.Code != http.StatusNotFound {
		t.Fatalf("metadata is served with MCP SSO off: %d %s", w.Code, w.Body.String())
	}
	w := mcpCall(srv, "/mcp/gateway", idp.accessToken(t, "https://gateway.example.test/mcp", nil), mcpListTools)
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "" || !strings.Contains(w.Body.String(), "invalid_api_key") {
		t.Fatalf("with MCP SSO off a token must be refused exactly like an unknown key: %d %q %s", w.Code, w.Header().Get("WWW-Authenticate"), w.Body.String())
	}

	t.Setenv("MCP_OAUTH_ENABLED", "true")

	// The document, bare and public, at both well-known paths.
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource/mcp/gateway"} {
		w := metadataCall(srv, path)
		if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s: %d cors=%q", path, w.Code, w.Header().Get("Access-Control-Allow-Origin"))
		}
		var doc map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc["error"] != nil {
			t.Fatalf("%s: metadata must be the bare RFC 9728 document, got %s", path, w.Body.String())
		}
		// The resource comes from the SSO redirect URI's origin — the one public
		// address this deployment knows — not from the request.
		if doc["resource"] != "https://gateway.example.test/mcp" {
			t.Errorf("%s: resource = %v", path, doc["resource"])
		}
		if servers, _ := doc["authorization_servers"].([]any); len(servers) != 1 || servers[0] != idp.server.URL {
			t.Errorf("%s: authorization_servers = %v", path, doc["authorization_servers"])
		}
		if scopes, _ := doc["scopes_supported"].([]any); len(scopes) != 1 || scopes[0] != "mcp:use" {
			t.Errorf("%s: scopes_supported = %v", path, doc["scopes_supported"])
		}
	}
	if w := metadataCall(srv, "/.well-known/oauth-protected-resource/v1"); w.Code != http.StatusNotFound {
		t.Errorf("metadata must exist only beneath the MCP paths, got %d", w.Code)
	}

	// No bearer at all: the 401 points at the metadata, without invalid_token.
	w = mcpCall(srv, "/mcp/gateway", "", mcpListTools)
	challenge := w.Header().Get("WWW-Authenticate")
	if w.Code != http.StatusUnauthorized || !strings.Contains(challenge, `resource_metadata="https://gateway.example.test/.well-known/oauth-protected-resource/mcp"`) || strings.Contains(challenge, "invalid_token") {
		t.Fatalf("keyless MCP call: %d %q", w.Code, challenge)
	}
	// A refused token: the same pointer, now with error="invalid_token".
	w = mcpCall(srv, "/mcp", "not.a.jwt", mcpListTools)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("refused bearer on /mcp: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	// A REST 401 carries no challenge: browsers and SDKs would follow it nowhere.
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+idp.accessToken(t, "https://gateway.example.test/mcp", nil))
	rest := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rest, r)
	if rest.Code != http.StatusUnauthorized || rest.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("a valid SSO token on a REST route must be refused with no challenge: %d %q", rest.Code, rest.Header().Get("WWW-Authenticate"))
	}
}

// guards: mcpOAuthPrincipal, mcpOAuthAccount
func TestAKeycloakTokenOpensMCPForAnAccountClustaraKnows(t *testing.T) {
	idp := newFakeIDP(t)
	srv, db := newMCPOAuthServer(t, idp)
	t.Setenv("MCP_OAUTH_ENABLED", "true")

	// The canonical path: an Audience mapper put the resource in aud.
	w := mcpCall(srv, "/mcp/gateway", idp.accessToken(t, []any{"account", "https://gateway.example.test/mcp"}, nil), mcpListTools)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"tools"`) {
		t.Fatalf("tools/list with a token for this resource: %d %s", w.Code, w.Body.String())
	}
	// The aggregator endpoint takes the same token and applies its mcp:use gate.
	if w := mcpCall(srv, "/mcp", idp.accessToken(t, "https://gateway.example.test/mcp", nil), mcpListTools); w.Code != http.StatusOK {
		t.Fatalf("/mcp with the same token: %d %s", w.Code, w.Body.String())
	}

	// The principal is the registered account, with the administrator's
	// scopes and the account's own role — nothing lifted from the token.
	r := httptest.NewRequest(http.MethodPost, "/mcp/gateway", nil)
	r.Header.Set("Authorization", "Bearer "+idp.accessToken(t, "https://gateway.example.test/mcp", map[string]any{
		"realm_access": map[string]any{"roles": []any{"vibe-admin"}},
	}))
	id, authCtx, ok := srv.authenticateProxyContext(r)
	if !ok || authCtx == nil || authCtx.UserID != "usr_sso" || authCtx.Role != "developer" || id != "sso:usr_sso" {
		t.Fatalf("principal = %q %+v ok=%v", id, authCtx, ok)
	}
	if len(authCtx.Scopes) != 1 || authCtx.Scopes[0] != "mcp:use" {
		t.Fatalf("scopes must be the administrator's ceiling, got %v", authCtx.Scopes)
	}
	if hasScope(authCtx.Scopes, "admin:read") {
		t.Fatal("a realm role in the token lifted the principal to admin")
	}

	// A token whose scope claim speaks Clustara's vocabulary narrows further;
	// one that only says openid/profile does not zero the grant.
	r.Header.Set("Authorization", "Bearer "+idp.accessToken(t, "https://gateway.example.test/mcp", map[string]any{"scope": "openid profile email"}))
	if _, authCtx, ok := srv.authenticateProxyContext(r); !ok || !hasScope(authCtx.Scopes, "mcp:use") {
		t.Fatalf("OAuth-only scopes must not erase the grant: %+v ok=%v", authCtx, ok)
	}
	r.Header.Set("Authorization", "Bearer "+idp.accessToken(t, "https://gateway.example.test/mcp", map[string]any{"scope": "openid models:read"}))
	if _, authCtx, ok := srv.authenticateProxyContext(r); ok && hasScope(authCtx.Scopes, "mcp:use") {
		t.Fatalf("a token that names Clustara scopes must be held to their intersection: %+v ok=%v", authCtx, ok)
	}

	// The compatibility path: no mapper, the administrator lists the MCP
	// client id, and Keycloak's real shape (aud=account, azp=client) passes.
	t.Setenv("MCP_OAUTH_AUDIENCE", "claude-mcp")
	w = mcpCall(srv, "/mcp/gateway", idp.accessToken(t, "account", map[string]any{"azp": "claude-mcp"}), mcpListTools)
	if w.Code != http.StatusOK {
		t.Fatalf("azp in the administrator's list must pass without a mapper: %d %s", w.Code, w.Body.String())
	}

	// The account must be one the web sign-in already provisioned. A token for
	// a stranger creates nothing.
	before, _ := db.ListAuthUsers(context.Background())
	w = mcpCall(srv, "/mcp/gateway", idp.accessToken(t, "https://gateway.example.test/mcp", map[string]any{"sub": "nobody", "email": "nobody@example.com"}), mcpListTools)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "웹으로 한 번 로그인") {
		t.Fatalf("unknown subject: %d %s", w.Code, w.Body.String())
	}
	if after, _ := db.ListAuthUsers(context.Background()); len(after) != len(before) {
		t.Fatalf("a token created an account: %d → %d users", len(before), len(after))
	}
	// A disabled account does not come back to life through MCP.
	if err := db.UpdateAuthUserRoleStatus(context.Background(), "usr_sso", "", "disabled"); err != nil {
		t.Fatal(err)
	}
	if w := mcpCall(srv, "/mcp/gateway", idp.accessToken(t, "https://gateway.example.test/mcp", nil), mcpListTools); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "비활성") {
		t.Fatalf("disabled account: %d %s", w.Code, w.Body.String())
	}
}

// guards: mcpOAuthPrincipal, mcpOAuthAudienceAccepted
func TestATokenIsRefusedForTheRightReason(t *testing.T) {
	idp := newFakeIDP(t)
	srv, _ := newMCPOAuthServer(t, idp)
	t.Setenv("MCP_OAUTH_ENABLED", "true")

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hs256 := func(claims map[string]any) string {
		hb, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
		cb, _ := json.Marshal(claims)
		return base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb) + ".c2ln"
	}
	forThis := "https://gateway.example.test/mcp"
	cases := []struct {
		name, token, want string
	}{
		// The one this feature exists to catch: a token from some other
		// application in the realm. The message names what it saw and what
		// to write so the operator can finish the configuration from it.
		{"another app's token", idp.accessToken(t, "account", map[string]any{"azp": "other-app"}), `aud=[account], azp="other-app"`},
		{"another app's token names the fix", idp.accessToken(t, "account", map[string]any{"azp": "other-app"}), `mcp.oauth.audience 에 "other-app"`},
		{"another app's token names the mapper value", idp.accessToken(t, "account", map[string]any{"azp": "other-app"}), `"https://gateway.example.test/mcp"`},
		{"expired", idp.accessToken(t, forThis, map[string]any{"exp": float64(time.Now().Add(-time.Hour).Unix())}), "만료"},
		{"not yet valid", idp.accessToken(t, forThis, map[string]any{"nbf": float64(time.Now().Add(time.Hour).Unix())}), "nbf"},
		{"another issuer", signRS256(t, idp.key, idp.kid, map[string]any{"iss": "https://elsewhere.example.test", "aud": forThis, "sub": "subject-mcp", "exp": float64(time.Now().Add(time.Hour).Unix())}), "발급자"},
		{"wrong key", signRS256(t, other, idp.kid, map[string]any{"iss": idp.server.URL, "aud": forThis, "sub": "subject-mcp", "exp": float64(time.Now().Add(time.Hour).Unix())}), "서명"},
		{"HS256", hs256(map[string]any{"iss": idp.server.URL, "aud": forThis, "sub": "subject-mcp", "exp": float64(time.Now().Add(time.Hour).Unix())}), "유효하지 않"},
		{"ID token", idp.accessToken(t, forThis, map[string]any{"typ": "ID"}), "ID 토큰"},
		{"sender-constrained", idp.accessToken(t, forThis, map[string]any{"cnf": map[string]any{"jkt": "x"}}), "cnf"},
		{"no subject", idp.accessToken(t, forThis, map[string]any{"sub": ""}), "sub"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := mcpCall(srv, "/mcp/gateway", tc.token, mcpListTools)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("accepted: %d %s", w.Code, w.Body.String())
			}
			if msg := errorMessage(t, w); !strings.Contains(msg, tc.want) {
				t.Fatalf("refusal must say %q, got %s", tc.want, msg)
			}
			if !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
				t.Fatalf("a refused token must still be pointed at the metadata: %q", w.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

// guards: mcpOAuthResource, mcpOAuthMetadataURL
func TestTheResourceIdentifierComesFromConfigurationBeforeTheRequest(t *testing.T) {
	idp := newFakeIDP(t)
	srv, _ := newMCPOAuthServer(t, idp)
	t.Setenv("MCP_OAUTH_ENABLED", "true")
	t.Setenv("MCP_OAUTH_RESOURCE", "https://mcp.example.test/mcp")

	w := metadataCall(srv, "/.well-known/oauth-protected-resource/mcp")
	var doc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	if doc["resource"] != "https://mcp.example.test/mcp" {
		t.Fatalf("resource = %v", doc["resource"])
	}
	// The explicit identifier is what the audience must name, and the 401
	// points at the metadata beneath it.
	if w := mcpCall(srv, "/mcp/gateway", idp.accessToken(t, "https://gateway.example.test/mcp", nil), mcpListTools); w.Code != http.StatusUnauthorized {
		t.Fatalf("the derived identifier must stop being accepted once one is configured: %d", w.Code)
	}
	w = mcpCall(srv, "/mcp/gateway", idp.accessToken(t, "https://mcp.example.test/mcp/gateway", nil), mcpListTools)
	if w.Code != http.StatusOK {
		t.Fatalf("an aud naming the endpoint beneath the identifier must pass: %d %s", w.Code, w.Body.String())
	}
	if got := mcpOAuthMetadataURL("https://mcp.example.test/mcp"); got != "https://mcp.example.test/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("metadata url = %s", got)
	}
	if got := mcpOAuthMetadataURL("https://mcp.example.test"); got != "https://mcp.example.test/.well-known/oauth-protected-resource" {
		t.Fatalf("metadata url for a bare origin = %s", got)
	}
}

// guards: authenticateProxyContext
func TestAProxyKeyStillWorksWhenMCPSSOIsOn(t *testing.T) {
	idp := newFakeIDP(t)
	srv, db := newMCPOAuthServer(t, idp)
	t.Setenv("MCP_OAUTH_ENABLED", "true")
	mustCreateAPIKey(t, db, "ak_sso_side", "usr_sso", "pcg_test_key_beside_sso")

	if w := mcpCall(srv, "/mcp/gateway", "pcg_test_key_beside_sso", mcpListTools); w.Code != http.StatusOK {
		t.Fatalf("the key path must be untouched: %d %s", w.Code, w.Body.String())
	}
	if w := mcpCall(srv, "/mcp/gateway", "pcg_unknown_key", mcpListTools); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_api_key") {
		t.Fatalf("an unknown key is refused as an unknown key, not as a bad token: %d %s", w.Code, w.Body.String())
	}
}
