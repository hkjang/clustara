package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"clustara/internal/store"
)

// MCP 를 SSO 로 — 개인 키 없이, Keycloak 이 발급한 액세스 토큰으로.
//
// The MCP authorization specification (2025-06-18 and later) is OAuth 2.1: the
// MCP server is a *resource server* that publishes where its authorization
// server is (RFC 9728, /.well-known/oauth-protected-resource), and a client
// refused with 401 reads that document, sends the person through Keycloak with
// PKCE, and comes back with an access token whose audience (RFC 8707) is this
// server. Nothing about issuing tokens happens here — Keycloak does that — and
// this file answers two questions only: where is the authorization server, and
// is this token one it issued for us.
//
// The proxy key stays. It is what an automation with no person behind it uses,
// and what a deployment without Keycloak uses. A token from SSO is a second
// door into the same room: it authenticates an *existing* Clustara account,
// carries the scopes the administrator chose (never wider than the account's
// own role), and is accepted on the two MCP endpoints only. It never creates
// an account — signing in to the web once is what provisions one — and it
// never lifts a role from a token claim.

// mcpOAuthPaths are the endpoints that accept an SSO access token. REST,
// WebSocket and admin routes keep taking keys and sessions only; a token that
// opened the whole API would make this "a new door into everything" rather
// than "MCP without a key".
var mcpOAuthPaths = map[string]bool{"/mcp": true, "/mcp/gateway": true}

func mcpOAuthPath(path string) bool { return mcpOAuthPaths[path] }

const mcpOAuthMetadataPath = "/.well-known/oauth-protected-resource"

type mcpOAuthSettings struct {
	Enabled bool
	// Issuer is the authorization server, shared with the web sign-in
	// (SSO 설정의 Issuer URL). MCP never configures a second one.
	Issuer string
	// Resource is the identifier this server claims (RFC 8707): the public
	// address of the MCP endpoint, what the metadata advertises and what a
	// token's aud may name. Empty means derived — see resource().
	Resource string
	// Audiences are the additional aud/azp values an administrator accepts.
	// A real Keycloak 26 puts only "account" in aud and the client id in azp,
	// so naming the MCP client id here is the path that needs no mapper.
	Audiences []string
	// Scopes are what a valid token may do. Keycloak does not know Clustara's
	// scope vocabulary, and teaching every realm that vocabulary before MCP
	// works is the wrong trade; the administrator states the ceiling once.
	Scopes []string
}

// mcpOAuthSettings reads the runtime settings on demand, the way the monitoring
// workers do, so an administrator's save is seen by every pod without restart.
func (s *Server) mcpOAuthSettings(ctx context.Context) mcpOAuthSettings {
	enabled, _ := strconv.ParseBool(s.runtimeSettingValue(ctx, "mcp.oauth.enabled"))
	return mcpOAuthSettings{
		Enabled:   enabled,
		Issuer:    strings.TrimRight(strings.TrimSpace(s.keycloakConfig().IssuerURL), "/"),
		Resource:  strings.TrimRight(s.runtimeSettingValue(ctx, "mcp.oauth.resource"), "/"),
		Audiences: strings.Fields(s.runtimeSettingValue(ctx, "mcp.oauth.audience")),
		Scopes:    strings.Fields(s.runtimeSettingValue(ctx, "mcp.oauth.scopes")),
	}
}

// active reports whether SSO tokens are actually accepted. The switch alone is
// not enough: without an issuer there is nothing to verify against, and
// advertising metadata that then refuses every token puts the client in a
// sign-in loop. The reason is logged so "I turned it on and nothing happened"
// has an answer.
func (settings mcpOAuthSettings) active() bool {
	if !settings.Enabled {
		return false
	}
	if settings.Issuer == "" {
		slog.Warn("mcp oauth is enabled but the SSO issuer URL is empty; SSO tokens are not accepted")
		return false
	}
	return true
}

// resource is the identifier this deployment claims for its MCP endpoints.
//
// Order: the administrator's explicit value; the origin of the SSO redirect
// URI, which is the one public address this deployment already knows about;
// the request's own origin as a last resort. The last is what anyone can set
// with a Host header, which is why it comes last.
func (s *Server) mcpOAuthResource(r *http.Request, settings mcpOAuthSettings) string {
	if settings.Resource != "" {
		return settings.Resource
	}
	if redirect, err := url.Parse(strings.TrimSpace(s.keycloakConfig().RedirectURI)); err == nil && redirect.Scheme != "" && redirect.Host != "" {
		return redirect.Scheme + "://" + redirect.Host + "/mcp"
	}
	return requestOrigin(r) + "/mcp"
}

// mcpOAuthMetadataURL is where a refused client is sent to learn the above:
// the resource identifier with the RFC 9728 well-known prefix inserted before
// its path.
func mcpOAuthMetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(resource, "/") + mcpOAuthMetadataPath
	}
	return u.Scheme + "://" + u.Host + mcpOAuthMetadataPath + strings.TrimRight(u.Path, "/")
}

// mcpOAuthAcceptedAudiences is every aud value that means "this token is for
// this server": the resource identifier, and — because one identifier covers
// both MCP endpoints — the endpoint URLs beneath it.
func mcpOAuthAcceptedAudiences(resource string) []string {
	accepted := []string{resource}
	if strings.HasSuffix(resource, "/mcp") {
		accepted = append(accepted, resource+"/gateway")
	}
	return accepted
}

// handleMCPOAuthMetadata is RFC 9728: the document a refused MCP client reads
// to find the authorization server. Public by design — it says where to sign
// in, not who is signed in — and served as the bare document, not the
// product's error envelope, because the reader is an OAuth client library.
// GET /.well-known/oauth-protected-resource[/mcp[/gateway]]
func (s *Server) handleMCPOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, mcpOAuthMetadataPath)
	if suffix != "" && !mcpOAuthPath(suffix) {
		http.NotFound(w, r)
		return
	}
	settings := s.mcpOAuthSettings(r.Context())
	if !settings.active() {
		writeOpenAIError(w, http.StatusNotFound, "이 서버의 MCP 는 SSO 액세스 토큰을 받지 않습니다. 개인 proxy key 를 사용하세요.", "invalid_request_error", "mcp_oauth_disabled")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 s.mcpOAuthResource(r, settings),
		"authorization_servers":    []string{settings.Issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         settings.Scopes,
		"resource_name":            "Clustara MCP",
	})
}

// mcpOAuthChallenge is the header that turns an MCP 401 into an invitation: the
// client reads resource_metadata and starts the OAuth flow from there. Without
// it a refusal is a dead end. Attached on the MCP endpoints only — a REST 401
// carrying it would send browsers and SDKs somewhere they cannot follow.
func (s *Server) mcpOAuthChallenge(w http.ResponseWriter, r *http.Request, tokenPresented bool) {
	settings := s.mcpOAuthSettings(r.Context())
	if !settings.active() {
		return
	}
	challenge := fmt.Sprintf(`Bearer realm="Clustara", resource_metadata=%q`, mcpOAuthMetadataURL(s.mcpOAuthResource(r, settings)))
	if tokenPresented {
		challenge += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
}

// writeMCPUnauthorized is the one refusal both MCP endpoints send: the challenge
// header when SSO is on, and the reason an SSO token was refused when there was
// one — the operator fixes the configuration from that message alone.
func (s *Server) writeMCPUnauthorized(w http.ResponseWriter, r *http.Request) {
	s.mcpOAuthChallenge(w, r, bearerToken(r.Header.Get("Authorization")) != "")
	if refusal, ok := mcpOAuthRefusalFromRequest(r); ok {
		writeOpenAIError(w, http.StatusUnauthorized, refusal.message, "invalid_request_error", refusal.code)
		return
	}
	writeOpenAIError(w, http.StatusUnauthorized, "invalid proxy API key", "invalid_request_error", "invalid_api_key")
}

// mcpOAuthRefusal is why a bearer that looked like an SSO token was not one we
// accept. The code is what the audit log keeps; the message is what the client
// shows the person.
type mcpOAuthRefusal struct {
	code    string
	message string
}

func (e mcpOAuthRefusal) Error() string { return e.code + ": " + e.message }

type mcpOAuthRefusalContextKey struct{}

func rememberMCPOAuthRefusal(r *http.Request, refusal mcpOAuthRefusal) {
	*r = *r.WithContext(context.WithValue(r.Context(), mcpOAuthRefusalContextKey{}, refusal))
}

func mcpOAuthRefusalFromRequest(r *http.Request) (mcpOAuthRefusal, bool) {
	refusal, ok := r.Context().Value(mcpOAuthRefusalContextKey{}).(mcpOAuthRefusal)
	return refusal, ok
}

// looksLikeJWT is the cheap shape test that separates "not a key" from "a token
// of a kind we might accept": three non-empty dot-separated segments. A proxy
// key never has that shape, so a bearer that fails the key lookup and passes
// this test is the only thing worth the network round trip to Keycloak.
func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

// mcpOAuthPrincipal turns a bearer access token into the auth context a proxy
// key would have produced for the same account, or says exactly why it will
// not. The caller has already established that the bearer is not a key.
func (s *Server) mcpOAuthPrincipal(r *http.Request, token string) (string, *store.AuthContext, error) {
	ctx := r.Context()
	settings := s.mcpOAuthSettings(ctx)
	if !settings.active() {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_disabled", "이 서버는 SSO 액세스 토큰을 받지 않습니다. 개인 proxy key 를 쓰거나, 관리자가 SSO 설정에서 MCP SSO(OAuth) 인증을 켜야 합니다."}
	}
	disc, err := keycloakDiscover(ctx, settings.Issuer)
	if err != nil {
		slog.Warn("mcp oauth discovery failed", "issuer", settings.Issuer, "error", err)
		return "", nil, mcpOAuthRefusal{"mcp_oauth_discovery_failed", "Keycloak 발급자 정보를 읽지 못해 SSO 토큰을 확인할 수 없습니다. 잠시 후 다시 시도하거나 관리자에게 알리세요."}
	}
	// Signature (JWKS, RS256 only — the header alg is checked before any key is
	// consulted, so HS256 and none never reach a verifier), issuer and expiry.
	claims, err := s.keycloakVerifyJWT(ctx, disc, token)
	if err != nil {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_invalid_token", "SSO 액세스 토큰이 유효하지 않습니다(서명·발급자·만료: " + err.Error() + "). 클라이언트에서 다시 로그인하세요."}
	}
	if nbf, ok := claims["nbf"].(float64); ok && time.Now().Add(60*time.Second).Before(time.Unix(int64(nbf), 0)) {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_invalid_token", "SSO 액세스 토큰이 아직 유효하지 않습니다(nbf). 서버 시계를 확인하세요."}
	}
	// An ID token proves a sign-in happened; it is not a credential for an API.
	// Keycloak tells the two apart with the typ claim ("Bearer" vs "ID").
	if strings.EqualFold(strClaim(claims, "typ"), "ID") {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_id_token", "ID 토큰은 로그인 증거이지 API 자격이 아닙니다. 액세스 토큰을 보내세요."}
	}
	// A cnf claim binds the token to a key (DPoP, mTLS) this server cannot
	// verify; accepting it as a plain bearer would drop the binding silently.
	if _, bound := claims["cnf"]; bound {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_bound_token", "소지자 증명(cnf: DPoP·mTLS)이 묶인 토큰은 이 서버가 검증할 수 없어 받지 않습니다."}
	}
	sub := strings.TrimSpace(strClaim(claims, "sub"))
	if sub == "" {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_invalid_token", "SSO 액세스 토큰에 sub 가 없습니다."}
	}
	// Whom the token was minted for. Measured against a real Keycloak 26: an
	// access token issued to a client carries that client in azp and
	// aud: ["account"] — the client id is not in aud. So the binding is "aud
	// names this resource, or aud/azp names something the administrator
	// listed". Either is the token being for this deployment rather than
	// passed through from another application in the realm, which is what
	// RFC 8707 and the MCP specification guard against.
	resource := s.mcpOAuthResource(r, settings)
	aud := claimAudience(claims["aud"])
	azp := strClaim(claims, "azp")
	if !mcpOAuthAudienceAccepted(aud, azp, resource, settings.Audiences) {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_audience", fmt.Sprintf(
			"SSO 토큰이 이 서버를 위해 발급된 것이 아닙니다(aud=%v, azp=%q). 관리자가 mcp.oauth.audience 에 %q 를 더하거나, Keycloak 클라이언트의 Audience 매퍼에 %q 를 넣으세요.",
			aud, azp, firstNonEmpty(azp, "<client id>"), resource)}
	}
	// The same account the web sign-in would land on, without the provisioning
	// half: the linked identity first, then the account whose email the token
	// names. A token is not the moment to decide who somebody is.
	user, found := s.mcpOAuthAccount(ctx, settings.Issuer, sub, strings.TrimSpace(strClaim(claims, "email")))
	if !found {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_unknown_account", "이 SSO 계정은 Clustara 에 등록되지 않았습니다. 먼저 웹으로 한 번 로그인하세요."}
	}
	if authUserDisabled(user) || user.MustChangePassword {
		return "", nil, mcpOAuthRefusal{"mcp_oauth_account_inactive", "이 SSO 계정은 Clustara 에서 비활성 상태입니다. 관리자에게 문의하세요."}
	}
	// Scopes: the administrator's ceiling, never wider than the account's own
	// role (what a key minted by this person would carry), and narrowed again
	// by the token's scope claim when it speaks Clustara's vocabulary.
	scopes := intersectScopes(settings.Scopes, s.effectiveScopesForRole(ctx, user.Role))
	if spoken := tokenScopesInVocabulary(strClaim(claims, "scope")); len(spoken) > 0 {
		scopes = intersectScopes(scopes, spoken)
	}
	teamID, _ := s.db.PrimaryTeamForUser(ctx, user.ID)
	authCtx := &store.AuthContext{UserID: user.ID, TeamID: teamID, Role: user.Role, Scopes: scopes}
	s.enrichAuthContextTeam(ctx, authCtx)
	return "sso:" + user.ID, authCtx, nil
}

// mcpOAuthAccount finds the registered account for a token: by linked SSO
// subject first (what the web sign-in wrote), then by the email the token
// carries (the same merge rule the web sign-in applies), and never by
// creating one.
func (s *Server) mcpOAuthAccount(ctx context.Context, issuer, sub, email string) (store.AuthUser, bool) {
	if id, found, _ := s.db.AuthIdentityBySubject(ctx, "keycloak", issuer, sub); found {
		if user, ok, _ := s.db.AuthUserByID(ctx, id.UserID); ok {
			return user, true
		}
	}
	if email != "" {
		if user, found, _ := s.db.AuthUserByEmail(ctx, email); found {
			return user, true
		}
	}
	return store.AuthUser{}, false
}

// mcpOAuthAudienceAccepted is the RFC 8707 check with the Keycloak reality
// folded in: aud may name the resource; aud or azp may name something the
// administrator listed.
func mcpOAuthAudienceAccepted(aud []string, azp, resource string, listed []string) bool {
	for _, accepted := range mcpOAuthAcceptedAudiences(resource) {
		if hasScope(aud, accepted) {
			return true
		}
	}
	for _, value := range listed {
		if value == "" {
			continue
		}
		if hasScope(aud, value) || (azp != "" && azp == value) {
			return true
		}
	}
	return false
}

// claimAudience reads aud, which JWT allows as a string or an array.
func claimAudience(v any) []string {
	switch aud := v.(type) {
	case string:
		if aud == "" {
			return nil
		}
		return []string{aud}
	case []any:
		return toStringSlice(aud)
	}
	return nil
}

// tokenScopesInVocabulary keeps the entries of a space-separated scope claim
// that are Clustara scopes. OAuth scopes like openid or profile say nothing
// about what the token may do here and are ignored rather than treated as
// "nothing".
func tokenScopesInVocabulary(scope string) []string {
	var spoken []string
	for _, entry := range strings.Fields(scope) {
		if hasScope(allScopes, entry) {
			spoken = append(spoken, entry)
		}
	}
	return spoken
}

// validateMCPOAuthScopes is the settings validator: every entry must be a
// scope this build enforces, so a typo cannot silently grant nothing.
func validateMCPOAuthScopes(v string) error {
	for _, entry := range strings.Fields(v) {
		if !hasScope(allScopes, entry) {
			return fmt.Errorf("unknown scope %q", entry)
		}
	}
	return nil
}
