package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"clustara/internal/store"
)

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var p struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(p.Email))
	if retryAfter, throttled := s.loginThrottled(r, email); throttled {
		_ = s.db.InsertLoginAttempt(r.Context(), email, false, clientIP(r), r.UserAgent(), "throttled")
		_ = s.db.InsertAuditEvent(r.Context(), store.AuthEvent{ID: newID("ae"), EventType: "login_throttled", IP: clientIP(r), UserAgent: r.UserAgent(), Detail: email, CreatedAt: time.Now().UTC()})
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeOpenAIError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later", "rate_limit_error", "login_throttled")
		return
	}
	user, found, err := s.db.AuthUserByEmail(r.Context(), email)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "login_failed")
		return
	}
	if !found || user.Status != "active" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(p.Password)) != nil {
		_ = s.db.InsertLoginAttempt(r.Context(), email, false, clientIP(r), r.UserAgent(), "invalid_credentials")
		_ = s.db.InsertAuditEvent(r.Context(), store.AuthEvent{ID: newID("ae"), EventType: "login_failed", IP: clientIP(r), UserAgent: r.UserAgent(), Detail: email, CreatedAt: time.Now().UTC()})
		writeOpenAIError(w, http.StatusUnauthorized, "invalid email or password", "invalid_request_error", "invalid_credentials")
		return
	}
	if !s.enforceAdminLoginIP(w, r, user) {
		return
	}
	teamID, _ := s.db.PrimaryTeamForUser(r.Context(), user.ID)
	tokens, err := s.issueTokenPair(r.Context(), user, teamID, clientIP(r), r.UserAgent())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "login_failed")
		return
	}
	_ = s.db.InsertLoginAttempt(r.Context(), email, true, clientIP(r), r.UserAgent(), "")
	_ = s.db.InsertAuditEvent(r.Context(), store.AuthEvent{ID: newID("ae"), EventType: "login_success", ActorUserID: user.ID, TeamID: teamID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusOK, tokens)
}

// loginThrottled reports whether this login attempt should be rejected before the
// password is even checked, and how long to advise waiting.
//
// This deliberately fails open. Every other "cannot verify" gate in the gateway
// blocks, because there the unverified thing was a destructive action. Here the
// actual access control is the bcrypt comparison, which still has to pass;
// throttling is defence in depth against guessing. Refusing every login because
// the attempt table is unreadable would lock operators out of the system during
// exactly the incident they need it for.
func (s *Server) loginThrottled(r *http.Request, email string) (retryAfterSeconds int, throttled bool) {
	cfg := s.cfg.Auth
	window := cfg.LoginThrottleWindow
	if window <= 0 || s.db == nil {
		return 0, false
	}
	byIP, byUser, err := s.db.LoginFailureCounts(r.Context(), email, clientIP(r), time.Now().UTC().Add(-window))
	if err != nil {
		slog.Warn("login throttle check failed; allowing the attempt to proceed to password verification", "error", err)
		return 0, false
	}
	if cfg.LoginThrottleMaxPerIP > 0 && byIP >= cfg.LoginThrottleMaxPerIP {
		return int(window.Seconds()), true
	}
	if cfg.LoginThrottleMaxPerUser > 0 && byUser >= cfg.LoginThrottleMaxPerUser {
		return int(window.Seconds()), true
	}
	return 0, false
}

func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var p struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	out, err := s.rotateRefreshToken(r.Context(), strings.TrimSpace(p.RefreshToken), clientIP(r), r.UserAgent())
	if err != nil {
		_ = s.db.InsertAuditEvent(r.Context(), store.AuthEvent{ID: newID("ae"), EventType: "login_failed", IP: clientIP(r), UserAgent: r.UserAgent(), Detail: "refresh: " + err.Error(), CreatedAt: time.Now().UTC()})
		writeOpenAIError(w, http.StatusUnauthorized, "invalid refresh token", "invalid_request_error", "invalid_refresh_token")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if claims, ok := s.verifyAccessToken(r.Context(), bearerToken(r.Header.Get("Authorization"))); ok {
		_ = s.db.RevokeAuthSession(r.Context(), claims.SessionID)
	}
	var p struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	if p.RefreshToken != "" {
		if rec, found, _ := s.db.RefreshTokenByHash(r.Context(), hashProxyKey(p.RefreshToken)); found {
			_ = s.db.RevokeRefreshToken(r.Context(), rec.ID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.cfg.Auth.Enabled {
		role, scopes, authenticated := s.legacyTokenIdentity(r)
		out := map[string]any{
			"auth_enabled": false, "version": AppVersion, "authenticated": authenticated,
			"legacy_token_required": s.cfg.Auth.AdminToken != "" || s.cfg.Auth.AdminReadonlyToken != "",
			"menu_version":          menuVersion,
		}
		if authenticated {
			out["user"] = map[string]any{"id": "legacy-token", "email": "", "role": role, "roles": []string{role}, "scopes": scopes, "features": s.featureFlags(), "default_home": resolveHome(role, scopes)}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	claims, ok := s.verifyAccessToken(r.Context(), bearerToken(r.Header.Get("Authorization")))
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid access token", "invalid_request_error", "invalid_access_token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_enabled": true,
		"version":      AppVersion,
		"expires_at":   claims.ExpiresAt, // unix seconds; the access token's expiry
		"menu_version": menuVersion,
		"user": map[string]any{
			"id": claims.Subject, "email": claims.Email, "role": claims.Role,
			"roles":                    []string{claims.Role},
			"team_id":                  claims.TeamID,
			"cost_center":              "",
			"scopes":                   claims.Scopes,
			"features":                 s.featureFlags(),
			"default_home":             resolveHome(claims.Role, claims.Scopes),
			"password_change_required": claims.PasswordChangeRequired,
		},
	})
}

func (s *Server) handleAuthAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	events, err := s.db.ListAuditEvents(r.Context(), recentLimit(r))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "auth_events_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}
