package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func passwordPolicyError(password string) error {
	if len(password) < 12 || len(password) > 128 {
		return fmt.Errorf("비밀번호는 12~128자여야 합니다")
	}
	classes := 0
	var lower, upper, digit, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	for _, ok := range []bool{lower, upper, digit, symbol} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return fmt.Errorf("영문 대/소문자, 숫자, 특수문자 중 3종 이상을 사용해야 합니다")
	}
	for _, weak := range []string{"password", "qwerty", "12345678", "clustara"} {
		if strings.Contains(strings.ToLower(password), weak) {
			return fmt.Errorf("쉽게 추측할 수 있는 문자열을 사용할 수 없습니다")
		}
	}
	return nil
}

// POST /auth/password/change changes the caller's own local password. Every active session is
// revoked, including the current one, so a token minted before the credential change cannot live
// past it. The caller signs in again with the new password.
func (s *Server) handleAuthPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	claims, ok := s.currentAccessClaims(r)
	if !ok || claims.Subject == "" {
		writeOpenAIError(w, http.StatusUnauthorized, "login is required", "authentication_error", "authentication_required")
		return
	}
	var payload struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	user, found, err := s.db.AuthUserByID(r.Context(), claims.Subject)
	if err != nil || !found {
		writeOpenAIError(w, http.StatusNotFound, "user not found", "invalid_request_error", "user_not_found")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.CurrentPassword)) != nil {
		s.auditAuthEvent(r.Context(), "password_change_failed", claims.Subject, "", claims.TeamID, "current password mismatch")
		writeOpenAIError(w, http.StatusBadRequest, "현재 비밀번호가 올바르지 않습니다", "invalid_request_error", "current_password_invalid")
		return
	}
	if payload.CurrentPassword == payload.NewPassword {
		writeOpenAIError(w, http.StatusBadRequest, "새 비밀번호는 현재 비밀번호와 달라야 합니다", "invalid_request_error", "password_reuse")
		return
	}
	if err := passwordPolicyError(payload.NewPassword); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "password_policy_failed")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), bcrypt.DefaultCost)
	if err != nil || s.db.UpdateAuthUserPassword(r.Context(), user.ID, string(hash), false) != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "비밀번호를 변경하지 못했습니다", "server_error", "password_change_failed")
		return
	}
	_ = s.db.RevokeAuthSessionsForUser(r.Context(), user.ID)
	s.auditAuthEvent(r.Context(), "password_changed", user.ID, "", claims.TeamID, "self-service; all sessions revoked")
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "reauthentication_required": true, "sessions_revoked": true})
}

// POST /admin/users/{id}/password-reset {temporary_password}. Full administrators only. The
// temporary password is never returned or logged and must be replaced on the next login.
func (s *Server) handleAdminUserPasswordReset(w http.ResponseWriter, r *http.Request, userID string) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if claims, ok := s.currentAccessClaims(r); ok && claims.Role != "super_admin" && claims.Role != "admin" {
		writeOpenAIError(w, http.StatusForbidden, "full administrator role is required", "permission_error", "password_reset_denied")
		return
	}
	user, found, err := s.db.AuthUserByID(r.Context(), userID)
	if err != nil || !found {
		writeOpenAIError(w, http.StatusNotFound, "user not found", "invalid_request_error", "user_not_found")
		return
	}
	if !s.canModifySubjectRole(r, user.Role) {
		writeOpenAIError(w, http.StatusForbidden, "cannot reset a user at or above your role", "permission_error", "role_escalation_denied")
		return
	}
	var payload struct {
		TemporaryPassword string `json:"temporary_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if err := passwordPolicyError(payload.TemporaryPassword); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "password_policy_failed")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.TemporaryPassword), bcrypt.DefaultCost)
	if err != nil || s.db.UpdateAuthUserPassword(r.Context(), user.ID, string(hash), true) != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "비밀번호를 초기화하지 못했습니다", "server_error", "password_reset_failed")
		return
	}
	_ = s.db.RevokeAuthSessionsForUser(r.Context(), user.ID)
	s.auditAdmin(r, "auth_user.password_reset", user.ID, auditJSON(map[string]any{"must_change_password": true, "sessions_revoked": true}))
	s.auditAuthEvent(r.Context(), "password_reset", user.ID, "", "", "administrator reset; all sessions revoked")
	writeJSON(w, http.StatusOK, map[string]any{"reset": true, "must_change_password": true, "sessions_revoked": true})
}

// withPasswordChangeGate restricts reset accounts to the credential-change flow until the
// temporary password has been replaced.
func (s *Server) withPasswordChangeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := s.currentAccessClaims(r)
		if !ok || !claims.PasswordChangeRequired {
			next.ServeHTTP(w, r)
			return
		}
		allowed := r.URL.Path == "/auth/password/change" || r.URL.Path == "/auth/logout" || r.URL.Path == "/auth/me" || r.URL.Path == "/me/navigation" || r.URL.Path == "/admin" || r.URL.Path == "/admin/"
		if allowed {
			next.ServeHTTP(w, r)
			return
		}
		writeOpenAIError(w, http.StatusForbidden, "비밀번호를 먼저 변경해야 합니다", "permission_error", "password_change_required")
	})
}
