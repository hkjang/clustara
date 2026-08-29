package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"clustara/internal/config"
	"clustara/internal/secret"
)

// handleSecretsRotate re-encrypts every secret column in the database from the
// current GATEWAY_SECRET to a new one, then atomically swaps the in-process
// cipher so subsequent Encrypt/Decrypt calls use the new key — all without a
// restart.
//
// POST /admin/secrets/rotate
//
//	{"new_secret": "<64-hex-char passphrase>"}
//
// Workflow (safe GATEWAY_SECRET rotation):
//  1. Call this endpoint while the container is running with the OLD secret.
//  2. On success the DB is fully re-encrypted and the process now uses the new
//     cipher. Note the returned `rotated` counts.
//  3. Restart the container with GATEWAY_SECRET=<new_secret> so the next
//     process startup also builds the correct cipher from the env variable.
//
// The operation is atomic at the DB layer (single transaction) and the cipher
// pointer is swapped only after a successful commit, so no request window sees
// a half-rotated state.
func (s *Server) handleSecretsRotate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}

	var p struct {
		NewSecret string `json:"new_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	p.NewSecret = strings.TrimSpace(p.NewSecret)
	if p.NewSecret == "" {
		writeOpenAIError(w, http.StatusBadRequest, "new_secret is required", "invalid_request_error", "missing_field")
		return
	}
	if len(p.NewSecret) < 16 {
		writeOpenAIError(w, http.StatusBadRequest, "new_secret must be at least 16 characters", "invalid_request_error", "weak_secret")
		return
	}
	if p.NewSecret == config.DefaultGatewaySecret {
		writeOpenAIError(w, http.StatusBadRequest, "new_secret must not be the default development value", "invalid_request_error", "dev_secret_rejected")
		return
	}

	// Prevent concurrent rotations.
	if !s.secretsMu.TryLock() {
		writeOpenAIError(w, http.StatusConflict, "rotation already in progress", "invalid_request_error", "rotation_in_progress")
		return
	}
	defer s.secretsMu.Unlock()

	oldCipher := s.secrets.Load()
	newCipher, err := secret.New(p.NewSecret)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "failed to create new cipher: "+err.Error(), "server_error", "cipher_init_failed")
		return
	}

	counts, err := s.db.RotateEncryptedColumns(
		r.Context(),
		oldCipher.Decrypt,
		newCipher.Encrypt,
	)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "rotation failed: "+err.Error(), "server_error", "rotation_failed")
		return
	}

	// DB commit succeeded — swap the in-process cipher atomically.
	s.secrets.Store(newCipher)

	s.auditAdmin(r, "secrets.rotate", "", auditJSON(map[string]any{"rotated": counts}))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"rotated": counts,
		"note":    "재시작 시 GATEWAY_SECRET 환경변수를 new_secret 값으로 설정하세요.",
		// The rotated counts cover encrypted DB columns. Agent tokens are HMACs keyed by
		// GATEWAY_SECRET, not ciphertext, so they cannot be re-signed here — and because this
		// endpoint swaps the cipher but not cfg.Secret.GatewaySecret, they keep verifying until
		// the restart and then all fail at once, far from the action that caused it.
		"agent_tokens": "에이전트 토큰은 GATEWAY_SECRET 으로 서명되므로 재암호화 대상이 아닙니다. " +
			"재시작 이후 기존 토큰이 모두 무효가 되니, 각 클러스터의 install-manifest 를 다시 생성해 에이전트를 재배포하세요. " +
			"특정 클러스터의 토큰만 즉시 폐기하려면 POST /admin/k8s/agent/revoke-tokens?cluster_id= 를 쓰세요.",
	})
}
