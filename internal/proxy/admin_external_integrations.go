package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/gitprovider"
	"clustara/internal/harbor"
	"clustara/internal/store"
)

const externalCredentialKind = "external_credential"

type externalCredentialInput struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Provider    string         `json:"provider"`
	BaseURL     string         `json:"base_url"`
	Username    string         `json:"username"`
	Secret      string         `json:"secret"`
	AuthType    string         `json:"auth_type"`
	Status      string         `json:"status"`
	Description string         `json:"description"`
	Metadata    map[string]any `json:"metadata"`
}

type resolvedExternalCredential struct {
	Record   store.EnterpriseRecord
	Provider string
	BaseURL  string
	Username string
	Secret   string
	AuthType string
}

func (s *Server) handleExternalCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		records, err := s.listExternalCredentials(r)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credentials_failed")
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, externalCredentialKind, adminID(r), map[string]any{
			"credentials": records,
			"count":       len(records),
			"note":        "Secrets are encrypted at rest and never returned. Credentials are scoped to the current admin/user.",
		}))
	case http.MethodPost:
		rec, ok := s.decodeExternalCredential(w, r, "")
		if !ok {
			return
		}
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_save_failed")
			return
		}
		s.auditAdmin(r, "external_credential.upsert", rec.ID, auditJSON(scrubExternalCredential(rec)))
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, externalCredentialKind, rec.ID, map[string]any{"credential": scrubExternalCredential(rec)}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleExternalCredentialByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	tail := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/external-integrations/credentials/"), "/")
	if tail == "" {
		writeOpenAIError(w, http.StatusBadRequest, "credential id is required", "invalid_request_error", "external_credential_id_required")
		return
	}
	parts := strings.Split(tail, "/")
	id := strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		if parts[1] == "test" {
			s.handleExternalCredentialTest(w, r, id)
			return
		}
		writeOpenAIError(w, http.StatusNotFound, "unknown credential subresource", "invalid_request_error", "external_credential_subresource_not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rec, ok, err := s.findExternalCredentialRecord(r, id)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_lookup_failed")
			return
		}
		if !ok {
			writeOpenAIError(w, http.StatusNotFound, "credential not found", "invalid_request_error", "external_credential_not_found")
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, externalCredentialKind, id, map[string]any{"credential": scrubExternalCredential(rec)}))
	case http.MethodPost, http.MethodPut:
		rec, ok := s.decodeExternalCredential(w, r, id)
		if !ok {
			return
		}
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_update_failed")
			return
		}
		s.auditAdmin(r, "external_credential.update", rec.ID, auditJSON(scrubExternalCredential(rec)))
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, externalCredentialKind, rec.ID, map[string]any{"credential": scrubExternalCredential(rec)}))
	case http.MethodDelete:
		rec, ok, err := s.findExternalCredentialRecord(r, id)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_lookup_failed")
			return
		}
		if !ok {
			writeOpenAIError(w, http.StatusNotFound, "credential not found", "invalid_request_error", "external_credential_not_found")
			return
		}
		rec.Status = "archived"
		rec.Payload["archived_at"] = time.Now().UTC().Format(time.RFC3339)
		rec.Payload["archived_by"] = adminID(r)
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_archive_failed")
			return
		}
		s.auditAdmin(r, "external_credential.archive", rec.ID, auditJSON(scrubExternalCredential(rec)))
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, externalCredentialKind, rec.ID, map[string]any{"credential": scrubExternalCredential(rec)}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleExternalCredentialTest(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	cred, ok, err := s.resolveExternalCredential(r, id, "")
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_decrypt_failed")
		return
	}
	if !ok {
		writeOpenAIError(w, http.StatusNotFound, "credential not found", "invalid_request_error", "external_credential_not_found")
		return
	}
	result := map[string]any{"ok": false, "provider": cred.Provider, "base_url": cred.BaseURL, "tested_at": time.Now().UTC().Format(time.RFC3339), "secret_policy": "decrypted_in_memory_only"}
	switch normalizeExternalProvider(cred.Provider) {
	case "gitlab", "bitbucket_server":
		gitResult := gitprovider.Test(r.Context(), gitProviderHTTPClient(), gitprovider.Config{
			Provider: cred.Provider,
			BaseURL:  cred.BaseURL,
			Username: cred.Username,
			Token:    cred.Secret,
		})
		result["ok"] = gitResult.OK
		result["status_code"] = gitResult.StatusCode
		result["request_path"] = gitResult.RequestPath
		result["error"] = gitResult.Error
	case "harbor", "harbor_robot":
		if normalizeExternalProvider(cred.Provider) == "harbor_robot" && strings.TrimSpace(cred.Username) != "" && strings.TrimSpace(toString(cred.Record.Payload["default_project"])) != "" {
			harborResult := harbor.CheckRobotPull(r.Context(), &http.Client{Timeout: 8 * time.Second}, cred.BaseURL, cred.Username, cred.Secret, toString(cred.Record.Payload["default_project"]))
			result["ok"] = harborResult.OK
			result["status_code"] = harborResult.StatusCode
			result["error"] = harborResult.Error
		} else {
			harborResult := harbor.CheckSystemInfo(r.Context(), &http.Client{Timeout: 8 * time.Second}, cred.BaseURL)
			result["ok"] = harborResult.OK
			result["status_code"] = harborResult.StatusCode
			result["version"] = harborResult.Version
			result["error"] = harborResult.Error
		}
	default:
		result["error"] = "test is not implemented for provider " + cred.Provider
	}
	s.auditAdmin(r, "external_credential.test", id, auditJSON(map[string]any{"provider": cred.Provider, "ok": result["ok"]}))
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, externalCredentialKind, id, map[string]any{"result": result, "credential": scrubExternalCredential(cred.Record)}))
}

func (s *Server) decodeExternalCredential(w http.ResponseWriter, r *http.Request, forcedID string) (store.EnterpriseRecord, bool) {
	var in externalCredentialInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return store.EnterpriseRecord{}, false
	}
	if in.Metadata == nil {
		in.Metadata = map[string]any{}
	}
	if strings.TrimSpace(in.Provider) == "" || strings.TrimSpace(in.BaseURL) == "" || strings.TrimSpace(in.Name) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "name, provider and base_url are required", "invalid_request_error", "external_credential_missing_fields")
		return store.EnterpriseRecord{}, false
	}
	provider := normalizeExternalProvider(in.Provider)
	if provider == "" {
		writeOpenAIError(w, http.StatusBadRequest, "provider is required", "invalid_request_error", "external_credential_provider_required")
		return store.EnterpriseRecord{}, false
	}
	rec := store.EnterpriseRecord{}
	if forcedID != "" || strings.TrimSpace(in.ID) != "" {
		if existing, found, err := s.findExternalCredentialRecord(r, firstNonEmptyStr(forcedID, in.ID)); err == nil && found {
			rec = existing
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_lookup_failed")
			return store.EnterpriseRecord{}, false
		}
	}
	if rec.ID == "" {
		rec.ID = firstNonEmptyStr(strings.TrimSpace(in.ID), newID("extcred"))
	}
	rec.Kind = externalCredentialKind
	rec.ScopeType = "user"
	rec.ScopeID = adminID(r)
	rec.Name = strings.TrimSpace(in.Name)
	rec.Status = firstNonEmptyStr(strings.TrimSpace(in.Status), rec.Status, "active")
	rec.OwnerTeamID = ""
	rec.SourceRef = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	rec.CreatedBy = firstNonEmptyStr(rec.CreatedBy, adminID(r))
	if rec.EvidenceID == "" {
		rec.EvidenceID = "ev_" + audit.HashText(strings.Join([]string{externalCredentialKind, rec.ScopeID, provider, rec.SourceRef, time.Now().UTC().Format(time.RFC3339Nano)}, "|"))[:16]
	}
	if rec.Payload == nil {
		rec.Payload = map[string]any{}
	}
	for k, v := range in.Metadata {
		if strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "password") {
			continue
		}
		rec.Payload[k] = v
	}
	rec.Payload["provider"] = provider
	rec.Payload["base_url"] = rec.SourceRef
	rec.Payload["username"] = strings.TrimSpace(in.Username)
	rec.Payload["auth_type"] = firstNonEmptyStr(strings.TrimSpace(in.AuthType), "token")
	rec.Payload["description"] = strings.TrimSpace(in.Description)
	rec.Payload["secret_storage"] = "encrypted_per_user"
	rec.Payload["secret_configured"] = rec.Payload["encrypted_secret"] != nil && strings.TrimSpace(toString(rec.Payload["encrypted_secret"])) != ""
	if strings.TrimSpace(in.Secret) != "" {
		encrypted, err := s.secrets.Load().Encrypt(strings.TrimSpace(in.Secret))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "external_credential_encrypt_failed")
			return store.EnterpriseRecord{}, false
		}
		rec.Payload["encrypted_secret"] = encrypted
		rec.Payload["secret_hash"] = audit.HashText(strings.TrimSpace(in.Secret))[:16]
		rec.Payload["secret_configured"] = true
		rec.Payload["secret_updated_at"] = time.Now().UTC().Format(time.RFC3339)
	}
	rec.Payload["evidence_id"] = rec.EvidenceID
	return rec, true
}

func (s *Server) listExternalCredentials(r *http.Request) ([]store.EnterpriseRecord, error) {
	rows, err := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: externalCredentialKind, ScopeType: "user", ScopeID: adminID(r), Limit: intParam(r.URL.Query().Get("limit"), 500)})
	if err != nil {
		return nil, err
	}
	providers := splitCSVLower(r.URL.Query().Get("provider"))
	if len(providers) == 0 {
		providers = splitCSVLower(r.URL.Query().Get("providers"))
	}
	out := make([]store.EnterpriseRecord, 0, len(rows))
	for _, row := range rows {
		if strings.EqualFold(row.Status, "archived") && strings.TrimSpace(r.URL.Query().Get("status")) == "" {
			continue
		}
		if len(providers) > 0 && !containsString(providers, normalizeExternalProvider(toString(row.Payload["provider"]))) {
			continue
		}
		out = append(out, scrubExternalCredential(row))
	}
	return out, nil
}

func (s *Server) findExternalCredentialRecord(r *http.Request, id string) (store.EnterpriseRecord, bool, error) {
	rows, err := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: externalCredentialKind, ScopeType: "user", ScopeID: adminID(r), Limit: 1000})
	if err != nil {
		return store.EnterpriseRecord{}, false, err
	}
	for _, row := range rows {
		if row.ID == id {
			return row, true, nil
		}
	}
	return store.EnterpriseRecord{}, false, nil
}

func (s *Server) resolveExternalCredential(r *http.Request, id, providerHint string) (resolvedExternalCredential, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return resolvedExternalCredential{}, false, nil
	}
	rec, found, err := s.findExternalCredentialRecord(r, id)
	if err != nil {
		return resolvedExternalCredential{}, false, err
	}
	if !found {
		return resolvedExternalCredential{}, false, nil
	}
	if strings.EqualFold(rec.Status, "archived") {
		return resolvedExternalCredential{}, false, nil
	}
	provider := normalizeExternalProvider(toString(rec.Payload["provider"]))
	if providerHint != "" && provider != "" && provider != normalizeExternalProvider(providerHint) {
		return resolvedExternalCredential{}, false, errors.New("credential provider does not match requested provider")
	}
	encrypted := strings.TrimSpace(toString(rec.Payload["encrypted_secret"]))
	secretValue, err := s.secrets.Load().Decrypt(encrypted)
	if err != nil {
		return resolvedExternalCredential{}, false, err
	}
	return resolvedExternalCredential{
		Record:   rec,
		Provider: provider,
		BaseURL:  strings.TrimRight(firstNonEmptyStr(toString(rec.Payload["base_url"]), rec.SourceRef), "/"),
		Username: toString(rec.Payload["username"]),
		Secret:   secretValue,
		AuthType: toString(rec.Payload["auth_type"]),
	}, true, nil
}

func scrubExternalCredential(rec store.EnterpriseRecord) store.EnterpriseRecord {
	if rec.Payload == nil {
		rec.Payload = map[string]any{}
		return rec
	}
	out := map[string]any{}
	for k, v := range rec.Payload {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "encrypted") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "password") {
			if lk == "secret_configured" || lk == "secret_storage" || lk == "secret_updated_at" {
				out[k] = v
			}
			continue
		}
		out[k] = v
	}
	out["secret_configured"] = strings.TrimSpace(toString(rec.Payload["encrypted_secret"])) != ""
	out["secret_storage"] = "encrypted_per_user"
	rec.Payload = out
	return rec
}

func normalizeExternalProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "bitbucket", "bitbucket-server", "bitbucket_server", "stash":
		return "bitbucket_server"
	case "gitlab":
		return "gitlab"
	case "harbor", "harbor_registry":
		return "harbor"
	case "harbor_robot", "harbor-robot", "robot":
		return "harbor_robot"
	case "mattermost", "mattermost_webhook":
		return "mattermost"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func splitCSVLower(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		v := normalizeExternalProvider(p)
		if v != "" && !containsString(out, v) {
			out = append(out, v)
		}
	}
	return out
}
