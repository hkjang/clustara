package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/gitprovider"
	"clustara/internal/store"
)

type gitOpsProviderRequest struct {
	ProviderID   string `json:"provider_id"`
	Provider     string `json:"provider"`
	BaseURL      string `json:"base_url"`
	Username     string `json:"username"`
	Token        string `json:"token"`
	Target       string `json:"target"`
	Search       string `json:"search"`
	ProjectID    string `json:"project_id"`
	ProjectKey   string `json:"project_key"`
	RepoSlug     string `json:"repo_slug"`
	Branch       string `json:"branch"`
	Path         string `json:"path"`
	Limit        int    `json:"limit"`
	SourceBranch string `json:"source_branch"`
	TargetBranch string `json:"target_branch"`
	Title        string `json:"title"`
	Description  string `json:"description"`
}

func (s *Server) handleGitOpsProviders(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "gitops_provider")
		if !ok {
			return
		}
		filtered := make([]store.EnterpriseRecord, 0, len(rows))
		for _, row := range rows {
			if strings.EqualFold(row.Status, "archived") && strings.TrimSpace(r.URL.Query().Get("status")) == "" {
				continue
			}
			filtered = append(filtered, scrubGitOpsProviderRecord(row))
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_provider", "*", map[string]any{
			"providers": filtered,
			"count":     len(filtered),
			"note":      "GitLab and Bitbucket Server provider metadata. Tokens are transient and are never persisted.",
		}))
	case http.MethodPost:
		rec, ok := s.decodeGitOpsProviderRecord(w, r, "")
		if !ok {
			return
		}
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_provider_save_failed")
			return
		}
		s.auditAdmin(r, "gitops.provider.upsert", rec.ID, auditJSON(scrubGitOpsProviderRecord(rec)))
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "gitops_provider", rec.ID, map[string]any{"provider": scrubGitOpsProviderRecord(rec)}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGitOpsProviderItem(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	tail := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/gitops/providers/"), "/")
	if tail == "" {
		writeOpenAIError(w, http.StatusNotFound, "provider id is required", "invalid_request_error", "gitops_provider_id_required")
		return
	}
	parts := strings.Split(tail, "/")
	id := strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		switch parts[1] {
		case "test":
			s.handleGitOpsProviderTestWithID(w, r, id)
		case "catalog":
			s.handleGitOpsProviderCatalogWithID(w, r, id)
		case "pr-template":
			s.handleGitOpsProviderPRTemplateWithID(w, r, id)
		default:
			writeOpenAIError(w, http.StatusNotFound, "unknown provider subresource", "invalid_request_error", "gitops_provider_subresource_not_found")
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		rec, found, err := s.findGitOpsProvider(r, id)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_provider_lookup_failed")
			return
		}
		if !found {
			writeOpenAIError(w, http.StatusNotFound, "provider not found", "invalid_request_error", "gitops_provider_not_found")
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_provider", id, map[string]any{"provider": scrubGitOpsProviderRecord(rec)}))
	case http.MethodPost, http.MethodPut:
		rec, ok := s.decodeGitOpsProviderRecord(w, r, id)
		if !ok {
			return
		}
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_provider_update_failed")
			return
		}
		s.auditAdmin(r, "gitops.provider.update", rec.ID, auditJSON(scrubGitOpsProviderRecord(rec)))
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_provider", rec.ID, map[string]any{"provider": scrubGitOpsProviderRecord(rec)}))
	case http.MethodDelete:
		rec, found, err := s.findGitOpsProvider(r, id)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_provider_lookup_failed")
			return
		}
		if !found {
			writeOpenAIError(w, http.StatusNotFound, "provider not found", "invalid_request_error", "gitops_provider_not_found")
			return
		}
		rec.Status = "archived"
		rec.Payload["archived_at"] = time.Now().UTC().Format(time.RFC3339)
		rec.Payload["archived_by"] = adminID(r)
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_provider_archive_failed")
			return
		}
		s.auditAdmin(r, "gitops.provider.archive", rec.ID, auditJSON(scrubGitOpsProviderRecord(rec)))
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_provider", rec.ID, map[string]any{"provider": scrubGitOpsProviderRecord(rec)}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGitOpsProviderTest(w http.ResponseWriter, r *http.Request) {
	s.handleGitOpsProviderTestWithID(w, r, "")
}

func (s *Server) handleGitOpsProviderCatalog(w http.ResponseWriter, r *http.Request) {
	s.handleGitOpsProviderCatalogWithID(w, r, "")
}

func (s *Server) handleGitOpsProviderPRTemplate(w http.ResponseWriter, r *http.Request) {
	s.handleGitOpsProviderPRTemplateWithID(w, r, "")
}

func (s *Server) handleGitOpsProviderTestWithID(w http.ResponseWriter, r *http.Request, providerID string) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	in, ok := decodeGitOpsProviderRequest(w, r)
	if !ok {
		return
	}
	if providerID != "" {
		in.ProviderID = providerID
	}
	cfg, rec, ok := s.resolveGitOpsProvider(w, r, in)
	if !ok {
		return
	}
	result := gitprovider.Test(r.Context(), gitProviderHTTPClient(), cfg)
	s.auditAdmin(r, "gitops.provider.test", firstNonEmptyStr(in.ProviderID, cfg.BaseURL), auditJSON(map[string]any{
		"provider_id": rec.ID, "provider": cfg.Provider, "base_url": cfg.BaseURL, "ok": result.OK, "status_code": result.StatusCode, "token_supplied": in.Token != "",
	}))
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_provider", firstNonEmptyStr(rec.ID, cfg.BaseURL), map[string]any{"result": result, "provider": scrubGitOpsProviderRecord(rec)}))
}

func (s *Server) handleGitOpsProviderCatalogWithID(w http.ResponseWriter, r *http.Request, providerID string) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	in, ok := decodeGitOpsProviderRequest(w, r)
	if !ok {
		return
	}
	if providerID != "" {
		in.ProviderID = providerID
	}
	cfg, rec, ok := s.resolveGitOpsProvider(w, r, in)
	if !ok {
		return
	}
	q := gitprovider.Query{
		Config:     cfg,
		Target:     in.Target,
		Search:     in.Search,
		ProjectID:  in.ProjectID,
		ProjectKey: in.ProjectKey,
		RepoSlug:   in.RepoSlug,
		Branch:     in.Branch,
		Path:       in.Path,
		Limit:      in.Limit,
	}
	result := gitprovider.QueryCatalog(r.Context(), gitProviderHTTPClient(), q)
	s.auditAdmin(r, "gitops.provider.catalog", firstNonEmptyStr(in.ProviderID, cfg.BaseURL), auditJSON(map[string]any{
		"provider_id": rec.ID, "provider": cfg.Provider, "target": q.Target, "ok": result.OK, "items": len(result.Items), "token_supplied": in.Token != "",
	}))
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_provider", firstNonEmptyStr(rec.ID, cfg.BaseURL), map[string]any{"result": result, "provider": scrubGitOpsProviderRecord(rec)}))
}

func (s *Server) handleGitOpsProviderPRTemplateWithID(w http.ResponseWriter, r *http.Request, providerID string) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	in, ok := decodeGitOpsProviderRequest(w, r)
	if !ok {
		return
	}
	if providerID != "" {
		in.ProviderID = providerID
	}
	cfg, rec, ok := s.resolveGitOpsProvider(w, r, in)
	if !ok {
		return
	}
	result := gitprovider.BuildPRTemplate(gitprovider.PRTemplateInput{
		Config:       cfg,
		ProjectID:    in.ProjectID,
		ProjectKey:   in.ProjectKey,
		RepoSlug:     in.RepoSlug,
		SourceBranch: in.SourceBranch,
		TargetBranch: in.TargetBranch,
		Title:        in.Title,
		Description:  in.Description,
	})
	s.auditAdmin(r, "gitops.provider.pr_template", firstNonEmptyStr(in.ProviderID, cfg.BaseURL), auditJSON(map[string]any{
		"provider_id": rec.ID, "provider": cfg.Provider, "ok": result.OK, "template_only": true,
	}))
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_provider", firstNonEmptyStr(rec.ID, cfg.BaseURL), map[string]any{"result": result, "provider": scrubGitOpsProviderRecord(rec)}))
}

func (s *Server) decodeGitOpsProviderRecord(w http.ResponseWriter, r *http.Request, forcedID string) (store.EnterpriseRecord, bool) {
	var rec store.EnterpriseRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return store.EnterpriseRecord{}, false
	}
	if forcedID != "" {
		rec.ID = forcedID
	}
	rec.Kind = "gitops_provider"
	rec.Name = strings.TrimSpace(rec.Name)
	if rec.Payload == nil {
		rec.Payload = map[string]any{}
	}
	provider := normalizeGitOpsProvider(toString(rec.Payload["provider"]))
	baseURL := strings.TrimRight(strings.TrimSpace(toString(rec.Payload["base_url"])), "/")
	if provider == "" {
		provider = normalizeGitOpsProvider(rec.ScopeType)
	}
	if baseURL == "" {
		baseURL = strings.TrimRight(strings.TrimSpace(rec.SourceRef), "/")
	}
	if provider == "" {
		writeOpenAIError(w, http.StatusBadRequest, "provider is required", "invalid_request_error", "gitops_provider_required")
		return store.EnterpriseRecord{}, false
	}
	if baseURL == "" {
		writeOpenAIError(w, http.StatusBadRequest, "base_url is required", "invalid_request_error", "gitops_provider_base_url_required")
		return store.EnterpriseRecord{}, false
	}
	if rec.ID == "" {
		rec.ID = newID("gitprov")
	}
	if rec.Name == "" {
		rec.Name = provider + " " + baseURL
	}
	if rec.Status == "" {
		rec.Status = "active"
	}
	if rec.ScopeType == "" || rec.ScopeType == "gitlab" || rec.ScopeType == "bitbucket_server" {
		rec.ScopeType = "git_provider"
	}
	if rec.ScopeID == "" {
		rec.ScopeID = provider + ":" + baseURL
	}
	if rec.SourceRef == "" {
		rec.SourceRef = baseURL
	}
	if rec.CreatedBy == "" {
		rec.CreatedBy = adminID(r)
	}
	if rec.EvidenceID == "" {
		rec.EvidenceID = "ev_" + audit.HashText("gitops_provider|" + provider + "|" + baseURL + "|" + time.Now().UTC().Format(time.RFC3339Nano))[:16]
	}
	sanitizeGitOpsProviderPayload(rec.Payload, provider, baseURL)
	rec.Payload["evidence_id"] = rec.EvidenceID
	return rec, true
}

func decodeGitOpsProviderRequest(w http.ResponseWriter, r *http.Request) (gitOpsProviderRequest, bool) {
	var in gitOpsProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return gitOpsProviderRequest{}, false
	}
	return in, true
}

func (s *Server) resolveGitOpsProvider(w http.ResponseWriter, r *http.Request, in gitOpsProviderRequest) (gitprovider.Config, store.EnterpriseRecord, bool) {
	rec := store.EnterpriseRecord{ID: strings.TrimSpace(in.ProviderID), Payload: map[string]any{}}
	if strings.TrimSpace(in.ProviderID) != "" {
		found, ok, err := s.findGitOpsProvider(r, strings.TrimSpace(in.ProviderID))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_provider_lookup_failed")
			return gitprovider.Config{}, store.EnterpriseRecord{}, false
		}
		if !ok {
			writeOpenAIError(w, http.StatusNotFound, "provider not found", "invalid_request_error", "gitops_provider_not_found")
			return gitprovider.Config{}, store.EnterpriseRecord{}, false
		}
		rec = found
	}
	cfg := gitprovider.Config{
		Provider: normalizeGitOpsProvider(firstNonEmptyStr(in.Provider, toString(rec.Payload["provider"]))),
		BaseURL:  strings.TrimRight(firstNonEmptyStr(in.BaseURL, toString(rec.Payload["base_url"]), rec.SourceRef), "/"),
		Username: firstNonEmptyStr(in.Username, toString(rec.Payload["username"])),
		Token:    strings.TrimSpace(in.Token),
	}
	if cfg.Provider == "" {
		writeOpenAIError(w, http.StatusBadRequest, "provider is required", "invalid_request_error", "gitops_provider_required")
		return gitprovider.Config{}, store.EnterpriseRecord{}, false
	}
	if cfg.BaseURL == "" {
		writeOpenAIError(w, http.StatusBadRequest, "base_url is required", "invalid_request_error", "gitops_provider_base_url_required")
		return gitprovider.Config{}, store.EnterpriseRecord{}, false
	}
	return cfg, rec, true
}

func (s *Server) findGitOpsProvider(r *http.Request, id string) (store.EnterpriseRecord, bool, error) {
	rows, err := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: "gitops_provider", Limit: 1000})
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

func sanitizeGitOpsProviderPayload(payload map[string]any, provider, baseURL string) {
	token := firstNonEmptyStr(toString(payload["token"]), toString(payload["password"]), toString(payload["private_token"]), toString(payload["access_token"]))
	delete(payload, "token")
	delete(payload, "password")
	delete(payload, "private_token")
	delete(payload, "access_token")
	if token != "" {
		payload["token_hash"] = audit.HashText(token)[:16]
		payload["token_last_seen_at"] = time.Now().UTC().Format(time.RFC3339)
	}
	payload["token_storage"] = "transient_only"
	payload["token_required_for_catalog"] = true
	payload["provider"] = provider
	payload["base_url"] = baseURL
	payload["username"] = strings.TrimSpace(toString(payload["username"]))
	if payload["default_branch"] == nil || strings.TrimSpace(toString(payload["default_branch"])) == "" {
		payload["default_branch"] = "main"
	}
}

func scrubGitOpsProviderRecord(rec store.EnterpriseRecord) store.EnterpriseRecord {
	if rec.Payload == nil {
		rec.Payload = map[string]any{}
		return rec
	}
	out := map[string]any{}
	for k, v := range rec.Payload {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") && lk != "token_hash" && lk != "token_storage" && lk != "token_required_for_catalog" && lk != "token_last_seen_at" {
			continue
		}
		if strings.Contains(lk, "password") || strings.Contains(lk, "private") || strings.Contains(lk, "secret") {
			continue
		}
		out[k] = v
	}
	rec.Payload = out
	return rec
}

func normalizeGitOpsProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "bitbucket", "bitbucket-server", "bitbucket_server", "stash":
		return "bitbucket_server"
	case "gitlab":
		return "gitlab"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func gitProviderHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}
