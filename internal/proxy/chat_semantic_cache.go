package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/store"
)

// maxSemanticEmbedBytes bounds what the semantic cache will send to the embedding
// model. The prompt text was passed through at whatever size the request happened to
// be — a 2MB single-turn message produced a 2MB embedding request.
const maxSemanticEmbedBytes = 32 << 10

// semanticEmbedInputTooLarge reports whether a prompt is too big to be worth
// embedding for cache matching.
func semanticEmbedInputTooLarge(text string) bool {
	return len(text) > maxSemanticEmbedBytes
}

// chatPromptText extracts a flat text representation of a chat request's messages, used
// as the embedding input for semantic-cache matching.
func chatPromptText(body []byte) string {
	var root struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return ""
	}
	var b strings.Builder
	for _, m := range root.Messages {
		// content may be a string or an array of parts; handle the common string case
		// and fall back to the raw JSON for structured content.
		var str string
		if json.Unmarshal(m.Content, &str) == nil {
			b.WriteString(m.Role + ": " + str + "\n")
		} else {
			b.WriteString(m.Role + ": " + string(m.Content) + "\n")
		}
	}
	return strings.TrimSpace(b.String())
}

// chatIsSingleTurn reports whether the request is a fresh single-turn prompt — only system
// and user message(s), no prior assistant/tool turns and no tools declared. This is the only
// shape where a whole-conversation semantic match is both *likely* (the text is short and
// self-contained) and *safe*. Multi-turn agent conversations grow monotonically, so their
// full-text embedding almost never matches a stored entry, and a coincidental hit mid-thread
// could serve an answer for the wrong context. Such requests skip the embedding entirely.
func chatIsSingleTurn(body []byte) bool {
	var root struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return false
	}
	if len(root.Tools) > 0 && strings.TrimSpace(string(root.Tools)) != "null" {
		return false
	}
	users := 0
	for _, m := range root.Messages {
		switch strings.ToLower(strings.TrimSpace(m.Role)) {
		case "assistant", "tool", "function":
			return false
		case "user":
			users++
		}
	}
	return users >= 1
}

// embedText calls the configured embedding model (via the normal provider selection)
// to vectorize text. Best-effort with a short timeout; returns an error the caller
// treats as "no semantic cache for this request".
// embedSpend is what one semantic-cache embedding call actually cost. The call is made
// per eligible chat request, hit or miss, and until now it was invisible: the identical
// HTTP call made by a client against /v1/embeddings produces a request row with usage and
// cost, and made here it produced nothing at all. The cache's savings were reported while
// its running cost was not, so a semantic cache could cost more than it saved with no
// report able to show it.
type embedSpend struct {
	model     string
	provider  string
	status    int
	latencyMS int64
	usage     audit.Usage
	hasUsage  bool
	inputText string
	errText   string
}

func (s *Server) embedText(ctx context.Context, r *http.Request, model, text string) ([]float64, embedSpend, error) {
	spend := embedSpend{model: model, inputText: text}
	start := time.Now()
	defer func() { spend.latencyMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg := s.cacheConf()
	var baseURL, apiKey string
	if strings.TrimSpace(cfg.EmbeddingBaseURL) != "" {
		// Dedicated embedding endpoint (e.g. a local embedding server). Use its own key
		// when provided, else fall back to the default upstream provider's key.
		baseURL = cfg.EmbeddingBaseURL
		apiKey = cfg.EmbeddingAPIKey
		if strings.TrimSpace(apiKey) == "" {
			if provider, perr := s.selectProvider(ctx, r, model); perr == nil {
				apiKey = provider.APIKey
				spend.provider = provider.Name
			}
		}
	} else {
		// Optional provider override; empty → normal selection (model glob → default upstream).
		provider, err := s.selectProviderForced(ctx, r, model, strings.TrimSpace(cfg.EmbeddingProvider))
		if err != nil {
			spend.errText = err.Error()
			return nil, spend, err
		}
		baseURL, apiKey = provider.BaseURL, provider.APIKey
		spend.provider = provider.Name
	}
	upstreamURL, err := s.upstreamURL(baseURL, &url.URL{Path: "/v1/embeddings"})
	if err != nil {
		spend.errText = err.Error()
		return nil, spend, err
	}
	reqBody, _ := json.Marshal(map[string]any{"model": model, "input": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(reqBody))
	if err != nil {
		spend.errText = err.Error()
		return nil, spend, err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		spend.errText = err.Error()
		return nil, spend, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	spend.status = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, spend, &cacheEmbedError{status: resp.StatusCode}
	}
	var parsed struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		spend.errText = err.Error()
		return nil, spend, err
	}
	if parsed.Usage.TotalTokens > 0 || parsed.Usage.PromptTokens > 0 {
		spend.hasUsage = true
		spend.usage = audit.Usage{
			PromptTokens: parsed.Usage.PromptTokens,
			TotalTokens:  parsed.Usage.TotalTokens,
			Source:       "usage",
		}
		if spend.usage.TotalTokens == 0 {
			spend.usage.TotalTokens = spend.usage.PromptTokens
		}
	}
	if len(parsed.Data) == 0 || len(parsed.Data[0].Embedding) == 0 {
		return nil, spend, &cacheEmbedError{status: resp.StatusCode}
	}
	return parsed.Data[0].Embedding, spend, nil
}

// recordSemanticEmbedSpend logs the semantic cache's embedding call as its own request,
// carrying the triggering request's attribution (key, team tags, cost centre) so the spend
// lands on whoever caused it rather than on nobody. An upstream rejection is recorded as
// explicitly not billed, the same rule as the main path (v0.9.247).
func (s *Server) recordSemanticEmbedSpend(ctx context.Context, trigger store.RequestLog, spend embedSpend) {
	if strings.TrimSpace(spend.model) == "" {
		return
	}
	req := store.RequestLog{
		ID:          newID("req"),
		TraceID:     trigger.TraceID,
		APIKeyID:    trigger.APIKeyID,
		ClientIP:    trigger.ClientIP,
		Hostname:    trigger.Hostname,
		Model:       spend.model,
		Endpoint:    "/v1/embeddings",
		Provider:    firstNonEmpty(spend.provider, "cache-semantic"),
		StatusCode:  spend.status,
		LatencyMS:   spend.latencyMS,
		Error:       spend.errText,
		RouteReason: "cache-semantic-embed",
		Repo:        trigger.Repo,
		Branch:      trigger.Branch,
		Project:     trigger.Project,
		Service:     trigger.Service,
		CostCenter:  trigger.CostCenter,
		CreatedAt:   time.Now().UTC(),
	}
	record := store.LogRecord{Request: req}
	switch {
	case spend.status >= 400 || spend.status == 0:
		record.Usage = &store.TokenUsage{
			ID: newID("usage"), RequestID: req.ID, Currency: "KRW",
			Source: "not_billed", CreatedAt: time.Now().UTC(),
		}
	default:
		usage := spend.usage
		if !spend.hasUsage {
			tokens := audit.EstimateTokens(spend.inputText)
			usage = audit.Usage{PromptTokens: tokens, TotalTokens: tokens, Source: "estimated"}
		}
		record.Usage = &store.TokenUsage{
			ID: newID("usage"), RequestID: req.ID,
			PromptTokens:  usage.PromptTokens,
			TotalTokens:   usage.TotalTokens,
			EstimatedCost: audit.EstimateCostKRW(spend.model, usage, s.pricingMap(ctx)),
			Currency:      "KRW",
			Source:        usage.Source,
			CreatedAt:     time.Now().UTC(),
		}
	}
	s.enqueueDetached(record)
}

type cacheEmbedError struct{ status int }

func (e *cacheEmbedError) Error() string { return "embedding upstream failed" }

// semanticCacheScope resolves the pool a caller may read from and write to, and reports
// whether the semantic cache may be used at all.
//
// Under "team" or "key" a caller with no resolvable identity is excluded rather than pooled
// with everyone else: pooling unattributed callers together is exactly the shared pool the
// mode exists to prevent. Operators whose callers are all one tenant set "global"
// explicitly, which makes the sharing a stated choice rather than a default nobody picked.
func semanticCacheScope(mode string, auth *store.AuthContext) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "global":
		return "", true
	case "key":
		if auth == nil || strings.TrimSpace(auth.APIKeyID) == "" {
			return "", false
		}
		return "key:" + auth.APIKeyID, true
	default: // "team" and anything unset — the safe default
		if auth == nil {
			return "", false
		}
		if team := strings.TrimSpace(auth.TeamID); team != "" {
			return "team:" + team, true
		}
		// No team, but a known key still identifies one caller: scope to it rather than
		// falling back to the shared pool.
		if key := strings.TrimSpace(auth.APIKeyID); key != "" {
			return "key:" + key, true
		}
		return "", false
	}
}

// serveChatSemantic, on an exact-cache miss, embeds the prompt and looks for a
// semantically-near cached response. On a hit it writes the response and returns
// served=true. It always returns the computed query vector (when available) so the
// caller can store the eventual response under it. Any failure → (nil, false): the
// request proceeds normally.
func (s *Server) serveChatSemantic(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, meta store.LogRecord, traceID string, scope string) ([]float64, bool) {
	cfg := s.cacheConf()
	if !cfg.ChatSemanticEnabled || strings.TrimSpace(cfg.ChatSemanticModel) == "" {
		return nil, false
	}
	// Skip the embedding call for multi-turn / tool-using requests unless explicitly opted in:
	// their growing context makes a whole-prompt match unlikely (wasted embed) and unsafe.
	if !cfg.ChatSemanticMultiTurn && !chatIsSingleTurn(body) {
		return nil, false
	}
	text := chatPromptText(body)
	if text == "" {
		return nil, false
	}
	// Skip the embedding call for prompts too large to embed. Embedding models cap
	// their input well below this, so the call would cost a paid round trip and then
	// fail; and a prompt this size is not going to match a stored entry anyway.
	// Declining to use the cache is the correct outcome here — nothing is reported as
	// done, the request simply proceeds to the upstream unchanged.
	if semanticEmbedInputTooLarge(text) {
		return nil, false
	}
	vec, spend, err := s.embedText(ctx, r, cfg.ChatSemanticModel, text)
	// Recorded whether or not the embedding succeeded: a failing embedding endpoint still
	// costs a round trip, and a semantic cache quietly failing every lookup is worth seeing.
	s.recordSemanticEmbedSpend(ctx, meta.Request, spend)
	if err != nil {
		slog.Warn("semantic cache embed failed", "error", err)
		return nil, false
	}
	_, model, _ := chatCacheKey(body)
	hit, found, err := s.db.SearchChatSemantic(ctx, model, scope, vec, cfg.ChatSemanticThreshold, cfg.ChatSemanticMaxCandidates)
	if err != nil || !found {
		return vec, false
	}
	contentType := hit.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Cache", "HIT")
	w.Header().Set("X-Cache-Type", "chat-semantic")
	w.Header().Set("X-Request-ID", traceID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(hit.Body)

	s.metrics.IncCacheHit()
	s.metrics.IncRequest(false)
	meta.Request.Provider = "cache"
	meta.Request.StatusCode = http.StatusOK
	meta.Request.LatencyMS = 0
	meta.Request.RouteReason = "cache-semantic"
	meta.Response = &store.ResponseLog{
		ID: newID("resp"), RequestID: meta.Request.ID, StatusCode: http.StatusOK,
		FinishReason: "cache", ResponseHash: audit.HashText(string(hit.Body)), CreatedAt: time.Now().UTC(),
	}
	// The exact-cache path records a usage row with source "cache"; this one recorded none,
	// so a semantic hit was invisible to the savings figure that keys on that source. The
	// prompt tokens are what the call would have cost had it gone upstream — the same basis
	// the exact path uses — and the cost stays zero because no completion was bought. What
	// the request did cost, the embedding call, is its own row.
	if promptEstimate := promptTokenEstimate(meta.Prompts); promptEstimate > 0 {
		meta.Usage = &store.TokenUsage{
			ID:           newID("usage"),
			RequestID:    meta.Request.ID,
			PromptTokens: promptEstimate,
			TotalTokens:  promptEstimate,
			Currency:     "KRW",
			Source:       "cache",
			CreatedAt:    time.Now().UTC(),
		}
	}
	meta.Evaluations = buildLLMEvaluations(meta, ResponseAnalysis{Hash: meta.Response.ResponseHash, FinishReason: "cache"})
	s.metrics.ObserveLLMEvaluations(meta.Evaluations)
	s.enqueue(meta)
	return vec, true
}

// maybeStoreChatSemantic stores a successful chat response under the query embedding for
// future semantic reuse.
func (s *Server) maybeStoreChatSemantic(ctx context.Context, body []byte, vec []float64, statusCode int, contentType string, responseBody []byte, scope string) {
	if !s.cacheConf().ChatSemanticEnabled || len(vec) == 0 || statusCode != http.StatusOK || len(responseBody) == 0 {
		return
	}
	if maxBytes := s.cacheConf().EmbeddingMaxBytes; maxBytes > 0 && len(responseBody) > maxBytes {
		return
	}
	_, model, _ := chatCacheKey(body)
	if model == "" {
		return
	}
	if err := s.db.PutChatSemanticEntry(ctx, newID("sem"), model, scope, vec, contentType, responseBody, s.cacheConf().ChatTTL); err != nil {
		slog.Warn("semantic cache store failed", "error", err)
	}
}
