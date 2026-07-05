package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

type aiGatewayKeyRisk struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Team           string   `json:"team"`
	Role           string   `json:"role"`
	Status         string   `json:"status"`
	RiskLevel      string   `json:"risk_level"`
	Reasons        []string `json:"reasons"`
	BudgetLimitKRW float64  `json:"budget_limit_krw"`
	ExpiresAt      string   `json:"expires_at"`
}

type aiGatewayProviderPosture struct {
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	APIKeyConfigured bool   `json:"api_key_configured"`
	TimeoutMS        int    `json:"timeout_ms"`
	ModelPatterns    string `json:"model_patterns"`
	RiskLevel        string `json:"risk_level"`
	Reason           string `json:"reason"`
}

type aiGatewayGovernanceSummary struct {
	TotalKeys            int     `json:"total_keys"`
	ActiveKeys           int     `json:"active_keys"`
	UnboundedKeys        int     `json:"unbounded_keys"`
	UnscopedModelKeys    int     `json:"unscoped_model_keys"`
	UnscopedProviderKeys int     `json:"unscoped_provider_keys"`
	ExpiringKeys         int     `json:"expiring_keys"`
	RevokedKeys          int     `json:"revoked_keys"`
	Providers            int     `json:"providers"`
	EnabledProviders     int     `json:"enabled_providers"`
	ProviderWarnings     int     `json:"provider_warnings"`
	RoutingRules         int     `json:"routing_rules"`
	ActiveRoutingRules   int     `json:"active_routing_rules"`
	BudgetWarnings       int     `json:"budget_warnings"`
	ModelAnomalies       int     `json:"model_anomalies"`
	CostAnomalies        int     `json:"cost_anomalies"`
	Requests30d          int64   `json:"requests_30d"`
	Tokens30d            int64   `json:"tokens_30d"`
	CostKRW30d           float64 `json:"cost_krw_30d"`
}

func (s *Server) handleAIGatewayGovernanceOverview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	now := time.Now().UTC()
	keys, err := s.db.ListAPIKeys(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "ai_governance_keys_failed")
		return
	}
	providers, _ := s.db.ListProviders(r.Context())
	rules, _ := s.db.ListRoutingRules(r.Context())
	budgets, _ := s.db.BudgetStatuses(r.Context(), now)
	modelAnomalies, _ := s.db.ModelAnomalies(r.Context(), 7*24*time.Hour, 6*time.Hour, 3)
	costAnomalies, _ := s.db.CostAnomalies(r.Context(), 7*24*time.Hour, 6*time.Hour, 3)
	requests, cost, tokens, _ := s.db.UsageSince(r.Context(), store.UsageFilter{Scope: "global", Since: now.AddDate(0, 0, -30)})

	summary := aiGatewayGovernanceSummary{
		TotalKeys: len(keys), Providers: len(providers), RoutingRules: len(rules),
		ModelAnomalies: len(modelAnomalies), CostAnomalies: len(costAnomalies),
		Requests30d: requests, Tokens30d: tokens, CostKRW30d: roundMoney(cost),
	}
	keyRisks := make([]aiGatewayKeyRisk, 0, len(keys))
	for _, key := range keys {
		active := strings.EqualFold(key.Status, "active") || key.Status == ""
		if active {
			summary.ActiveKeys++
		} else if strings.EqualFold(key.Status, "revoked") || key.RevokedAt != "" {
			summary.RevokedKeys++
		}
		row := aiGovernanceKeyRisk(key, now)
		if active {
			for _, reason := range row.Reasons {
				switch reason {
				case "budget_not_set":
					summary.UnboundedKeys++
				case "model_allowlist_not_set":
					summary.UnscopedModelKeys++
				case "provider_allowlist_not_set":
					summary.UnscopedProviderKeys++
				case "expires_soon":
					summary.ExpiringKeys++
				}
			}
		}
		if row.RiskLevel != "low" {
			keyRisks = append(keyRisks, row)
		}
	}
	sort.SliceStable(keyRisks, func(i, j int) bool {
		if aiGovernanceRiskRank(keyRisks[i].RiskLevel) != aiGovernanceRiskRank(keyRisks[j].RiskLevel) {
			return aiGovernanceRiskRank(keyRisks[i].RiskLevel) > aiGovernanceRiskRank(keyRisks[j].RiskLevel)
		}
		return keyRisks[i].Name < keyRisks[j].Name
	})

	providerPosture := make([]aiGatewayProviderPosture, 0, len(providers))
	for _, p := range providers {
		row := aiGovernanceProviderPosture(p)
		if p.Enabled {
			summary.EnabledProviders++
		}
		if row.RiskLevel != "low" {
			summary.ProviderWarnings++
		}
		providerPosture = append(providerPosture, row)
	}
	for _, rule := range rules {
		if rule.Enabled {
			summary.ActiveRoutingRules++
		}
	}
	for _, b := range budgets {
		if !b.OnTrack || b.ProjectedRatio >= 0.8 {
			summary.BudgetWarnings++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"summary":           summary,
		"key_risks":         keyRisks,
		"providers":         providerPosture,
		"routing_rules":     rules,
		"budget_statuses":   budgets,
		"model_anomalies":   modelAnomalies,
		"cost_anomalies":    costAnomalies,
		"generated_at":      now.Format(time.RFC3339),
		"recommendations":   aiGovernanceRecommendations(summary),
		"evaluation_window": "30d usage, 7d baseline, 6h anomaly window",
	})
}

func aiGovernanceKeyRisk(key store.APIKeyPublic, now time.Time) aiGatewayKeyRisk {
	reasons := []string{}
	risk := "low"
	active := strings.EqualFold(key.Status, "active") || key.Status == ""
	if active {
		if key.BudgetLimitKRW <= 0 {
			reasons = append(reasons, "budget_not_set")
			risk = "medium"
		}
		if len(key.AllowedModels) == 0 {
			reasons = append(reasons, "model_allowlist_not_set")
			risk = maxAIGovernanceRisk(risk, "medium")
		}
		if len(key.AllowedProviders) == 0 {
			reasons = append(reasons, "provider_allowlist_not_set")
			risk = maxAIGovernanceRisk(risk, "medium")
		}
		if strings.TrimSpace(key.ExpiresAt) == "" {
			reasons = append(reasons, "expiration_not_set")
			risk = maxAIGovernanceRisk(risk, "high")
		} else if expires, err := time.Parse(time.RFC3339Nano, key.ExpiresAt); err == nil && expires.Before(now.AddDate(0, 0, 14)) {
			reasons = append(reasons, "expires_soon")
			risk = maxAIGovernanceRisk(risk, "medium")
		}
	}
	if len(reasons) == 0 {
		reasons = []string{"policy_scoped"}
	}
	return aiGatewayKeyRisk{
		ID: key.ID, Name: key.Name, Team: key.Team, Role: key.Role, Status: key.Status,
		RiskLevel: risk, Reasons: reasons, BudgetLimitKRW: key.BudgetLimitKRW, ExpiresAt: key.ExpiresAt,
	}
}

func aiGovernanceProviderPosture(p store.ProviderPublic) aiGatewayProviderPosture {
	risk, reason := "low", "ready"
	switch {
	case !p.Enabled:
		risk, reason = "medium", "provider_disabled"
	case p.Enabled && !p.APIKeyConfigured:
		risk, reason = "high", "api_key_not_configured"
	case strings.TrimSpace(p.ModelPatterns) == "":
		risk, reason = "medium", "model_patterns_not_set"
	}
	return aiGatewayProviderPosture{
		Name: p.Name, Enabled: p.Enabled, APIKeyConfigured: p.APIKeyConfigured, TimeoutMS: p.TimeoutMS,
		ModelPatterns: p.ModelPatterns, RiskLevel: risk, Reason: reason,
	}
}

func aiGovernanceRecommendations(s aiGatewayGovernanceSummary) []string {
	out := []string{}
	if s.UnboundedKeys > 0 {
		out = append(out, "active keys without budget should get team or key budget limits")
	}
	if s.UnscopedModelKeys > 0 || s.UnscopedProviderKeys > 0 {
		out = append(out, "active keys should use model and provider allowlists for production traffic")
	}
	if s.ProviderWarnings > 0 {
		out = append(out, "provider configuration should be completed before routing production traffic")
	}
	if s.BudgetWarnings > 0 {
		out = append(out, "budget warnings should be reviewed with FinOps owners")
	}
	if s.ModelAnomalies > 0 || s.CostAnomalies > 0 {
		out = append(out, "recent model or cost anomalies should be triaged before increasing traffic")
	}
	if len(out) == 0 {
		out = append(out, "gateway governance posture is within configured guardrails")
	}
	return out
}

func maxAIGovernanceRisk(a, b string) string {
	if aiGovernanceRiskRank(b) > aiGovernanceRiskRank(a) {
		return b
	}
	return a
}

func aiGovernanceRiskRank(risk string) int {
	switch risk {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
