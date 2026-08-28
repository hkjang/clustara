package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestAIGatewayGovernanceOverview(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.UpsertAPIKey(ctx, store.APIKeyRecord{
		ID: "key_risky", Name: "risky", KeyHash: "hash_risky", Team: "platform", Role: "developer", Status: "active",
		Scopes: []string{"chat:completion"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAPIKey(ctx, store.APIKeyRecord{
		ID: "key_scoped", Name: "scoped", KeyHash: "hash_scoped", Team: "platform", Role: "developer", Status: "active",
		Scopes: []string{"chat:completion"}, AllowedModels: []string{"gpt-4.1"}, AllowedProviders: []string{"openai"},
		BudgetLimitKRW: 10000, ExpiresAt: now.AddDate(0, 1, 0),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProvider(ctx, store.ProviderConfig{
		Name: "openai", BaseURL: "https://api.openai.com/v1", Enabled: true, TimeoutMS: 30000, ModelPatterns: "gpt-*",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertRoutingRule(ctx, store.RoutingRule{
		ID: "route1", Enabled: true, Priority: 10, MatchPattern: "vibe/auto", TargetModel: "gpt-4.1", TargetProvider: "openai",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertLogRecord(ctx, store.LogRecord{
		Request: store.RequestLog{
			ID: "req1", TraceID: "tr1", APIKeyID: "key_scoped", Endpoint: "/v1/chat/completions",
			Model: "gpt-4.1", Provider: "openai", StatusCode: 200, LatencyMS: 100, CreatedAt: now.Add(-time.Hour),
		},
		Usage: &store.TokenUsage{
			ID: "usage1", RequestID: "req1", TotalTokens: 1000, EstimatedCost: 12.5, Currency: "KRW", CreatedAt: now.Add(-time.Hour),
		},
	}); err != nil {
		t.Fatal(err)
	}

	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "ai-governance.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/ai/governance/overview")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/ai/governance/overview = %d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Summary   aiGatewayGovernanceSummary `json:"summary"`
		KeyRisks  []aiGatewayKeyRisk         `json:"key_risks"`
		Providers []aiGatewayProviderPosture `json:"providers"`
		Rules     []store.RoutingRule        `json:"routing_rules"`
		Recs      []string                   `json:"recommendations"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	// Neither key is covered by a cost quota, so both are unbounded. key_scoped
	// carries budget_limit_krw = 10000, which caps one request's estimated cost
	// and does nothing about its total spend; counting it as bounded is what this
	// report used to do.
	if out.Summary.TotalKeys != 2 || out.Summary.ActiveKeys != 2 || out.Summary.UnboundedKeys != 2 || out.Summary.UnscopedModelKeys != 1 || out.Summary.UnscopedProviderKeys != 1 {
		t.Fatalf("key summary mismatch: %+v", out.Summary)
	}
	hasOpenAIWarning := false
	for _, p := range out.Providers {
		if p.Name == "openai" && p.RiskLevel == "high" {
			hasOpenAIWarning = true
		}
	}
	if out.Summary.ProviderWarnings < 1 || !hasOpenAIWarning {
		t.Fatalf("provider posture mismatch: summary=%+v providers=%+v", out.Summary, out.Providers)
	}
	if out.Summary.ActiveRoutingRules != 1 || len(out.Rules) != 1 {
		t.Fatalf("routing summary mismatch: summary=%+v rules=%+v", out.Summary, out.Rules)
	}
	if out.Summary.Requests30d != 1 || out.Summary.Tokens30d != 1000 || out.Summary.CostKRW30d != 12.5 {
		t.Fatalf("usage summary mismatch: %+v", out.Summary)
	}
	// Both keys are now high risk: neither is covered by a cost quota, so neither
	// has any bound on what it can spend. key_scoped previously graded low on the
	// strength of a per-request cap that never fires.
	if len(out.KeyRisks) != 2 || len(out.Recs) == 0 {
		t.Fatalf("risk output mismatch: risks=%+v recs=%+v", out.KeyRisks, out.Recs)
	}
	for _, risk := range out.KeyRisks {
		if risk.RiskLevel != "high" || !hasReason(risk.Reasons, "cumulative_spend_not_capped") {
			t.Fatalf("%s: risk=%q reasons=%v; no quota covers it, so spend is unbounded",
				risk.ID, risk.RiskLevel, risk.Reasons)
		}
	}
}

// A key's budget_limit_krw caps the estimated cost of one request. It does not
// bound what the key spends: ordinary calls cost a fraction of a KRW, so a
// "budget" of 10,000 KRW never fires and the key runs unlimited in small calls.
//
// The governance report nevertheless graded a key carrying one as budgeted, and
// counted it out of UnboundedKeys — telling an operator following that report
// that spend was controlled when nothing bounded it. Only a cost quota, enforced
// in stepQuota against accumulated usage, actually does.
func TestPerRequestCapIsNotReportedAsASpendCap(t *testing.T) {
	key := store.APIKeyPublic{
		ID: "key_capped", Team: "platform", Status: "active",
		BudgetLimitKRW: 10000, AllowedModels: []string{"gpt-4.1"},
		AllowedProviders: []string{"openai"}, ExpiresAt: time.Now().UTC().AddDate(0, 1, 0).Format(time.RFC3339Nano),
	}

	row := aiGovernanceKeyRisk(key, time.Now().UTC(), spendCappedByQuota(nil, key))
	if !hasReason(row.Reasons, "cumulative_spend_not_capped") {
		t.Fatalf("a key with only a per-request cap was not reported as unbounded: %v", row.Reasons)
	}
	if row.RiskLevel != "high" {
		t.Fatalf("risk = %q, want high: nothing bounds this key's spend", row.RiskLevel)
	}

	// A cost quota at any covering scope is what actually bounds it.
	for _, q := range []store.QuotaPublic{
		{Scope: "api_key", ScopeValue: "key_capped", KRWLimit: 50000, Enabled: true},
		{Scope: "team", ScopeValue: "platform", KRWLimit: 50000, Enabled: true},
		{Scope: "global", ScopeValue: "*", KRWLimit: 50000, Enabled: true},
	} {
		if !spendCappedByQuota([]store.QuotaPublic{q}, key) {
			t.Fatalf("%s quota should cap this key's spend", q.Scope)
		}
	}

	// A token-only quota bounds volume, not money.
	if spendCappedByQuota([]store.QuotaPublic{
		{Scope: "team", ScopeValue: "platform", TokenLimit: 1000, Enabled: true},
	}, key) {
		t.Fatal("a token-only quota was treated as a spend cap")
	}
	// A disabled quota caps nothing.
	if spendCappedByQuota([]store.QuotaPublic{
		{Scope: "global", ScopeValue: "*", KRWLimit: 50000, Enabled: false},
	}, key) {
		t.Fatal("a disabled quota was treated as a spend cap")
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
