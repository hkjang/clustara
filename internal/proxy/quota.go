package proxy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"clustara/internal/store"
)

// Asia/Seoul fixed offset. KST has no DST so a fixed offset is safe.
var seoulZone = time.FixedZone("KST", 9*3600)

type quotaDecision struct {
	Allowed     bool
	Reason      string
	Quota       store.QuotaRecord
	Tokens      int64
	CostKRW     float64
	PeriodStart time.Time
	PeriodEnd   time.Time
	// Unevaluated names the scopes whose quotas could not be read, so "Allowed" can be
	// distinguished from "not checked". A quota that was never evaluated is not a quota that
	// was satisfied, and the usage aggregate this depends on gets slower exactly as usage
	// grows — the check is most likely to fail when it matters most.
	Unevaluated []string
}

// quotaScopeRef is one scope a request is measured against.
type quotaScopeRef struct{ scope, value string }

// evaluateQuotaScopes applies every scope's quotas and returns the first breach it finds.
//
// A scope whose lookup fails is recorded in Unevaluated and the REMAINING scopes are still
// evaluated. Previously the first error returned immediately with Allowed=true, so a failure
// reading, say, the global scope silently discarded the api-key, ip and team quotas that
// were perfectly readable — one slow aggregate disabled every limit behind it.
func evaluateQuotaScopes(now time.Time, scopes []quotaScopeRef,
	load func(quotaScopeRef) ([]store.QuotaRecord, error),
	usage func(store.QuotaRecord, time.Time) (costKRW float64, tokens int64, err error)) (quotaDecision, []error) {

	unevaluated := []string{}
	errs := []error{}
	for _, scope := range scopes {
		if scope.value == "" {
			continue
		}
		quotas, err := load(scope)
		if err != nil {
			unevaluated = append(unevaluated, scope.scope)
			errs = append(errs, fmt.Errorf("load %s quotas: %w", scope.scope, err))
			continue
		}
		for _, q := range quotas {
			start, end := periodBounds(q.Period, now)
			costKRW, tokens, err := usage(q, start)
			if err != nil {
				unevaluated = append(unevaluated, scope.scope)
				errs = append(errs, fmt.Errorf("usage for %s quota %s: %w", scope.scope, q.ID, err))
				continue
			}
			if q.TokenLimit > 0 && tokens >= q.TokenLimit {
				return quotaDecision{
					Allowed: false, Reason: "token_limit_exceeded",
					Quota: q, Tokens: tokens, CostKRW: costKRW,
					PeriodStart: start, PeriodEnd: end, Unevaluated: unevaluated,
				}, errs
			}
			if q.KRWLimit > 0 && costKRW >= q.KRWLimit {
				return quotaDecision{
					Allowed: false, Reason: "krw_limit_exceeded",
					Quota: q, Tokens: tokens, CostKRW: costKRW,
					PeriodStart: start, PeriodEnd: end, Unevaluated: unevaluated,
				}, errs
			}
		}
	}
	return quotaDecision{Allowed: true, Unevaluated: unevaluated}, errs
}

func periodBounds(period string, now time.Time) (time.Time, time.Time) {
	now = now.In(seoulZone)
	switch period {
	case "monthly":
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, seoulZone)
		end := start.AddDate(0, 1, 0)
		return start, end
	default:
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, seoulZone)
		end := start.AddDate(0, 0, 1)
		return start, end
	}
}

func (s *Server) checkQuotas(ctx context.Context, apiKeyID string, clientIP string) (quotaDecision, error) {
	now := time.Now()

	team, err := s.db.GetTeamForAPIKey(ctx, apiKeyID)
	if err != nil {
		return quotaDecision{Allowed: true}, err
	}

	scopes := []quotaScopeRef{
		{"global", "*"},
		{"api_key", apiKeyID},
		{"ip", clientIP},
	}
	if team != "" {
		scopes = append(scopes, quotaScopeRef{"team", team})
	}

	decision, errs := evaluateQuotaScopes(now, scopes,
		func(scope quotaScopeRef) ([]store.QuotaRecord, error) {
			return s.db.ActiveQuotasFor(ctx, scope.scope, scope.value)
		},
		func(q store.QuotaRecord, start time.Time) (float64, int64, error) {
			_, costKRW, tokens, err := s.db.UsageSince(ctx, store.UsageFilter{
				Scope:      q.Scope,
				ScopeValue: q.ScopeValue,
				Since:      start,
			})
			return costKRW, tokens, err
		})
	return decision, errors.Join(errs...)
}

func quotaRetryAfterSeconds(end time.Time) int {
	d := time.Until(end)
	if d <= 0 {
		return 1
	}
	return int(d.Seconds()) + 1
}

func formatKRW(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
}

func quotaHeaderTag(d quotaDecision) string {
	return fmt.Sprintf("%s:%s:%s", d.Quota.Scope, d.Quota.ScopeValue, d.Quota.Period)
}
