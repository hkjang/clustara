package proxy

import (
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

type finOpsBudgetLine struct {
	Scope         string  `json:"scope"`
	ScopeValue    string  `json:"scope_value"`
	MonthlyBudget float64 `json:"monthly_budget_krw"`
	EstimatedKRW  float64 `json:"estimated_monthly_krw"`
	BurnRatio     float64 `json:"burn_ratio"`
	Status        string  `json:"status"`
	DeltaKRW      float64 `json:"delta_krw"`
	Note          string  `json:"note"`
}

type finOpsAnomaly struct {
	Dimension string  `json:"dimension"`
	Key       string  `json:"key"`
	Current   float64 `json:"current_krw"`
	Previous  float64 `json:"previous_krw"`
	Delta     float64 `json:"delta_krw"`
	PctChange float64 `json:"pct_change"`
	Severity  string  `json:"severity"`
	Reason    string  `json:"reason"`
}

func (s *Server) handleFinOpsOverview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	report, recs, anomalies, budgets, err := s.finOpsSnapshot(r, clusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_overview_failed")
		return
	}
	savings := 0.0
	upsize := 0
	for _, rec := range recs {
		savings += rec.MonthlySavingsKRW
		if rec.Direction == "up" {
			upsize++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cost":      report,
		"budgets":   budgets,
		"anomalies": anomalies,
		"rightsizing": map[string]any{
			"recommendations":           recs,
			"total_monthly_savings_krw": roundMoney(savings),
			"upsize_count":              upsize,
			"downsize_count":            len(recs) - upsize,
		},
		"summary": map[string]any{
			"estimated_monthly_krw": report.TotalMonthlyKRW,
			"budget_violations":     countFinOpsBudgetViolations(budgets),
			"anomalies":             len(anomalies),
			"cluster_id":            clusterID,
			"generated_at":          time.Now().UTC().Format(time.RFC3339),
		},
		"note": "K8s request 기반 월 비용, team/global 예산, 일별 snapshot 이상 증가, rightsizing 절감 후보를 묶은 FinOps overview입니다.",
	})
}

func (s *Server) handleFinOpsCosts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	report, _, _, _, err := s.finOpsSnapshot(r, strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_costs_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cost": report})
}

func (s *Server) handleFinOpsAnomalies(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	_, _, anomalies, _, err := s.finOpsSnapshot(r, strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_anomalies_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"anomalies": anomalies, "count": len(anomalies)})
}

func (s *Server) handleFinOpsRightsizing(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	_, recs, _, _, err := s.finOpsSnapshot(r, strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "finops_rightsizing_failed")
		return
	}
	total := 0.0
	for _, rec := range recs {
		total += rec.MonthlySavingsKRW
	}
	writeJSON(w, http.StatusOK, map[string]any{"recommendations": recs, "count": len(recs), "total_monthly_savings_krw": roundMoney(total)})
}

func (s *Server) finOpsSnapshot(r *http.Request, clusterID string) (analyzer.CostReport, []analyzer.RightsizingRec, []finOpsAnomaly, []finOpsBudgetLine, error) {
	items, prices, nsTeam, nsCC, clusterGroup, err := s.costContext(r.Context(), clusterID)
	if err != nil {
		return analyzer.CostReport{}, nil, nil, nil, err
	}
	report := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)
	metrics, _ := s.db.ListK8sMetricSamples(r.Context(), clusterID, 5000)
	recs := analyzer.RecommendRightsizing(items, metrics, prices)
	budgets, _ := s.db.ListBudgets(r.Context())
	budgetLines := buildFinOpsBudgetLines(report, budgets)
	snaps, _ := s.db.ListK8sCostSnapshots(r.Context(), clusterID, "namespace", 3000)
	anomalies := buildFinOpsAnomalies(analyzer.ComputeCostTrend(snaps))
	return report, recs, anomalies, budgetLines, nil
}

func buildFinOpsBudgetLines(report analyzer.CostReport, budgets []store.Budget) []finOpsBudgetLine {
	teamCost := map[string]float64{}
	for _, line := range report.ByTeam {
		teamCost[strings.ToLower(line.Key)] = line.MonthlyKRW
	}
	out := []finOpsBudgetLine{}
	for _, b := range budgets {
		if b.Scope != "global" && b.Scope != "team" {
			continue
		}
		estimated := report.TotalMonthlyKRW
		if b.Scope == "team" {
			estimated = teamCost[strings.ToLower(b.ScopeValue)]
		}
		line := finOpsBudgetLine{
			Scope: b.Scope, ScopeValue: b.ScopeValue, MonthlyBudget: b.MonthlyKRW,
			EstimatedKRW: roundMoney(estimated), DeltaKRW: roundMoney(estimated - b.MonthlyKRW), Note: b.Note,
		}
		if b.MonthlyKRW > 0 {
			line.BurnRatio = roundMoney(estimated / b.MonthlyKRW)
		}
		switch {
		case b.MonthlyKRW <= 0:
			line.Status = "unknown"
		case estimated >= b.MonthlyKRW:
			line.Status = "critical"
		case estimated >= b.MonthlyKRW*0.8:
			line.Status = "warn"
		default:
			line.Status = "ok"
		}
		out = append(out, line)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			return finOpsStatusRank(out[i].Status) > finOpsStatusRank(out[j].Status)
		}
		return out[i].BurnRatio > out[j].BurnRatio
	})
	return out
}

func buildFinOpsAnomalies(trend []analyzer.CostTrendLine) []finOpsAnomaly {
	out := []finOpsAnomaly{}
	for _, line := range trend {
		if line.Delta <= 0 {
			continue
		}
		severity := "low"
		switch {
		case line.PctChange >= 50 || line.Delta >= 100000:
			severity = "critical"
		case line.PctChange >= 25 || line.Delta >= 50000:
			severity = "high"
		case line.PctChange >= 10 || line.Delta >= 10000:
			severity = "medium"
		default:
			continue
		}
		out = append(out, finOpsAnomaly{
			Dimension: "namespace", Key: line.Key, Current: line.Current, Previous: line.Previous,
			Delta: line.Delta, PctChange: line.PctChange, Severity: severity,
			Reason: "daily namespace cost increased",
		})
	}
	return out
}

func finOpsStatusRank(status string) int {
	switch status {
	case "critical":
		return 3
	case "warn":
		return 2
	case "ok":
		return 1
	default:
		return 0
	}
}

func countFinOpsBudgetViolations(lines []finOpsBudgetLine) int {
	n := 0
	for _, line := range lines {
		if line.Status == "critical" || line.Status == "warn" {
			n++
		}
	}
	return n
}

func roundMoney(v float64) float64 {
	return math.Round(v*100) / 100
}
