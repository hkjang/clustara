package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/store"
)

func (s *Server) handleGovernanceEvidence(w http.ResponseWriter, r *http.Request) {
	s.handleGovernanceRecordEndpoint(w, r, "evidence_chain", "captured", "governance.evidence.upsert", "evidence")
}

func (s *Server) handleGovernanceCMDBLinks(w http.ResponseWriter, r *http.Request) {
	s.handleGovernanceRecordEndpoint(w, r, "cmdb_link", "active", "governance.cmdb_link.upsert", "links")
}

func (s *Server) handleGovernanceTickets(w http.ResponseWriter, r *http.Request) {
	s.handleGovernanceRecordEndpoint(w, r, "itsm_ticket", "open", "governance.ticket.upsert", "tickets")
}

func (s *Server) handleGovernanceRiskRegister(w http.ResponseWriter, r *http.Request) {
	s.handleGovernanceRecordEndpoint(w, r, "risk_register", "accepted", "governance.risk.upsert", "risks")
}

func (s *Server) handleGovernanceRecordEndpoint(w http.ResponseWriter, r *http.Request, kind, defaultStatus, auditAction, responseKey string) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, kind)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, kind, "*", map[string]any{responseKey: rows, "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, kind, defaultStatus, auditAction)
		if !ok {
			return
		}
		if rec.EvidenceID == "" {
			rec.EvidenceID = "ev_" + audit.HashText(kind + rec.ID + fleetJSON(rec.Payload))[:16]
			_ = s.db.UpsertEnterpriseRecord(r.Context(), rec)
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, kind, rec.ID, map[string]any{strings.TrimSuffix(responseKey, "s"): rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGovernanceExecutiveReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusters, _ := s.db.ListK8sClusters(r.Context())
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{Status: "open", Limit: 500})
	findings, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{Status: "open", Limit: 1000})
	risks, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: "risk_register", Limit: 500})
	tickets, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: "itsm_ticket", Limit: 500})
	report, recs, anomalies, budgets, _ := s.finOpsSnapshot(r, strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	criticalFindings := 0
	for _, f := range findings {
		if aiopsSeverityRank(f.Severity) >= 3 {
			criticalFindings++
		}
	}
	criticalIncidents := 0
	for _, inc := range incidents {
		if aiopsSeverityRank(inc.Severity) >= 3 {
			criticalIncidents++
		}
	}
	totalSavings := 0.0
	for _, rec := range recs {
		totalSavings += rec.MonthlySavingsKRW
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "executive_report", "*", map[string]any{
		"period": firstNonEmptyStr(r.URL.Query().Get("period"), time.Now().UTC().Format("2006-01")),
		"summary": map[string]any{
			"clusters":       len(clusters),
			"open_incidents": len(incidents), "critical_incidents": criticalIncidents,
			"open_security_findings": len(findings), "critical_security_findings": criticalFindings,
			"monthly_k8s_cost_krw": report.TotalMonthlyKRW, "cost_anomalies": len(anomalies),
			"budget_warnings":         countFinOpsBudgetViolations(budgets),
			"rightsizing_savings_krw": roundMoney(totalSavings),
			"open_tickets":            len(tickets), "accepted_risks": len(risks),
		},
		"sections":     []string{"stability", "security", "finops", "change_risk", "governance"},
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}))
}

func (s *Server) handleGovernanceAuditSearch(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := intParam(r.URL.Query().Get("limit"), 200)
	rows := []map[string]any{}
	adminLogs, _ := s.db.ListAdminAudit(r.Context(), limit)
	for _, l := range adminLogs {
		row := map[string]any{
			"source": "admin_audit", "id": l.ID, "actor": l.AdminID, "action": l.Action,
			"target": l.BeforeValue, "result": l.AfterValue, "created_at": l.CreatedAt,
		}
		if auditRowMatches(row, q) {
			rows = append(rows, row)
		}
	}
	authEvents, _ := s.db.ListAuditEvents(r.Context(), limit)
	for _, ev := range authEvents {
		row := map[string]any{
			"source": "auth_event", "id": ev.ID, "actor": ev.ActorUserID, "team_id": ev.TeamID,
			"action": ev.EventType, "target": ev.APIKeyID, "detail": ev.Detail, "ip": ev.IP,
			"created_at": ev.CreatedAt.Format(time.RFC3339),
		}
		if auditRowMatches(row, q) {
			rows = append(rows, row)
		}
	}
	records, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Limit: limit})
	for _, rec := range records {
		row := map[string]any{
			"source": "enterprise_record", "id": rec.ID, "actor": rec.CreatedBy, "action": rec.Kind,
			"target": rec.ScopeType + ":" + rec.ScopeID, "risk": rec.Payload["risk_level"],
			"result": rec.Status, "tenant": rec.OwnerTeamID, "evidence_id": rec.EvidenceID,
			"created_at": rec.CreatedAt,
		}
		if auditRowMatches(row, q) {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return toString(rows[i]["created_at"]) > toString(rows[j]["created_at"]) })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "audit_search", "*", map[string]any{"events": rows, "count": len(rows)}))
}

func auditRowMatches(row map[string]any, q string) bool {
	if q == "" {
		return true
	}
	return strings.Contains(strings.ToLower(fleetJSON(row)), q)
}
