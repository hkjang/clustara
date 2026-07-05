package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/store"
)

func (s *Server) handleGitOpsSources(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "gitops_source")
		if !ok {
			return
		}
		stacks, _ := s.db.ListK8sStacks(r.Context(), strings.TrimSpace(r.URL.Query().Get("cluster_id")))
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_source", "*", map[string]any{"sources": rows, "stack_sources": gitOpsStackSources(stacks), "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "gitops_source", "active", "gitops.source.upsert")
		if !ok {
			return
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "gitops_source", rec.ID, map[string]any{"source": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGitOpsDrift(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	stacks, err := s.db.ListK8sStacks(r.Context(), strings.TrimSpace(r.URL.Query().Get("cluster_id")))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_drift_failed")
		return
	}
	rows := []map[string]any{}
	for _, st := range stacks {
		revs, _ := s.db.ListK8sStackRevisions(r.Context(), st.ID, 2)
		class := "in_sync"
		reasons := []string{}
		if st.GitRepo == "" {
			class = "live_only"
			reasons = append(reasons, "git_source_missing")
		}
		if strings.EqualFold(st.Status, "drifted") {
			class = "spec_diff"
			reasons = append(reasons, "stack_status_drifted")
		}
		if len(revs) > 1 && revs[0].ManifestHash != revs[1].ManifestHash {
			reasons = append(reasons, "manifest_revision_changed")
		}
		risk := "low"
		if class == "spec_diff" {
			risk = "high"
		} else if class == "live_only" {
			risk = "medium"
		}
		rows = append(rows, map[string]any{
			"stack_id": st.ID, "stack": st.Name, "cluster_id": st.ClusterID, "namespace": st.Namespace,
			"classification": class, "risk_level": risk, "reasons": reasons,
			"git_repo": st.GitRepo, "git_branch": st.GitBranch, "git_path": st.GitPath,
			"live_hash": st.ManifestHash, "recommended_action": gitOpsDriftAction(class),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if aiGovernanceRiskRank(toString(rows[i]["risk_level"])) != aiGovernanceRiskRank(toString(rows[j]["risk_level"])) {
			return aiGovernanceRiskRank(toString(rows[i]["risk_level"])) > aiGovernanceRiskRank(toString(rows[j]["risk_level"]))
		}
		return toString(rows[i]["stack"]) < toString(rows[j]["stack"])
	})
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_drift", "*", map[string]any{"drift": rows, "count": len(rows)}))
}

func (s *Server) handleGitOpsPRDrafts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "gitops_pr_draft")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_pr_draft", "*", map[string]any{"drafts": rows, "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "gitops_pr_draft", "draft", "gitops.pr_draft.upsert")
		if !ok {
			return
		}
		if rec.Payload["patch_hash"] == nil {
			rec.Payload["patch_hash"] = audit.HashText(fleetJSON(rec.Payload))[:16]
		}
		_ = s.db.UpsertEnterpriseRecord(r.Context(), rec)
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "gitops_pr_draft", rec.ID, map[string]any{"draft": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGitOpsProgressiveRollouts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "gitops_progressive_rollout")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_progressive_rollout", "*", map[string]any{"rollouts": rows, "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "gitops_progressive_rollout", "planned", "gitops.progressive_rollout.upsert")
		if !ok {
			return
		}
		if rec.Payload["stages"] == nil {
			rec.Payload["stages"] = []map[string]any{{"name": "dev", "gate": "healthy"}, {"name": "qa", "gate": "healthy"}, {"name": "canary", "gate": "slo_ok"}, {"name": "prod", "gate": "approval"}}
			_ = s.db.UpsertEnterpriseRecord(r.Context(), rec)
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "gitops_progressive_rollout", rec.ID, map[string]any{"rollout": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGitOpsRollbackPlans(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		stackID := strings.TrimSpace(r.URL.Query().Get("stack_id"))
		rows := []map[string]any{}
		if stackID != "" {
			revs, _ := s.db.ListK8sStackRevisions(r.Context(), stackID, 5)
			for i, rev := range revs {
				rows = append(rows, map[string]any{"source": "stack_revision", "stack_id": stackID, "revision_no": rev.RevisionNo, "manifest_hash": rev.ManifestHash, "created_at": rev.CreatedAt, "preferred": i == 1})
			}
		}
		recs, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: "gitops_rollback_plan", Limit: 500})
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "gitops_rollback_plan", stackID, map[string]any{"stack_candidates": rows, "plans": recs}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "gitops_rollback_plan", "ready", "gitops.rollback_plan.upsert")
		if !ok {
			return
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "gitops_rollback_plan", rec.ID, map[string]any{"plan": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGitOpsChangeCalendar(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "change_calendar")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "change_calendar", "*", map[string]any{"windows": rows, "active_freeze": activeChangeFreeze(rows), "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "change_calendar", "active", "gitops.change_calendar.upsert")
		if !ok {
			return
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "change_calendar", rec.ID, map[string]any{"window": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleGitOpsDeploymentEvidence(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		stackID := strings.TrimSpace(r.URL.Query().Get("stack_id"))
		history := []store.K8sStackApplyHistory{}
		if stackID != "" {
			history, _ = s.db.ListK8sStackApplyHistory(r.Context(), stackID, 20)
		}
		records, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: "deployment_evidence", SourceRef: stackID, Limit: 500})
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "deployment_evidence", stackID, map[string]any{"apply_history": history, "evidence": records}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "deployment_evidence", "captured", "gitops.deployment_evidence.upsert")
		if !ok {
			return
		}
		if rec.EvidenceID == "" {
			rec.EvidenceID = "ev_" + audit.HashText(fleetJSON(rec.Payload) + time.Now().UTC().Format(time.RFC3339Nano))[:16]
			_ = s.db.UpsertEnterpriseRecord(r.Context(), rec)
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "deployment_evidence", rec.ID, map[string]any{"evidence": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func gitOpsStackSources(stacks []store.K8sApplicationStack) []map[string]any {
	out := []map[string]any{}
	for _, st := range stacks {
		if strings.TrimSpace(st.GitRepo) == "" {
			continue
		}
		out = append(out, map[string]any{"stack_id": st.ID, "name": st.Name, "cluster_id": st.ClusterID, "namespace": st.Namespace, "repo": st.GitRepo, "branch": st.GitBranch, "path": st.GitPath, "sync_policy": st.SyncPolicy})
	}
	return out
}

func gitOpsDriftAction(class string) string {
	switch class {
	case "live_only":
		return "create_git_source_or_export_pr"
	case "spec_diff":
		return "review_diff_and_create_pr_draft"
	default:
		return "monitor"
	}
}

func activeChangeFreeze(records []store.EnterpriseRecord) bool {
	now := time.Now().UTC()
	for _, rec := range records {
		if !strings.Contains(strings.ToLower(rec.Name+" "+toString(rec.Payload["type"])), "freeze") {
			continue
		}
		start, _ := time.Parse(time.RFC3339, toString(rec.Payload["start_at"]))
		end, _ := time.Parse(time.RFC3339, toString(rec.Payload["end_at"]))
		if !start.IsZero() && !end.IsZero() && now.After(start) && now.Before(end) {
			return true
		}
	}
	return false
}
