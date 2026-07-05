package proxy

import (
	"net/http"
	"sort"
	"strings"

	"clustara/internal/store"
)

type gitOpsStackPosture struct {
	Stack              store.K8sApplicationStack   `json:"stack"`
	GitConnected       bool                        `json:"git_connected"`
	Drifted            bool                        `json:"drifted"`
	RiskLevel          string                      `json:"risk_level"`
	Reasons            []string                    `json:"reasons"`
	LastOperation      *store.K8sStackApplyHistory `json:"last_operation,omitempty"`
	RollbackRevisionNo int                         `json:"rollback_revision_no"`
	RecommendedAction  string                      `json:"recommended_action"`
}

type gitOpsOverviewSummary struct {
	Stacks           int `json:"stacks"`
	GitConnected     int `json:"git_connected"`
	Drifted          int `json:"drifted"`
	ApplyFailures    int `json:"apply_failures"`
	ApprovalRequired int `json:"approval_required"`
	RollbackReady    int `json:"rollback_ready"`
	ManualSync       int `json:"manual_sync"`
}

func (s *Server) handleGitOpsOverview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	stacks, err := s.db.ListK8sStacks(r.Context(), clusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "gitops_stacks_failed")
		return
	}
	summary := gitOpsOverviewSummary{Stacks: len(stacks)}
	rows := make([]gitOpsStackPosture, 0, len(stacks))
	for _, st := range stacks {
		hist, _ := s.db.ListK8sStackApplyHistory(r.Context(), st.ID, 1)
		revs, _ := s.db.ListK8sStackRevisions(r.Context(), st.ID, 2)
		row := gitOpsStackPosture{Stack: st, GitConnected: strings.TrimSpace(st.GitRepo) != "", Drifted: strings.EqualFold(st.Status, "drifted"), RiskLevel: "low"}
		if len(hist) > 0 {
			h := hist[0]
			row.LastOperation = &h
		}
		if len(revs) > 1 {
			row.RollbackRevisionNo = revs[1].RevisionNo
			summary.RollbackReady++
		}
		row.RiskLevel, row.Reasons, row.RecommendedAction = gitOpsStackRisk(row)
		if row.GitConnected {
			summary.GitConnected++
		}
		if row.Drifted {
			summary.Drifted++
		}
		if row.LastOperation != nil {
			switch row.LastOperation.Status {
			case "failed", "partial", "denied":
				summary.ApplyFailures++
			case "approval_required":
				summary.ApprovalRequired++
			}
		}
		if strings.EqualFold(st.SyncPolicy, "manual") || st.SyncPolicy == "" {
			summary.ManualSync++
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if aiGovernanceRiskRank(rows[i].RiskLevel) != aiGovernanceRiskRank(rows[j].RiskLevel) {
			return aiGovernanceRiskRank(rows[i].RiskLevel) > aiGovernanceRiskRank(rows[j].RiskLevel)
		}
		return rows[i].Stack.UpdatedAt > rows[j].Stack.UpdatedAt
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": summary,
		"stacks":  rows,
		"note":    "Application Stack의 Git metadata, sync policy, drift status, apply history, rollback 가능성을 묶은 GitOps Change Manager overview입니다.",
	})
}

func gitOpsStackRisk(row gitOpsStackPosture) (string, []string, string) {
	reasons := []string{}
	risk := "low"
	action := "monitor"
	if !row.GitConnected {
		reasons = append(reasons, "git_source_not_connected")
		risk = maxAIGovernanceRisk(risk, "medium")
		action = "connect_git_source"
	}
	if row.Drifted {
		reasons = append(reasons, "live_state_drifted")
		risk = maxAIGovernanceRisk(risk, "high")
		action = "review_drift_or_create_manifest_change"
	}
	if row.LastOperation != nil {
		switch row.LastOperation.Status {
		case "failed", "partial", "denied":
			reasons = append(reasons, "last_apply_"+row.LastOperation.Status)
			risk = maxAIGovernanceRisk(risk, "high")
			if row.RollbackRevisionNo > 0 {
				action = "rollback_candidate_available"
			} else {
				action = "inspect_apply_history"
			}
		case "approval_required":
			reasons = append(reasons, "approval_required")
			risk = maxAIGovernanceRisk(risk, "medium")
			action = "review_action_center"
		}
	}
	if row.RollbackRevisionNo > 0 && action == "monitor" {
		action = "rollback_ready_if_needed"
	}
	if len(reasons) == 0 {
		reasons = []string{"in_sync_or_no_issue"}
	}
	return risk, reasons, action
}
