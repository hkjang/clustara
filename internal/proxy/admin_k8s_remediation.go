package proxy

import (
	"net/http"
	"time"

	k8saction "clustara/internal/action"
	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sRemediation returns prioritized remediation advice for current RCA findings — the
// recommended action, rationale, rollback viability, and (from the action classifier) risk level
// and approval requirement (Remediation Advisor). GET /admin/k8s/remediation/advice?cluster_id=
func (s *Server) handleK8sRemediation(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Limit: 2000})
	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, time.Now().UTC(), 24*time.Hour)

	advice := analyzer.AdviseRemediation(rca)
	for i := range advice {
		a := &advice[i]
		if a.Actionable {
			d := k8saction.Classify(a.RecommendedAction)
			a.RiskLevel = d.RiskLevel
			a.RequiresApproval = d.RequiresApproval
		} else {
			a.RiskLevel = "n/a"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"advice": advice,
		"count":  len(advice),
		"note":   "RCA 원인별 권장 조치입니다. actionable=true는 액션 승인함에서 바로 요청·실행할 수 있고, rollback/investigate는 수동 검토 권고입니다.",
	})
}
