package proxy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

const k8sCollectionBudgetFlag = "k8s_collection_budget_mb"
const k8sCollectionBudgetDefaultMB = 1024

// handleK8sCollectionCost serves the Collection Cost Guard report (CLU-REQ-11): estimated storage
// footprint + projected growth per cluster, flagging clusters over the configured budget.
// GET  /admin/k8s/collection-cost
// POST /admin/k8s/collection-cost {budget_mb}
func (s *Server) handleK8sCollectionCost(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method == http.MethodPost {
		var in struct {
			BudgetMB int `json:"budget_mb"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if in.BudgetMB < 0 {
			in.BudgetMB = 0
		}
		_ = s.db.SetFlag(r.Context(), store.RuntimeFlag{Key: k8sCollectionBudgetFlag, Value: strconv.Itoa(in.BudgetMB), UpdatedBy: adminID(r)})
		s.auditAdmin(r, "k8s.collection.budget", "", auditJSON(map[string]any{"budget_mb": in.BudgetMB}))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "budget_mb": in.BudgetMB})
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}

	budgetMB := float64(s.k8sPollFlagInt(r.Context(), k8sCollectionBudgetFlag, k8sCollectionBudgetDefaultMB))
	counts, err := s.db.K8sCollectionCountsByCluster(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "collection_counts_failed")
		return
	}
	noAgentSecs := s.k8sPollFlagInt(r.Context(), k8sPollNoAgentSecsFlag, k8sPollNoAgentDefaultSecs)
	withAgentSecs := s.k8sPollFlagInt(r.Context(), k8sPollWithAgentSecsFlag, k8sPollWithAgentDefaultSec)
	now := time.Now().UTC()

	clusters, _ := s.db.ListK8sClusters(r.Context())
	names := map[string]string{}
	for _, c := range clusters {
		names[c.ID] = firstNonEmpty(c.Name, c.ID)
	}

	inputs := make([]analyzer.CollectionCostInput, 0, len(counts))
	for id, c := range counts {
		secs, _ := analyzer.EffectiveCollectInterval(analyzer.CollectPolicyInput{
			BaseSecs: noAgentSecs, WithAgentSecs: withAgentSecs, AgentAlive: s.clusterHasLiveAgent(r.Context(), id, now),
		})
		perDay := 0.0
		if secs > 0 {
			perDay = 86400.0 / float64(secs)
		}
		inputs = append(inputs, analyzer.CollectionCostInput{
			ClusterID: id, ClusterName: firstNonEmpty(names[id], id),
			Inventory: c.Inventory, Events: c.Events, Revisions: c.Revisions,
			WatchEvents: c.WatchEvents, Metrics: c.Metrics, CollectRuns: c.CollectRuns,
			CollectsPerDay: perDay, BudgetMB: budgetMB,
		})
	}
	report := analyzer.BuildCollectionCostReport(inputs)
	writeJSON(w, http.StatusOK, map[string]any{
		"report":    report,
		"budget_mb": budgetMB,
		"note":      "수집으로 적재되는 저장량(행 수×테이블별 평균 행 크기) 추정과 수집 주기 기반 월 증가량 예측입니다. 예산 초과 클러스터는 수집 주기를 늘리거나(collect-config) 보존 기간을 줄이세요. 실제 디스크 사용량과는 다를 수 있습니다.",
	})
}
