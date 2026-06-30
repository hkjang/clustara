package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// composeK8sAIPrompt builds a grounded, Korean prompt that constrains the model to the supplied
// evidence (AI-OPS-08 근거 중심). Pure + testable; the LLM call is done by the handler.
func composeK8sAIPrompt(question string, evidence []string) string {
	var b strings.Builder
	b.WriteString("당신은 Kubernetes 운영 분석 보조자입니다. 아래 '근거' 데이터만 사용해 한국어로 답하세요. ")
	b.WriteString("근거에 없는 내용은 추측하지 말고 \"근거에서 확인되지 않음\"이라고 답하세요.\n\n")
	b.WriteString("[질문]\n")
	b.WriteString(strings.TrimSpace(question))
	b.WriteString("\n\n[근거]\n")
	if len(evidence) == 0 {
		b.WriteString("(제공된 근거 없음)\n")
	}
	for i, e := range evidence {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, e))
	}
	b.WriteString("\n답변은 1) 핵심 원인/요약 2) 권고 조치 3) 사용한 근거 번호 순으로 간결히 작성하세요.")
	return b.String()
}

// gatherK8sEvidence collects the deterministic evidence (RCA causes, warning events, last config
// diff) for a target resource. Pure over its inputs so it can be unit-tested.
func gatherK8sEvidence(namespace, name string, rca []analyzer.RCAFinding, events []store.K8sEvent, diff *analyzer.RevisionDiff) []string {
	ev := []string{}
	for _, c := range rca {
		if name != "" && c.ResourceName != name {
			continue
		}
		if namespace != "" && c.Namespace != namespace {
			continue
		}
		condition := strings.TrimSpace(c.Condition)
		if condition != "" {
			condition += " "
		}
		line := fmt.Sprintf("RCA[%s] %s%s/%s: %s", c.Severity, condition, c.ResourceKind, c.ResourceName, c.Cause)
		ev = append(ev, line)
		for _, e := range c.Evidence {
			ev = append(ev, "  근거: "+e)
		}
	}
	warn := 0
	for _, e := range events {
		if !strings.EqualFold(e.Type, "Warning") {
			continue
		}
		if name != "" && e.InvolvedName != name && !strings.Contains(e.Message, name) {
			continue
		}
		if namespace != "" && e.Namespace != "" && e.Namespace != namespace {
			continue
		}
		ev = append(ev, fmt.Sprintf("Event[Warning] %s: %s", e.Reason, e.Message))
		if warn++; warn >= 8 {
			break
		}
	}
	if diff != nil && len(diff.Changes) > 0 {
		if len(diff.Highlights) > 0 {
			ev = append(ev, "직전 변경 하이라이트: "+strings.Join(diff.Highlights, ", "))
		}
		for i, c := range diff.Changes {
			if i >= 6 {
				break
			}
			ev = append(ev, fmt.Sprintf("변경 %s: %s (%s → %s)", c.Path, c.Kind, c.Old, c.New))
		}
	}
	if len(ev) > 40 {
		ev = ev[:40] // keep the prompt bounded
	}
	return ev
}

type k8sAIAskPayload struct {
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Question  string `json:"question"`
}

// handleK8sAIAsk answers a natural-language operations question grounded in the cluster's
// current RCA/events/diff evidence (AI-OPS-01 + AI-OPS-08). Degrades gracefully to evidence
// only when no LLM upstream is configured.
func (s *Server) handleK8sAIAsk(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var p k8sAIAskPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if strings.TrimSpace(p.Question) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "question is required", "invalid_request_error", "missing_question")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: p.ClusterID, Limit: 2000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), p.ClusterID, 500)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: p.ClusterID, Limit: 1000})
	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, time.Now().UTC(), 24*time.Hour)

	var diff *analyzer.RevisionDiff
	if p.Name != "" {
		revs, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: p.ClusterID, Kind: p.Kind, Namespace: p.Namespace, Name: p.Name, Limit: 2})
		if len(revs) >= 2 {
			d := analyzer.DiffRevisions(revs[1], revs[0])
			diff = &d
		}
	}

	evidence := gatherK8sEvidence(p.Namespace, p.Name, rca, events, diff)
	prompt := composeK8sAIPrompt(p.Question, evidence)

	answer, llmErr := s.workflowChatStep(r, "clustara/auto", prompt, 1024, nil)
	resp := map[string]any{"evidence": evidence, "grounded": true}
	if llmErr != nil {
		resp["answer"] = ""
		resp["llm_available"] = false
		resp["note"] = "LLM 업스트림이 구성되지 않았거나 호출에 실패했습니다. 아래 근거 데이터를 참고하세요: " + llmErr.Error()
	} else {
		resp["answer"] = answer
		resp["llm_available"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleK8sAIReport produces a Korean operations summary from the cross-cluster aggregates
// (AI-OPS-06). Degrades to the raw aggregate lines when no LLM is configured.
func (s *Server) handleK8sAIReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 2000})
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 500)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Limit: 500})
	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, time.Now().UTC(), 24*time.Hour)
	sec := analyzer.AnalyzeSecurity(items)

	evidence := []string{
		fmt.Sprintf("워크로드 %d개, 장애 후보 %d개, Privileged 워크로드 %d개, RBAC 위험 %d개, 보안 점수 %d",
			len(items), len(rca), sec.Summary.Privileged, sec.Summary.RBACFindings, sec.Summary.Score),
	}
	high := 0
	for _, c := range rca {
		if (c.Severity == "high" || c.Severity == "critical") && high < 15 {
			evidence = append(evidence, fmt.Sprintf("장애[%s] %s/%s: %s", c.Severity, c.ResourceKind, c.ResourceName, c.Cause))
			high++
		}
	}
	prompt := composeK8sAIPrompt("이 클러스터의 운영 상태를 경영진 보고용으로 요약하고, 우선 조치 3가지를 제안하세요.", evidence)

	answer, llmErr := s.workflowChatStep(r, "clustara/auto", prompt, 1500, nil)
	resp := map[string]any{"evidence": evidence}
	if llmErr != nil {
		resp["report"] = ""
		resp["llm_available"] = false
		resp["note"] = "LLM 미구성/실패 — 아래 근거로 직접 요약하세요: " + llmErr.Error()
	} else {
		resp["report"] = answer
		resp["llm_available"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}
