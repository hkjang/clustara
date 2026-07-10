package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func toAnalyzerPolicies(ps []store.K8sPolicy) []analyzer.Policy {
	out := make([]analyzer.Policy, 0, len(ps))
	for _, p := range ps {
		out = append(out, analyzer.Policy{ID: p.ID, Name: p.Name, RuleType: p.RuleType, Action: p.Action, Enabled: p.Enabled})
	}
	return out
}

func validPolicyRule(rt string) bool {
	for _, t := range analyzer.PolicyRuleTypes {
		if t == rt {
			return true
		}
	}
	return false
}

// handleK8sPolicies lists/creates policy-pack entries (SEC-10). GET/POST /admin/k8s/policies
func (s *Server) handleK8sPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		ps, err := s.db.ListK8sPolicies(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_policies_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": ps, "available_rule_types": analyzer.PolicyRuleTypes})
	case http.MethodPost:
		var p store.K8sPolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(p.Name) == "" || !validPolicyRule(p.RuleType) {
			writeOpenAIError(w, http.StatusBadRequest, "name and a valid rule_type are required", "invalid_request_error", "invalid_policy")
			return
		}
		if p.Action == "" {
			p.Action = "Warn"
		}
		switch strings.ToLower(strings.TrimSpace(p.Action)) {
		case "deny":
			p.Action = "Deny"
		case "warn":
			p.Action = "Warn"
		case "audit":
			p.Action = "Audit"
		default:
			writeOpenAIError(w, http.StatusBadRequest, "action must be Deny, Warn, or Audit", "invalid_request_error", "invalid_policy_action")
			return
		}
		if strings.TrimSpace(p.ID) == "" {
			p.ID = newID("k8spol")
		}
		if err := s.db.UpsertK8sPolicy(r.Context(), p); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_policy_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.policy.upsert", "", auditJSON(p))
		writeJSON(w, http.StatusCreated, map[string]any{"policy": p})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sPolicyExport renders the enabled policies as Kyverno or Rego (Policy as Code).
// GET /admin/k8s/policies/export?format=kyverno|rego
func (s *Server) handleK8sPolicyExport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	ps, err := s.db.ListK8sPolicies(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_policies_failed")
		return
	}
	policies := toAnalyzerPolicies(ps)
	format := strings.ToLower(firstQuery(r.URL.Query().Get("format"), "kyverno"))
	var content, filename string
	switch format {
	case "rego":
		content, filename = analyzer.ExportRego(policies), "clustara-guardrails.rego"
	case "kyverno", "yaml":
		format = "kyverno"
		content, filename = analyzer.ExportKyverno(policies), "clustara-guardrails.yaml"
	default:
		writeOpenAIError(w, http.StatusBadRequest, "format must be kyverno or rego", "invalid_request_error", "invalid_format")
		return
	}
	if content == "" {
		content = "# 내보낼 활성 정책이 없습니다.\n"
	}
	s.auditAdmin(r, "k8s.policy.export", "", auditJSON(map[string]string{"format": format}))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}

// handleK8sPolicyImport recognizes rule types from a pasted Kyverno/Rego document and (unless
// dry_run) creates the corresponding Clustara policies. POST {content, dry_run, action}
func (s *Server) handleK8sPolicyImport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var p struct {
		Content string `json:"content"`
		DryRun  bool   `json:"dry_run"`
		Action  string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if strings.TrimSpace(p.Content) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "content is required", "invalid_request_error", "missing_content")
		return
	}
	matched, warnings := analyzer.ImportPolicyText(p.Content)
	action := p.Action
	if action == "" {
		action = "Warn"
	}
	created := []store.K8sPolicy{}
	if !p.DryRun {
		for _, m := range matched {
			pol := store.K8sPolicy{ID: newID("k8spol"), Name: m.Title, RuleType: m.RuleType, Action: action, Enabled: false}
			if err := s.db.UpsertK8sPolicy(r.Context(), pol); err != nil {
				continue
			}
			created = append(created, pol)
		}
		s.auditAdmin(r, "k8s.policy.import", "", auditJSON(map[string]any{"matched": len(matched), "created": len(created)}))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched": matched, "count": len(matched), "warnings": warnings,
		"dry_run": p.DryRun, "created": created,
		"note": "가져온 정책은 비활성(enabled=false) 상태로 생성됩니다 — 검토 후 활성화하세요.",
	})
}

// handleK8sPolicyByID deletes a policy. DELETE /admin/k8s/policies/{id}
func (s *Server) handleK8sPolicyByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodDelete {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/policies/"), "/")
	if id == "" || id == "simulate" || id == "compliance" || id == "export" || id == "import" {
		writeOpenAIError(w, http.StatusBadRequest, "policy id required", "invalid_request_error", "missing_policy_id")
		return
	}
	if err := s.db.DeleteK8sPolicy(r.Context(), id); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_policy_delete_failed")
		return
	}
	s.auditAdmin(r, "k8s.policy.delete", "", auditJSON(map[string]string{"id": id}))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleK8sPolicySimulate evaluates a submitted manifest against the enabled policies before it
// is applied (SEC-05 Admission 시뮬레이터). POST {kind, spec}
func (s *Server) handleK8sPolicySimulate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var p struct {
		Kind string         `json:"kind"`
		Spec map[string]any `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	policies, err := s.db.ListK8sPolicies(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_policies_failed")
		return
	}
	results := analyzer.EvaluatePolicies(p.Kind, p.Spec, toAnalyzerPolicies(policies))
	decision := "allow"
	for _, res := range results {
		if res.Violated && strings.EqualFold(res.Action, "Deny") {
			decision = "deny"
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decision": decision, "results": results})
}

// handleK8sPolicyCompliance runs the enabled policies across the inventory (SEC-10 정책 팩).
// GET /admin/k8s/policies/compliance?cluster_id=
func (s *Server) handleK8sPolicyCompliance(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: r.URL.Query().Get("cluster_id"), Limit: 4000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	policies, _ := s.db.ListK8sPolicies(r.Context())
	violations := analyzer.CheckPolicyCompliance(items, toAnalyzerPolicies(policies))
	writeJSON(w, http.StatusOK, map[string]any{"violations": violations, "count": len(violations)})
}
