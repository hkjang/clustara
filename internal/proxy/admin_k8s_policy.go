package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

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
// policyCheckStatus describes whether a returned analysis plan was produced against
// a real rule set. Analysing with no policies loaded yields a clean plan, so a
// response carrying one must say which of the two it is.
//
// Both ways of having no rule set count. A load failure was already reported; an
// empty or entirely disabled policy list was not, and it reaches the same place:
// EvaluatePolicies skips anything not enabled, so with none enabled every
// resource comes back clean and the response was indistinguishable from a real
// pass. "No rules ran" is not "nothing was wrong".
func policyCheckStatus(err error, policies []store.K8sPolicy) map[string]any {
	return policyCheckStatusOver(err, policies, -1, false)
}

// policyCheckStatusOver adds what the run had to examine. resources < 0 means the
// caller is analysing a manifest it was handed rather than a fetched inventory,
// where "nothing to examine" is not a possible surprise.
func policyCheckStatusOver(err error, policies []store.K8sPolicy, resources int, truncated bool) map[string]any {
	if err != nil {
		return map[string]any{
			"status": "unavailable",
			"error":  err.Error(),
			"reason": "정책 목록을 불러오지 못해 정책 검사가 수행되지 않았습니다. 이 결과는 정책 통과를 뜻하지 않습니다.",
		}
	}
	enabled := 0
	for _, p := range policies {
		if p.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return map[string]any{
			"status": "no_rules",
			"rules":  0,
			"reason": "활성화된 정책이 없어 검사할 규칙이 없었습니다. 이 결과는 정책 통과를 뜻하지 않습니다.",
		}
	}
	if resources == 0 {
		return map[string]any{
			"status": "no_resources", "rules": enabled, "resources": 0,
			"reason": "검사 대상 리소스가 없었습니다. 에이전트가 인벤토리를 보고하지 않았을 수 있으며, 이 결과는 정책 통과를 뜻하지 않습니다.",
		}
	}
	if truncated {
		return map[string]any{
			"status": "partial", "rules": enabled, "resources": resources,
			"reason": "검사 대상이 상한을 초과해 일부만 검사했습니다. 위반이 없다는 결과가 전수 통과를 뜻하지 않습니다.",
		}
	}
	out := map[string]any{"status": "checked", "rules": enabled}
	if resources > 0 {
		out["resources"] = resources
	}
	return out
}

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
		present, decErr := decodeWithPresence(r, &p)
		if decErr != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		// This endpoint upserts on id, so a POST carrying an existing id is an
		// edit — and every field the caller omits arrives as its Go zero value.
		// "enabled" is the dangerous one: leaving it out of a request that only
		// meant to change the action decodes as false and silently switches the
		// policy off. A disabled policy is what makes the compliance report say
		// "no violations", so the failure hides itself.
		//
		// Merge instead: only fields actually present in the body override what is
		// stored.
		if id := strings.TrimSpace(p.ID); id != "" {
			existing, listErr := s.db.ListK8sPolicies(r.Context())
			if listErr != nil {
				writeOpenAIError(w, http.StatusInternalServerError, listErr.Error(), "server_error", "k8s_policies_failed")
				return
			}
			for _, cur := range existing {
				if cur.ID != id {
					continue
				}
				if !present["name"] {
					p.Name = cur.Name
				}
				if !present["rule_type"] {
					p.RuleType = cur.RuleType
				}
				if !present["action"] {
					p.Action = cur.Action
				}
				if !present["enabled"] {
					p.Enabled = cur.Enabled
				}
				p.CreatedAt = cur.CreatedAt
				break
			}
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
		// Annotations mirror the resource's own metadata.annotations. The attestation
		// rules read them, so a simulation without them cannot reproduce the verdict
		// the same resource would get in a real evaluation.
		Annotations map[string]string `json:"annotations"`
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
	results := analyzer.EvaluatePolicies(p.Kind, p.Spec, p.Annotations, toAnalyzerPolicies(policies))
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
// complianceScanBudget caps how many evaluable resources one compliance run
// examines. A var rather than a const so a test can drive the truncation path
// without seeding thousands of rows.
var complianceScanBudget = 5000

func (s *Server) handleK8sPolicyCompliance(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	// Fetch only the kinds a policy run evaluates, and ask for one row beyond the
	// budget so truncation is detectable.
	//
	// The unfiltered fetch this replaces asked for 4000 rows ordered by
	// updated_at, so the budget went to whatever churns most and the stable
	// production workloads — the ones that have not changed lately — fell outside
	// the window first. The report then declared itself "checked" over that
	// sample. Scoping reclaims the budget from the kinds the evaluation ignores;
	// Pods are evaluated, so it cannot exclude the busiest kind, which is why the
	// truncation flag below carries the rest of the weight.
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{
		ClusterID: r.URL.Query().Get("cluster_id"),
		Kinds:     analyzer.PolicyEvaluableKinds(),
		Limit:     complianceScanBudget + 1,
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	policies, policyErr := s.db.ListK8sPolicies(r.Context())
	if policyErr != nil {
		// With no rule set every resource is compliant, so this would report
		// "0 violations" — an affirmative clean bill of health for a check that
		// never ran. Compliance sign-off reads this endpoint.
		writeOpenAIError(w, http.StatusServiceUnavailable, "정책 목록을 불러오지 못해 컴플라이언스 검사를 수행할 수 없습니다: "+policyErr.Error(), "server_error", "k8s_policy_load_failed")
		return
	}
	truncated := len(items) > complianceScanBudget
	if truncated {
		items = items[:complianceScanBudget]
	}
	violations := analyzer.CheckPolicyCompliance(items, toAnalyzerPolicies(policies))
	// The rules ran over whatever the collectors last wrote down. If the agent went
	// offline an hour ago the inventory is an hour-old photograph, and a verdict over
	// it is a statement about the past — indistinguishable, in this response, from a
	// live pass. Score the freshness of the exact rows that were evaluated.
	fresh := s.inventoryFreshness(r, items, time.Now().UTC())
	// Compliance sign-off reads this endpoint, and "0 violations" from an empty
	// rule set looks exactly like "0 violations" from a passing one. Say which.
	resp := map[string]any{
		"violations": violations, "count": len(violations),
		"policy_check": markStaleData(policyCheckStatusOver(nil, policies, analyzer.CountPolicyEvaluable(items), truncated), fresh),
	}
	if fresh.Band != "" {
		resp["freshness"] = fresh
	}
	writeJSON(w, http.StatusOK, resp)
}

// markStaleData folds collection freshness into a scan-status block. The status is left
// alone — the check really did run — but a verdict computed over inventory nobody has
// refreshed is not a statement about the cluster now, and "checked" with no violations
// reads as one. A block that already reported an incomplete run keeps its own reason and
// gains the age.
func markStaleData(check map[string]any, f analyzer.Freshness) map[string]any {
	if check == nil || !f.Stale {
		return check
	}
	check["stale"] = true
	check["data_age_seconds"] = f.AgeSeconds
	notice := "수집이 지연된 인벤토리로 판정했습니다 — " + f.Reason + " 이 결과는 클러스터의 현재 상태를 보장하지 않습니다."
	if prev, ok := check["reason"].(string); ok && prev != "" {
		notice = prev + " " + notice
	}
	check["reason"] = notice
	return check
}
