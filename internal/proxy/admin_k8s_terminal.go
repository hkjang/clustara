package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

type terminalPolicyEvalRequest struct {
	Role      string            `json:"role"`
	ClusterID string            `json:"cluster_id"`
	Namespace string            `json:"namespace"`
	Pod       string            `json:"pod"`
	PodLabels map[string]string `json:"pod_labels"`
	Command   string            `json:"command"`
}

type terminalPolicyEvalResult struct {
	Allowed           bool     `json:"allowed"`
	RequireApproval   bool     `json:"require_approval"`
	AuditEnabled      bool     `json:"audit_enabled"`
	MaxSessionMinutes int      `json:"max_session_minutes"`
	RiskLevel         string   `json:"risk_level"`
	Reason            string   `json:"reason"`
	MatchedPolicies   []string `json:"matched_policies"`
	MatchedRules      []string `json:"matched_rules"`
	CommandRisk       []analyzer.CommandRiskFinding `json:"command_risk_findings,omitempty"`
}

func (s *Server) handleK8sTerminalPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		policies, err := s.db.ListK8sTerminalPolicies(r.Context(), store.K8sTerminalPolicyFilter{
			Role: strings.ToLower(strings.TrimSpace(q.Get("role"))), ClusterID: strings.TrimSpace(q.Get("cluster_id")),
			Enabled: strings.TrimSpace(q.Get("enabled")), Limit: recentLimit(r),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "terminal_policy_list_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"policies":         policies,
			"default_denylist": builtinTerminalDenylist(),
			"command_presets":  terminalCommandPresets(),
		})
	case http.MethodPost:
		var in struct {
			ID                string   `json:"id"`
			Name              string   `json:"name"`
			Role              string   `json:"role"`
			ClusterID         string   `json:"cluster_id"`
			NamespacePattern  string   `json:"namespace_pattern"`
			PodSelector       string   `json:"pod_selector"`
			CommandAllowlist  []string `json:"command_allowlist"`
			CommandDenylist   []string `json:"command_denylist"`
			RequireApproval   *bool    `json:"require_approval"`
			MaxSessionMinutes int      `json:"max_session_minutes"`
			AuditEnabled      *bool    `json:"audit_enabled"`
			Enabled           *bool    `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		policy := terminalPolicyFromInput(in.ID, in.Name, in.Role, in.ClusterID, in.NamespacePattern, in.PodSelector, in.CommandAllowlist, in.CommandDenylist, in.MaxSessionMinutes)
		if policy.Name == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name is required", "invalid_request_error", "missing_name")
			return
		}
		if len(policy.CommandAllowlist) == 0 {
			writeOpenAIError(w, http.StatusBadRequest, "command_allowlist must include at least one safe command pattern", "invalid_request_error", "missing_allowlist")
			return
		}
		if in.RequireApproval != nil {
			policy.RequireApproval = *in.RequireApproval
		}
		if in.AuditEnabled != nil {
			policy.AuditEnabled = *in.AuditEnabled
		}
		if in.Enabled != nil {
			policy.Enabled = *in.Enabled
		}
		if err := s.db.UpsertK8sTerminalPolicy(r.Context(), policy); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "terminal_policy_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.terminal_policy.upsert", policy.ID, auditJSON(map[string]any{
			"name": policy.Name, "role": policy.Role, "cluster_id": policy.ClusterID, "namespace_pattern": policy.NamespacePattern,
		}))
		writeJSON(w, http.StatusCreated, map[string]any{"policy": policy})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sTerminalPolicyByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/terminal-policies/"), "/")
	if trimmed == "evaluate" {
		if r.Method != http.MethodPost {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sTerminalPolicyEvaluate(w, r)
		return
	}
	id, _ := url.PathUnescape(trimmed)
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "policy id is required", "invalid_request_error", "missing_policy_id")
		return
	}
	if r.Method != http.MethodDelete {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if err := s.db.DeleteK8sTerminalPolicy(r.Context(), id); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "terminal_policy_delete_failed")
		return
	}
	s.auditAdmin(r, "k8s.terminal_policy.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

func (s *Server) handleK8sTerminalPolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	var req terminalPolicyEvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	req.ClusterID = strings.TrimSpace(req.ClusterID)
	req.Namespace = strings.TrimSpace(req.Namespace)
	req.Command = strings.TrimSpace(req.Command)
	if req.Role == "" || req.Namespace == "" || req.Command == "" {
		writeOpenAIError(w, http.StatusBadRequest, "role, namespace and command are required", "invalid_request_error", "missing_fields")
		return
	}
	policies, err := s.db.ListK8sTerminalPolicies(r.Context(), store.K8sTerminalPolicyFilter{Role: req.Role, ClusterID: req.ClusterID, Enabled: "true", Limit: 500})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "terminal_policy_eval_failed")
		return
	}
	result := evaluateTerminalPolicy(req, policies)
	s.auditAdmin(r, "k8s.terminal_policy.evaluate", "", auditJSON(map[string]any{
		"role": req.Role, "cluster_id": req.ClusterID, "namespace": req.Namespace, "pod": req.Pod,
		"allowed": result.Allowed, "risk": result.RiskLevel, "matched_policies": result.MatchedPolicies,
	}))
	writeJSON(w, http.StatusOK, map[string]any{"result": result})
}

func terminalPolicyFromInput(id, name, role, clusterID, namespacePattern, podSelector string, allow, deny []string, maxSession int) store.K8sTerminalPolicy {
	if id == "" {
		id = newID("k8stp")
	}
	p := store.K8sTerminalPolicy{
		ID: id, Name: strings.TrimSpace(name), Role: strings.ToLower(strings.TrimSpace(role)),
		ClusterID: strings.TrimSpace(clusterID), NamespacePattern: strings.TrimSpace(namespacePattern),
		PodSelector: strings.TrimSpace(podSelector), CommandAllowlist: cleanStringList(allow), CommandDenylist: cleanStringList(deny),
		RequireApproval: true, MaxSessionMinutes: maxSession, AuditEnabled: true, Enabled: true,
	}
	if p.Role == "" {
		p.Role = "*"
	}
	if p.NamespacePattern == "" {
		p.NamespacePattern = "*"
	}
	if p.MaxSessionMinutes <= 0 {
		p.MaxSessionMinutes = 10
	}
	if len(p.CommandDenylist) == 0 {
		p.CommandDenylist = builtinTerminalDenylist()
	}
	return p
}

func evaluateTerminalPolicy(req terminalPolicyEvalRequest, policies []store.K8sTerminalPolicy) terminalPolicyEvalResult {
	parsed := analyzer.ParseCommandRisk(req.Command)
	commandRisk, commandRiskReason := parsed.Risk, analyzer.CommandRiskReason(parsed)
	result := terminalPolicyEvalResult{
		Allowed: false, RequireApproval: true, AuditEnabled: true, MaxSessionMinutes: 10,
		RiskLevel: commandRisk, Reason: "no enabled terminal policy matched this role/cluster/namespace/selector",
		CommandRisk: parsed.Findings,
	}
	if commandRisk == "critical" {
		result.Reason = commandRiskReason
		result.MatchedRules = []string{commandRiskReason}
		return result
	}
	matched := []store.K8sTerminalPolicy{}
	for _, p := range policies {
		if !terminalPolicyScopeMatches(req, p) {
			continue
		}
		matched = append(matched, p)
		result.MatchedPolicies = append(result.MatchedPolicies, p.ID)
	}
	if len(matched) == 0 {
		return result
	}
	selected := []store.K8sTerminalPolicy{}
	for _, p := range matched {
		for _, pattern := range append(builtinTerminalDenylist(), p.CommandDenylist...) {
			if terminalCommandMatches(pattern, req.Command) {
				result.Allowed = false
				result.RequireApproval = true
				result.RiskLevel = maxTerminalRisk(result.RiskLevel, "high")
				result.Reason = "command denied by policy pattern: " + pattern
				result.MatchedRules = append(result.MatchedRules, "deny:"+pattern)
				return result
			}
		}
		if terminalAllowlistMatches(p.CommandAllowlist, req.Command) {
			selected = append(selected, p)
			for _, pattern := range p.CommandAllowlist {
				if terminalCommandMatches(pattern, req.Command) {
					result.MatchedRules = append(result.MatchedRules, "allow:"+pattern)
					break
				}
			}
		}
	}
	if len(selected) == 0 {
		result.Reason = "matched policies did not allow this command"
		result.RiskLevel = maxTerminalRisk(result.RiskLevel, "medium")
		return result
	}
	result.Allowed = true
	result.RequireApproval = false
	result.AuditEnabled = false
	result.MaxSessionMinutes = 0
	for _, p := range selected {
		if p.RequireApproval {
			result.RequireApproval = true
		}
		if p.AuditEnabled {
			result.AuditEnabled = true
		}
		if result.MaxSessionMinutes == 0 || p.MaxSessionMinutes < result.MaxSessionMinutes {
			result.MaxSessionMinutes = p.MaxSessionMinutes
		}
	}
	result.RiskLevel = commandRisk
	result.Reason = "command allowed by terminal policy"
	if commandRiskReason != "" {
		result.Reason += " · " + commandRiskReason
	}
	result.MatchedPolicies = uniqueStrings(result.MatchedPolicies)
	result.MatchedRules = uniqueStrings(result.MatchedRules)
	return result
}

func terminalPolicyScopeMatches(req terminalPolicyEvalRequest, p store.K8sTerminalPolicy) bool {
	role := strings.ToLower(strings.TrimSpace(p.Role))
	if role != "" && role != "*" && role != req.Role {
		return false
	}
	if p.ClusterID != "" && p.ClusterID != req.ClusterID {
		return false
	}
	if !terminalWildcardMatch(firstNonEmpty(p.NamespacePattern, "*"), req.Namespace) {
		return false
	}
	return labelSelectorMatches(p.PodSelector, req.PodLabels)
}

func terminalAllowlistMatches(patterns []string, command string) bool {
	for _, pattern := range patterns {
		if terminalCommandMatches(pattern, command) {
			return true
		}
	}
	return false
}

// classifyTerminalCommandRisk delegates to the analyzer's tokenizing Command Risk Parser, which
// also catches shell metacharacters (pipe-to-shell, redirect to system paths, subshell, chaining)
// that the old substring lists missed. Signature preserved for existing call sites.
func classifyTerminalCommandRisk(command string) (string, string) {
	r := analyzer.ParseCommandRisk(command)
	return r.Risk, analyzer.CommandRiskReason(r)
}

func terminalCommandMatches(pattern, command string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	c := strings.ToLower(strings.TrimSpace(command))
	if p == "" || c == "" {
		return false
	}
	if strings.Contains(p, "*") {
		return terminalWildcardMatch(p, c)
	}
	if p == c || strings.HasPrefix(c, p+" ") {
		return true
	}
	if strings.Contains(p, " ") {
		return strings.Contains(c, p)
	}
	return false
}

func labelSelectorMatches(selector string, labels map[string]string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return true
	}
	for _, raw := range strings.Split(selector, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		if strings.Contains(part, "!=") {
			bits := strings.SplitN(part, "!=", 2)
			if labels[strings.TrimSpace(bits[0])] == strings.TrimSpace(bits[1]) {
				return false
			}
			continue
		}
		if strings.Contains(part, "=") {
			bits := strings.SplitN(part, "=", 2)
			if labels[strings.TrimSpace(bits[0])] != strings.TrimSpace(bits[1]) {
				return false
			}
			continue
		}
		if _, ok := labels[part]; !ok {
			return false
		}
	}
	return true
}

func terminalWildcardMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	last := parts[len(parts)-1]
	if last != "" && !strings.HasSuffix(pattern, "*") && !strings.HasSuffix(value, last) {
		return false
	}
	return true
}

func builtinTerminalDenylist() []string {
	return []string{"rm -rf /", "rm -rf", "dd if=", "dd of=", "mkfs", "shutdown", "reboot", "halt", "curl * | sh", "wget * | sh", "kubectl delete", "apt-get install", "apt install", "yum install", "dnf install", "apk add"}
}

func terminalCommandPresets() map[string][]string {
	return map[string][]string{
		"read_only": []string{"ls", "pwd", "cat", "head", "tail", "grep", "env", "printenv", "ps", "df", "du", "date", "id", "whoami"},
		"network":   []string{"curl", "wget", "nslookup", "dig", "nc", "netstat", "ss"},
		"runtime":   []string{"ps", "top", "free", "df", "du", "jcmd", "jstack"},
	}
}

func cleanStringList(values []string) []string {
	out := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, "\n") {
			for _, token := range strings.Split(part, ",") {
				token = strings.TrimSpace(token)
				if token != "" {
					out = append(out, token)
				}
			}
		}
	}
	sort.Strings(out)
	return uniqueStrings(out)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func maxTerminalRisk(a, b string) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if rank[b] > rank[a] {
		return b
	}
	if a == "" {
		return b
	}
	return a
}

func formatTerminalPolicySummary(p store.K8sTerminalPolicy) string {
	return fmt.Sprintf("%s role=%s ns=%s allow=%d deny=%d approval=%t", p.Name, firstNonEmpty(p.Role, "*"), firstNonEmpty(p.NamespacePattern, "*"), len(p.CommandAllowlist), len(p.CommandDenylist), p.RequireApproval)
}
