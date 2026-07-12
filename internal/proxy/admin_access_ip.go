package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"clustara/internal/store"
)

const adminBreakGlassHeader = "X-Clustara-Break-Glass"

type adminIPPolicy struct {
	Enabled           bool
	AllowedRaw        string
	TrustedProxiesRaw string
	EmergencyToken    string
	Allowed           []*net.IPNet
	TrustedProxies    []*net.IPNet
	ConfigError       string
}

type resolvedClientIP struct {
	IP           net.IP
	Text         string
	Source       string
	TrustedProxy bool
}

func splitIPCIDRList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	})
}

func parseIPCIDRList(value string) ([]*net.IPNet, error) {
	items := splitIPCIDRList(value)
	out := make([]*net.IPNet, 0, len(items))
	for _, item := range items {
		if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", item)
		}
		out = append(out, network)
	}
	return out, nil
}

func validateIPCIDRListSetting(value string) error {
	_, err := parseIPCIDRList(value)
	return err
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func remotePeerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return net.ParseIP(strings.TrimSpace(host))
	}
	return net.ParseIP(strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]"))
}

// resolvePolicyClientIP trusts forwarding headers only when the direct peer belongs to an
// explicitly configured proxy network. For X-Forwarded-For it walks right-to-left and returns
// the first untrusted hop, preventing a caller-prepended value from bypassing a trusted chain.
func resolvePolicyClientIP(r *http.Request, trusted []*net.IPNet) resolvedClientIP {
	peer := remotePeerIP(r)
	peerText := ""
	if peer != nil {
		peerText = peer.String()
	}
	if !ipInNetworks(peer, trusted) {
		return resolvedClientIP{IP: peer, Text: peerText, Source: "remote_addr"}
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(parts[i]))
			if ip != nil && !ipInNetworks(ip, trusted) {
				return resolvedClientIP{IP: ip, Text: ip.String(), Source: "x_forwarded_for", TrustedProxy: true}
			}
		}
	}
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get(header))); ip != nil {
			return resolvedClientIP{IP: ip, Text: ip.String(), Source: strings.ToLower(strings.ReplaceAll(header, "-", "_")), TrustedProxy: true}
		}
	}
	return resolvedClientIP{IP: peer, Text: peerText, Source: "trusted_proxy_peer", TrustedProxy: true}
}

func (s *Server) buildAdminIPPolicy(stored map[string]store.AdminSetting) *adminIPPolicy {
	policy := &adminIPPolicy{}
	values := map[string]string{}
	for _, key := range []string{
		"security.admin_access.ip_allowlist_enabled",
		"security.admin_access.allowed_cidrs",
		"security.admin_access.trusted_proxy_cidrs",
		"security.admin_access.emergency_token",
	} {
		if def, ok := settingDefByKey(key); ok {
			values[key], _ = s.effectiveSettingValue(stored, def)
		}
	}
	policy.Enabled, _ = strconv.ParseBool(strings.TrimSpace(values["security.admin_access.ip_allowlist_enabled"]))
	policy.AllowedRaw = strings.TrimSpace(values["security.admin_access.allowed_cidrs"])
	policy.TrustedProxiesRaw = strings.TrimSpace(values["security.admin_access.trusted_proxy_cidrs"])
	policy.EmergencyToken = strings.TrimSpace(values["security.admin_access.emergency_token"])
	var err error
	policy.Allowed, err = parseIPCIDRList(policy.AllowedRaw)
	if err != nil {
		policy.ConfigError = err.Error()
	}
	policy.TrustedProxies, err = parseIPCIDRList(policy.TrustedProxiesRaw)
	if err != nil && policy.ConfigError == "" {
		policy.ConfigError = err.Error()
	}
	if policy.Enabled && len(policy.Allowed) == 0 && policy.ConfigError == "" {
		policy.ConfigError = "enabled policy requires at least one allowed IP or CIDR"
	}
	return policy
}

func (s *Server) currentAdminIPPolicy() *adminIPPolicy {
	if policy := s.adminIPPolicy.Load(); policy != nil {
		return policy
	}
	return &adminIPPolicy{}
}

func validBreakGlass(r *http.Request, policy *adminIPPolicy) bool {
	provided := strings.TrimSpace(r.Header.Get(adminBreakGlassHeader))
	if provided == "" || policy == nil || policy.EmergencyToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(policy.EmergencyToken)) == 1
}

func isAdministratorRole(role string) bool {
	switch role {
	case "super_admin", "admin", "service_admin", "ops_admin", "ai_admin", "security_admin", "billing_admin", "team_admin", "readonly_admin":
		return true
	default:
		return false
	}
}

func (s *Server) requestHasAdministratorIdentity(r *http.Request) bool {
	if s.cfg.Auth.Enabled {
		claims, ok := s.currentAccessClaims(r)
		return ok && isAdministratorRole(claims.Role)
	}
	role, _, ok := s.legacyTokenIdentity(r)
	return ok && isAdministratorRole(role)
}

func (s *Server) auditIPPolicyDecision(r *http.Request, event, detail string) {
	claims, _ := s.currentAccessClaims(r)
	_ = s.db.InsertAuditEvent(r.Context(), store.AuthEvent{
		ID: newID("ae"), EventType: event, ActorUserID: claims.Subject, TeamID: claims.TeamID,
		IP:        resolvePolicyClientIP(r, s.currentAdminIPPolicy().TrustedProxies).Text,
		UserAgent: r.UserAgent(), Detail: detail, CreatedAt: time.Now().UTC(),
	})
}

func (s *Server) writeAdminIPDenied(w http.ResponseWriter, r *http.Request, resolved resolvedClientIP) {
	s.auditIPPolicyDecision(r, "admin_ip_denied", "path="+r.URL.Path+" resolved_ip="+resolved.Text+" source="+resolved.Source)
	if r.Method == http.MethodGet && strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		target := "/admin#/access-denied?status=403&path=" + url.QueryEscape(r.URL.Path) + "&required=admin-ip-policy"
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	writeOpenAIError(w, http.StatusForbidden, "관리자 접속 IP 허용 정책에 의해 차단되었습니다.", "permission_error", "admin_ip_denied")
}

func (s *Server) withAdminIPPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/admin/") || !s.requestHasAdministratorIdentity(r) {
			next.ServeHTTP(w, r)
			return
		}
		policy := s.currentAdminIPPolicy()
		if !policy.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if validBreakGlass(r, policy) {
			s.auditIPPolicyDecision(r, "admin_ip_break_glass", "path="+r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}
		resolved := resolvePolicyClientIP(r, policy.TrustedProxies)
		if policy.ConfigError != "" || !ipInNetworks(resolved.IP, policy.Allowed) {
			s.writeAdminIPDenied(w, r, resolved)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) enforceAdminLoginIP(w http.ResponseWriter, r *http.Request, user store.AuthUser) bool {
	policy := s.currentAdminIPPolicy()
	if !policy.Enabled || !isAdministratorRole(user.Role) {
		return true
	}
	if validBreakGlass(r, policy) {
		s.auditIPPolicyDecision(r, "admin_ip_break_glass", "path=/auth/login user="+user.ID)
		return true
	}
	resolved := resolvePolicyClientIP(r, policy.TrustedProxies)
	if policy.ConfigError == "" && ipInNetworks(resolved.IP, policy.Allowed) {
		return true
	}
	_ = s.db.InsertLoginAttempt(r.Context(), user.Email, false, resolved.Text, r.UserAgent(), "admin_ip_denied")
	s.writeAdminIPDenied(w, r, resolved)
	return false
}

func (s *Server) adminIPPolicyView(r *http.Request, policy *adminIPPolicy) map[string]any {
	resolved := resolvePolicyClientIP(r, policy.TrustedProxies)
	return map[string]any{
		"enabled": policy.Enabled, "allowed_cidrs": policy.AllowedRaw,
		"trusted_proxy_cidrs":        policy.TrustedProxiesRaw,
		"emergency_token_configured": policy.EmergencyToken != "",
		"current_ip":                 resolved.Text, "current_ip_source": resolved.Source,
		"via_trusted_proxy":  resolved.TrustedProxy,
		"current_ip_allowed": !policy.Enabled || (policy.ConfigError == "" && ipInNetworks(resolved.IP, policy.Allowed)),
		"config_error":       policy.ConfigError,
	}
}

func proposedAdminIPPolicy(enabled bool, allowed, trusted string) (*adminIPPolicy, error) {
	allowedNets, err := parseIPCIDRList(allowed)
	if err != nil {
		return nil, err
	}
	trustedNets, err := parseIPCIDRList(trusted)
	if err != nil {
		return nil, err
	}
	if enabled && len(allowedNets) == 0 {
		return nil, fmt.Errorf("활성화하려면 허용 IP 또는 CIDR이 하나 이상 필요합니다")
	}
	return &adminIPPolicy{Enabled: enabled, AllowedRaw: strings.TrimSpace(allowed), TrustedProxiesRaw: strings.TrimSpace(trusted), Allowed: allowedNets, TrustedProxies: trustedNets}, nil
}

func (s *Server) handleAdminAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.adminIPPolicyView(r, s.currentAdminIPPolicy()))
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var payload struct {
		Enabled           bool   `json:"enabled"`
		AllowedCIDRs      string `json:"allowed_cidrs"`
		TrustedProxyCIDRs string `json:"trusted_proxy_cidrs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	proposed, err := proposedAdminIPPolicy(payload.Enabled, payload.AllowedCIDRs, payload.TrustedProxyCIDRs)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_ip_policy")
		return
	}
	resolved := resolvePolicyClientIP(r, proposed.TrustedProxies)
	allowed := !proposed.Enabled || ipInNetworks(resolved.IP, proposed.Allowed)
	view := s.adminIPPolicyView(r, proposed)
	view["valid"] = true
	view["would_allow_current_ip"] = allowed
	if r.Method == http.MethodPost {
		writeJSON(w, http.StatusOK, view)
		return
	}
	if !allowed && !validBreakGlass(r, s.currentAdminIPPolicy()) {
		writeOpenAIError(w, http.StatusBadRequest, "현재 접속 IP가 새 허용 범위에 없어 정책을 활성화할 수 없습니다.", "invalid_request_error", "ip_policy_lockout_risk")
		return
	}
	// Persist fail-open for crash safety: write disabled first, then the networks, and enable
	// last. The in-memory policy is swapped only after all writes complete.
	changes := []struct{ key, value string }{
		{"security.admin_access.ip_allowlist_enabled", "false"},
		{"security.admin_access.allowed_cidrs", proposed.AllowedRaw},
		{"security.admin_access.trusted_proxy_cidrs", proposed.TrustedProxiesRaw},
	}
	if proposed.Enabled {
		changes = append(changes, struct{ key, value string }{"security.admin_access.ip_allowlist_enabled", "true"})
	}
	for _, change := range changes {
		def, _ := settingDefByKey(change.key)
		if err := s.persistSettingValue(r, def, change.value, "administrator IP access policy"); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "ip_policy_save_failed")
			return
		}
	}
	s.reloadRuntimeConfig(r.Context())
	s.auditAdmin(r, "security.admin_ip_policy.update", "", auditJSON(view))
	writeJSON(w, http.StatusOK, s.adminIPPolicyView(r, s.currentAdminIPPolicy()))
}
