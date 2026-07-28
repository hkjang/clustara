package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestInteractiveTerminalTicketIsShortLivedAndSingleUse(t *testing.T) {
	s := &Server{}
	s.terminalTickets.Store("once", terminalTicket{SessionID: "session-1", AdminID: "admin_test", ExpiresAt: time.Now().Add(time.Minute)})
	auth, ok := s.consumeTerminalTicket("session-1", "once")
	if !ok || auth.AdminID != "admin_test" {
		t.Fatal("valid terminal ticket should be accepted")
	}
	if _, ok := s.consumeTerminalTicket("session-1", "once"); ok {
		t.Fatal("terminal ticket must be single use")
	}
	s.terminalTickets.Store("expired", terminalTicket{SessionID: "session-1", ExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := s.consumeTerminalTicket("session-1", "expired"); ok {
		t.Fatal("expired terminal ticket must be rejected")
	}
}

func TestTerminalTicketPassesCommonAdminGateWithoutBearerHeader(t *testing.T) {
	s := &Server{}
	s.cfg.Auth.Enabled = true
	s.terminalTickets.Store("stream-ticket", terminalTicket{
		SessionID: "session-1",
		AdminID:   "admin_ticket_owner",
		ExpiresAt: time.Now().Add(time.Minute),
	})
	protected := s.withAdminAccessUX(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := terminalStreamAuthFromRequest(r)
		if !ok || auth.SessionID != "session-1" || adminID(r) != "admin_ticket_owner" {
			t.Fatalf("terminal stream identity was not propagated: %+v ok=%v actor=%q", auth, ok, adminID(r))
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/k8s/exec/sessions/session-1/stream?ticket=stream-ticket", nil)
	protected.ServeHTTP(rr, req)
	if rr.Code != http.StatusSwitchingProtocols {
		t.Fatalf("ticket-authenticated websocket upgrade must pass admin gate, got %d", rr.Code)
	}

	if _, exists := s.terminalTickets.Load("stream-ticket"); exists {
		t.Fatal("terminal ticket must be consumed by the common gate")
	}
}

func TestOfflineXtermAssetsAndAdminUIAreEmbedded(t *testing.T) {
	s := &Server{}
	for _, path := range []string{"xterm.js", "xterm.css", "LICENSE.txt"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/admin/assets/xterm/"+path, nil)
		s.handleAdminTerminalAsset(rr, req)
		if rr.Code != 200 || rr.Body.Len() < 100 {
			t.Fatalf("asset %s status=%d bytes=%d", path, rr.Code, rr.Body.Len())
		}
		if !strings.Contains(rr.Header().Get("Cache-Control"), "immutable") {
			t.Fatalf("asset %s should be immutable", path)
		}
	}
	for _, marker := range []string{"/admin/assets/xterm/xterm.js?v=6.0.0", "new TerminalCtor(", "k8sTerminalEnsureLibrary", "k8stty-pod-options", "k8sTerminalPreviewPods", "authRefreshPromise", "관리자 웹 터미널", "#/k8s-terminal"} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("admin UI missing terminal marker %q", marker)
		}
	}
}

func TestOfflineXtermAssetsBypassBearerAdminGate(t *testing.T) {
	s := &Server{}
	s.cfg.Auth.Enabled = true
	protected := s.withAdminAccessUX(http.HandlerFunc(s.handleAdminTerminalAsset))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/assets/xterm/xterm.js?v=6.0.0", nil)
	protected.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.Len() < 100 {
		t.Fatalf("embedded browser asset must load without Authorization header: status=%d bytes=%d", rr.Code, rr.Body.Len())
	}
}

func TestFullTTYPolicyTemplateAllowsOnlyApprovedShellEntry(t *testing.T) {
	var found bool
	for _, template := range terminalPolicyTemplates() {
		if template.Key != "admin_full_tty" {
			continue
		}
		found = true
		if !template.RequireApproval || template.MaxSessionMinutes <= 0 || !terminalAllowlistMatches(template.CommandAllowlist, "/bin/bash") {
			t.Fatalf("unsafe full TTY template: %+v", template)
		}
		result := evaluateTerminalPolicy(terminalPolicyEvalRequest{Role: template.Role, Namespace: "default", Command: "/bin/bash"}, []store.K8sTerminalPolicy{{
			ID: "full-tty", Role: template.Role, NamespacePattern: template.NamespacePattern, CommandAllowlist: template.CommandAllowlist,
			RequireApproval: template.RequireApproval, AuditEnabled: true, MaxSessionMinutes: template.MaxSessionMinutes, Enabled: true,
		}})
		if !result.Allowed || !result.RequireApproval || !result.AuditEnabled || result.AccessMode != "full_tty" {
			t.Fatalf("interactive shell must be allowed only as approved audited full_tty: %+v", result)
		}
	}
	if !found {
		t.Fatal("admin full TTY policy template missing")
	}
}

func TestSuperAdminHasAuditedPolicyFreeInteractiveTerminal(t *testing.T) {
	req := terminalPolicyEvalRequest{Role: "super_admin", ClusterID: "prod", Namespace: "default", Pod: "api-1", Command: "/bin/bash"}
	result := applySuperAdminTerminalDefault(req, evaluateTerminalPolicy(req, nil))
	if !result.Allowed || result.RequireApproval || !result.AuditEnabled || result.MaxSessionMinutes != 15 || result.AccessMode != "full_tty" {
		t.Fatalf("super admin terminal default is not usable and audited: %+v", result)
	}
	if len(result.MatchedPolicies) != 1 || result.MatchedPolicies[0] != "builtin:super_admin_full_tty" {
		t.Fatalf("built-in policy evidence missing: %+v", result)
	}
	viewerReq := terminalPolicyEvalRequest{Role: "viewer", Namespace: "default", Command: "/bin/bash"}
	viewer := applySuperAdminTerminalDefault(viewerReq, evaluateTerminalPolicy(viewerReq, nil))
	if viewer.Allowed {
		t.Fatal("built-in terminal default must not apply to non-super-admin roles")
	}
}
