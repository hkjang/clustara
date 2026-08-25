package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
	"github.com/gorilla/websocket"
)

func TestInteractiveTerminalTicketIsShortLivedAndSingleUse(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	createReadyTerminalTestSession(t, db, "session-1")
	req := terminalTestRequest("/admin/k8s/exec/sessions/session-1/stream?ticket=once")
	if err := db.CreateK8sTerminalTicket(t.Context(), "once", store.K8sTerminalTicket{
		SessionID: "session-1", AdminID: "admin_test", ClientIP: "192.0.2.1",
		UserAgentHash: hashProxyKey(req.UserAgent()), ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	auth, ok := s.consumeTerminalTicket(req, "session-1", "once")
	if !ok || auth.AdminID != "admin_test" {
		t.Fatal("valid terminal ticket should be accepted")
	}
	if _, ok := s.consumeTerminalTicket(req, "session-1", "once"); ok {
		t.Fatal("terminal ticket must be single use")
	}
	if err := db.CreateK8sTerminalTicket(t.Context(), "expired", store.K8sTerminalTicket{
		SessionID: "session-1", ClientIP: "192.0.2.1",
		UserAgentHash: hashProxyKey(req.UserAgent()), ExpiresAt: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.consumeTerminalTicket(req, "session-1", "expired"); ok {
		t.Fatal("expired terminal ticket must be rejected")
	}
	sess, err := db.GetK8sPodExecSession(t.Context(), "session-1")
	if err != nil || sess.Status != "connecting" {
		t.Fatalf("ticket consume must atomically claim ready session: %+v err=%v", sess, err)
	}
}

func TestTerminalTicketPassesCommonAdminGateWithoutBearerHeader(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	issuer := &Server{db: db}
	consumer := &Server{db: db}
	consumer.cfg.Auth.Enabled = true
	createReadyTerminalTestSession(t, db, "session-1")
	streamReq := terminalTestRequest("/admin/k8s/exec/sessions/session-1/stream?ticket=stream-ticket")
	if err := issuer.db.CreateK8sTerminalTicket(t.Context(), "stream-ticket", store.K8sTerminalTicket{
		SessionID:     "session-1",
		AdminID:       "admin_ticket_owner",
		ClientIP:      "192.0.2.1",
		UserAgentHash: hashProxyKey(streamReq.UserAgent()),
		ExpiresAt:     time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	protected := consumer.withAdminAccessUX(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := terminalStreamAuthFromRequest(r)
		if !ok || auth.SessionID != "session-1" || adminID(r) != "admin_ticket_owner" {
			t.Fatalf("terminal stream identity was not propagated: %+v ok=%v actor=%q", auth, ok, adminID(r))
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, streamReq)
	if rr.Code != http.StatusSwitchingProtocols {
		t.Fatalf("ticket-authenticated websocket upgrade must pass admin gate, got %d", rr.Code)
	}
	if _, ok := issuer.consumeTerminalTicket(terminalTestRequest(streamReq.URL.String()), "session-1", "stream-ticket"); ok {
		t.Fatal("terminal ticket consumed by another replica must remain one-use")
	}
}

func TestWrongMethodDoesNotConsumeTerminalTicket(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	s.cfg.Auth.Enabled = true
	createReadyTerminalTestSession(t, db, "session-method")
	if err := db.CreateK8sTerminalTicket(t.Context(), "method-ticket", store.K8sTerminalTicket{
		SessionID: "session-method", AdminID: "usr_operator", ClientIP: "192.0.2.1",
		UserAgentHash: hashProxyKey("terminal-test"), ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	postReq := terminalTestRequest("/admin/k8s/exec/sessions/session-method/stream?ticket=method-ticket")
	postReq.Method = http.MethodPost
	postRR := httptest.NewRecorder()
	s.handleK8sExecSessionByID(postRR, postReq)
	if postRR.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-method ticket request should be rejected before consume, got %d", postRR.Code)
	}
	if _, ok := s.consumeTerminalTicket(terminalTestRequest("/admin/k8s/exec/sessions/session-method/stream?ticket=method-ticket"), "session-method", "method-ticket"); !ok {
		t.Fatal("wrong HTTP method must leave terminal ticket unused")
	}
}

func TestTerminalTicketsRaceForOneSessionClaim(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	first := &Server{db: db}
	second := &Server{db: db}
	createReadyTerminalTestSession(t, db, "session-race")
	for _, ticket := range []string{"race-a", "race-b"} {
		if err := db.CreateK8sTerminalTicket(t.Context(), ticket, store.K8sTerminalTicket{
			SessionID: "session-race", AdminID: "usr_operator", ClientIP: "192.0.2.1",
			UserAgentHash: hashProxyKey("terminal-test"), ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan bool, 2)
	for i, server := range []*Server{first, second} {
		ticket := []string{"race-a", "race-b"}[i]
		go func() {
			<-start
			_, ok := server.consumeTerminalTicket(terminalTestRequest("/admin/k8s/exec/sessions/session-race/stream?ticket="+ticket), "session-race", ticket)
			results <- ok
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if <-results {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("exactly one replica may claim a ready terminal session, got %d", successes)
	}
	sess, err := db.GetK8sPodExecSession(t.Context(), "session-race")
	if err != nil || sess.Status != "connecting" || sess.ExecutedBy != "usr_operator" {
		t.Fatalf("unexpected claimed terminal session: %+v err=%v", sess, err)
	}
}

func TestTerminalTicketIsBoundToClientAndActiveAuthSession(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	createReadyTerminalTestSession(t, db, "session-bound")
	if err := db.CreateAuthUser(t.Context(), store.AuthUser{
		ID: "usr_operator", Email: "operator@example.com", PasswordHash: "unused", Role: "super_admin", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertAuthSession(t.Context(), "auth-session", "usr_operator", "192.0.2.1", "terminal-test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateK8sTerminalTicket(t.Context(), "bound", store.K8sTerminalTicket{
		SessionID: "session-bound", AdminID: "usr_operator", AuthSessionID: "auth-session",
		AuthExpiresAt: time.Now().Add(time.Hour), ClientIP: "192.0.2.1",
		UserAgentHash: hashProxyKey("terminal-test"), ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	wrongClient := terminalTestRequest("/admin/k8s/exec/sessions/session-bound/stream?ticket=bound")
	wrongClient.RemoteAddr = "198.51.100.9:4321"
	if _, ok := s.consumeTerminalTicket(wrongClient, "session-bound", "bound"); ok {
		t.Fatal("ticket must not be usable from a different client IP")
	}
	if err := db.CreateAuthUser(t.Context(), store.AuthUser{
		ID: "usr_operator", Email: "operator@example.com", PasswordHash: "unused", Role: "super_admin", Status: "active", MustChangePassword: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.consumeTerminalTicket(terminalTestRequest("/admin/k8s/exec/sessions/session-bound/stream?ticket=bound"), "session-bound", "bound"); ok {
		t.Fatal("ticket-only stream must enforce a newly required password change")
	}
	if err := db.CreateAuthUser(t.Context(), store.AuthUser{
		ID: "usr_operator", Email: "operator@example.com", PasswordHash: "unused", Role: "super_admin", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeAuthSession(t.Context(), "auth-session"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.consumeTerminalTicket(terminalTestRequest("/admin/k8s/exec/sessions/session-bound/stream?ticket=bound"), "session-bound", "bound"); ok {
		t.Fatal("ticket must not outlive revocation of its issuing auth session")
	}
	sess, err := db.GetK8sPodExecSession(t.Context(), "session-bound")
	if err != nil || sess.Status != "ready" {
		t.Fatalf("rejected ticket must not claim the exec session: %+v err=%v", sess, err)
	}
}

func TestStaleTerminalConnectionRecoveryFencesOldProcess(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	createReadyTerminalTestSession(t, db, "session-stale")
	if _, err := db.MarkK8sPodExecSessionConnecting(t.Context(), "session-stale", "usr_operator", "claim-old"); err != nil {
		t.Fatal(err)
	}
	recovered, err := db.RecoverStaleK8sPodExecSessionConnection(t.Context(), "session-stale", time.Now().Add(time.Second))
	if err != nil || !recovered {
		t.Fatalf("stale connecting session was not recovered: recovered=%v err=%v", recovered, err)
	}
	if _, err := db.MarkK8sPodExecSessionConnected(t.Context(), "session-stale", "claim-old"); err == nil {
		t.Fatal("old process must not connect a recovered session")
	}
	if _, err := db.MarkK8sPodExecSessionConnecting(t.Context(), "session-stale", "usr_operator", "claim-new"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MarkK8sPodExecSessionConnected(t.Context(), "session-stale", "claim-old"); err == nil {
		t.Fatal("old process must not complete another process's connecting claim")
	}
	if _, err := db.MarkK8sPodExecSessionConnected(t.Context(), "session-stale", "claim-new"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateK8sPodTerminalSessionExecution(t.Context(), "session-stale", "claim-old", "failed", "usr_operator", "", "late close", 1); err == nil {
		t.Fatal("old process must not finalize the new process's terminal")
	}
	done, err := db.UpdateK8sPodTerminalSessionExecution(t.Context(), "session-stale", "claim-new", "completed", "usr_operator", "ok", "", 0)
	if err != nil || done.Status != "completed" {
		t.Fatalf("new fenced terminal claim did not finalize: %+v err=%v", done, err)
	}
}

func TestAdminIDUsesVerifiedStableSubject(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	s.cfg.Auth.Enabled = true
	s.cfg.Auth.JWTSecret = "terminal-test-secret"
	if err := db.InsertAuthSession(t.Context(), "stable-session", "usr_stable", "192.0.2.1", "terminal-test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	token, err := s.signAccessToken(accessClaims{
		Subject: "usr_stable", Role: "super_admin", Scopes: []string{"admin:read"},
		SessionID: "stable-session", ExpiresAt: time.Now().Add(time.Hour).Unix(), Type: "access",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/k8s/exec/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if !s.authorizeAdmin(req) {
		t.Fatal("signed administrator token should authorize")
	}
	if got := adminID(req); got != "usr_stable" {
		t.Fatalf("admin actor must use stable token subject, got %q", got)
	}
}

func TestTerminalStreamRequiresTicketEvenWithVerifiedReadClaims(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	s := &Server{db: db}
	s.cfg.Auth.Enabled = true
	createReadyTerminalTestSession(t, db, "session-no-ticket")

	req := terminalTestRequest("/admin/k8s/exec/sessions/session-no-ticket/stream")
	cacheVerifiedAccessClaims(req, accessClaims{
		Subject: "usr_reader",
		Role:    "viewer",
		Scopes:  []string{"admin:read"},
		Type:    "access",
	})
	rr := httptest.NewRecorder()
	s.handleK8sExecSessionByID(rr, req)

	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), `"code":"terminal_ticket_required"`) {
		t.Fatalf("verified admin:read claims must not replace a terminal ticket: status=%d body=%s", rr.Code, rr.Body.String())
	}
	sess, err := db.GetK8sPodExecSession(t.Context(), "session-no-ticket")
	if err != nil || sess.Status != "ready" {
		t.Fatalf("ticket-less stream must leave the session ready: %+v err=%v", sess, err)
	}
}

func TestAdminIDPrefersTerminalTicketIdentityOverVerifiedClaims(t *testing.T) {
	req := terminalTestRequest("/admin/k8s/exec/sessions/session-identity/stream")
	cacheVerifiedAccessClaims(req, accessClaims{Subject: "usr_bearer_a"})
	req = withTerminalStreamAuth(req, terminalStreamAuth{
		SessionID: "session-identity",
		AdminID:   "usr_ticket_b",
		ClaimID:   "claim-b",
	})

	if got := adminID(req); got != "usr_ticket_b" {
		t.Fatalf("terminal stream actor must come from the consumed ticket, got %q", got)
	}
}

func TestCanceledPodExecFinalizesSessionWithBackgroundContext(t *testing.T) {
	execStarted := make(chan struct{})
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "websocket upgrade unavailable", http.StatusBadRequest)
			return
		}
		select {
		case <-execStarted:
		default:
			close(execStarted)
		}
		<-r.Context().Done()
	}))
	defer kubeAPI.Close()

	db := openTestStore(t)
	defer db.Close()
	if err := db.UpsertK8sCluster(t.Context(), store.K8sCluster{
		ID: "cluster-cancel", Name: "cancel-test", ServerURL: kubeAPI.URL, Status: "ready",
	}); err != nil {
		t.Fatal(err)
	}
	sess := store.K8sPodExecSession{
		ID: "session-cancel", ClusterID: "cluster-cancel", Namespace: "default", Pod: "api-1", Container: "app",
		Command: "echo ok", Role: "super_admin", RequestedBy: "usr_operator", Status: "ready",
		AuditEnabled: true, PolicyResult: `{"access_mode":"command"}`,
	}
	if err := db.CreateK8sPodExecSession(t.Context(), &sess); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/admin/k8s/exec/sessions/session-cancel/execute", nil).WithContext(ctx)
	cacheVerifiedAccessClaims(req, accessClaims{Subject: "usr_operator"})
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.executeK8sPodExecSession(rr, req, sess)
	}()

	select {
	case <-execStarted:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("fake PodExec did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled PodExec handler did not return")
	}

	stored, err := db.GetK8sPodExecSession(t.Context(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "failed" || stored.ExecutedBy != "usr_operator" || stored.ErrorMessage == "" {
		t.Fatalf("canceled execution must be durably finalized as failed: %+v", stored)
	}
}

func TestTerminalBrowserWriteDeadlineStopsStalledReader(t *testing.T) {
	type writeResult struct {
		err     error
		elapsed time.Duration
	}
	startWrite := make(chan struct{})
	result := make(chan writeResult, 1)
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		browser, err := terminalUpgrader.Upgrade(w, r, nil)
		if err != nil {
			result <- writeResult{err: err}
			return
		}
		defer browser.Close()
		<-startWrite
		started := time.Now()
		chunk := make([]byte, 1<<20)
		for err == nil {
			err = writeTerminalBrowserBinary(browser, chunk)
		}
		result <- writeResult{err: err, elapsed: time.Since(started)}
	}))
	defer wsServer.Close()

	wsURL := "ws" + strings.TrimPrefix(wsServer.URL, "http")
	stalledReader, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stalledReader.Close()
	tcp, ok := stalledReader.UnderlyingConn().(*net.TCPConn)
	if !ok {
		t.Fatalf("unexpected WebSocket transport %T", stalledReader.UnderlyingConn())
	}
	if err := tcp.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	close(startWrite)

	select {
	case got := <-result:
		if got.err == nil {
			t.Fatal("writes to a stalled browser must fail at the write deadline")
		}
		netErr, ok := got.err.(net.Error)
		if !ok || !netErr.Timeout() {
			t.Fatalf("stalled browser write must end with a timeout, got %T: %v", got.err, got.err)
		}
		if got.elapsed > terminalBrowserWriteTimeout+2*time.Second {
			t.Fatalf("stalled browser write exceeded its deadline: elapsed=%v timeout=%v", got.elapsed, terminalBrowserWriteTimeout)
		}
	case <-time.After(terminalBrowserWriteTimeout + 3*time.Second):
		t.Fatal("stalled browser write did not return after its deadline")
	}
}

func createReadyTerminalTestSession(t *testing.T, db *store.SQLStore, id string) {
	t.Helper()
	sess := store.K8sPodExecSession{
		ID: id, ClusterID: "cluster-1", Namespace: "default", Pod: "api-1", Container: "app",
		Command: "/bin/sh", Role: "super_admin", RequestedBy: "usr_operator", Status: "ready",
		AuditEnabled: true, PolicyResult: `{"access_mode":"full_tty"}`,
	}
	if err := db.CreateK8sPodExecSession(context.Background(), &sess); err != nil {
		t.Fatal(err)
	}
}

func terminalTestRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("User-Agent", "terminal-test")
	return req
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
