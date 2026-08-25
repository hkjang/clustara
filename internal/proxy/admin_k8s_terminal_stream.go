package proxy

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
	"github.com/gorilla/websocket"
)

//go:embed assets/xterm/xterm-6.0.0.js assets/xterm/xterm-6.0.0.css assets/xterm/LICENSE.xterm.txt
var terminalAssets embed.FS

func (s *Server) handleAdminTerminalAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/admin/assets/xterm/")
	contentType := map[string]string{
		"xterm.js":    "text/javascript; charset=utf-8",
		"xterm.css":   "text/css; charset=utf-8",
		"LICENSE.txt": "text/plain; charset=utf-8",
	}[name]
	source := map[string]string{
		"xterm.js":    "assets/xterm/xterm-6.0.0.js",
		"xterm.css":   "assets/xterm/xterm-6.0.0.css",
		"LICENSE.txt": "assets/xterm/LICENSE.xterm.txt",
	}[name]
	if source == "" {
		http.NotFound(w, r)
		return
	}
	body, err := terminalAssets.ReadFile(source)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

type browserTerminalMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

const terminalBrowserWriteTimeout = 5 * time.Second

func writeTerminalBrowserJSON(browser *websocket.Conn, message browserTerminalMessage) error {
	if err := browser.SetWriteDeadline(time.Now().Add(terminalBrowserWriteTimeout)); err != nil {
		return err
	}
	return browser.WriteJSON(message)
}

func writeTerminalBrowserBinary(browser *websocket.Conn, data []byte) error {
	if err := browser.SetWriteDeadline(time.Now().Add(terminalBrowserWriteTimeout)); err != nil {
		return err
	}
	return browser.WriteMessage(websocket.BinaryMessage, data)
}

type terminalStreamAuthContextKey struct{}

type terminalStreamAuth struct {
	SessionID string
	AdminID   string
	ClaimID   string
}

func (s *Server) issueTerminalTicket(w http.ResponseWriter, r *http.Request, sess store.K8sPodExecSession) {
	if sess.Status == "connecting" {
		staleBefore := time.Now().UTC().Add(-execSessionTimeout(sess.MaxSessionMinutes) - 30*time.Second)
		recovered, err := s.db.RecoverStaleK8sPodExecSessionConnection(r.Context(), sess.ID, staleBefore)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, "stale terminal connection recovery failed", "server_error", "terminal_recovery_failed")
			return
		}
		if recovered {
			sess, err = s.db.GetK8sPodExecSession(r.Context(), sess.ID)
			if err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, "recovered terminal session reload failed", "server_error", "terminal_recovery_failed")
				return
			}
		}
	}
	if sess.Status != "ready" || !isInteractiveShell(sess.Command) || fmt.Sprint(k8sExecSessionPolicy(sess)["access_mode"]) != "full_tty" {
		writeOpenAIError(w, http.StatusConflict, "approved full_tty shell session is required", "invalid_request_error", "terminal_session_not_ready")
		return
	}
	if claims, ok := s.currentAccessClaims(r); ok && claims.PasswordChangeRequired {
		writeOpenAIError(w, http.StatusForbidden, "password change is required before opening a terminal", "permission_error", "password_change_required")
		return
	}
	now := time.Now().UTC()
	ticket := newID("k8stty")
	expires := now.Add(30 * time.Second)
	actor := adminID(r)
	authSessionID := ""
	var authExpiresAt time.Time
	if claims, ok := s.currentAccessClaims(r); ok {
		if strings.TrimSpace(claims.Subject) != "" {
			actor = strings.TrimSpace(claims.Subject)
		}
		authSessionID = strings.TrimSpace(claims.SessionID)
		if claims.ExpiresAt > 0 {
			authExpiresAt = time.Unix(claims.ExpiresAt, 0).UTC()
		}
	}
	resolved := resolvePolicyClientIP(r, s.currentAdminIPPolicy().TrustedProxies)
	if err := s.db.CreateK8sTerminalTicket(r.Context(), ticket, store.K8sTerminalTicket{
		SessionID:     sess.ID,
		AdminID:       actor,
		AuthSessionID: authSessionID,
		AuthExpiresAt: authExpiresAt,
		ClientIP:      resolved.Text,
		UserAgentHash: hashProxyKey(r.UserAgent()),
		ExpiresAt:     expires,
	}); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "terminal ticket issuance failed", "server_error", "terminal_ticket_failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ticket": ticket, "expires_at": expires.Format(time.RFC3339)})
}

func (s *Server) consumeTerminalTicket(r *http.Request, sessionID, ticket string) (terminalStreamAuth, bool) {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" || s.db == nil {
		return terminalStreamAuth{}, false
	}
	policy := s.currentAdminIPPolicy()
	resolved := resolvePolicyClientIP(r, policy.TrustedProxies)
	if policy.Enabled && !validBreakGlass(r, policy) && (policy.ConfigError != "" || !ipInNetworks(resolved.IP, policy.Allowed)) {
		return terminalStreamAuth{}, false
	}
	value, ok, err := s.db.ConsumeK8sTerminalTicketAndClaimSession(
		r.Context(), sessionID, ticket, resolved.Text, hashProxyKey(r.UserAgent()),
	)
	if err != nil || !ok {
		return terminalStreamAuth{}, false
	}
	return terminalStreamAuth{SessionID: value.SessionID, AdminID: value.AdminID, ClaimID: value.ClaimID}, true
}

func terminalStreamSessionID(r *http.Request) (string, bool) {
	const prefix = "/admin/k8s/exec/sessions/"
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, prefix) {
		return "", false
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/"), "/")
	if len(parts) != 2 || parts[1] != "stream" {
		return "", false
	}
	id, err := url.PathUnescape(parts[0])
	return id, err == nil && id != ""
}

func terminalStreamAuthFromRequest(r *http.Request) (terminalStreamAuth, bool) {
	auth, ok := r.Context().Value(terminalStreamAuthContextKey{}).(terminalStreamAuth)
	return auth, ok && auth.SessionID != "" && auth.ClaimID != ""
}

func withTerminalStreamAuth(r *http.Request, auth terminalStreamAuth) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), terminalStreamAuthContextKey{}, auth))
}

var terminalUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	},
}

func isInteractiveShell(command string) bool {
	switch strings.TrimSpace(command) {
	case "/bin/sh", "/bin/bash", "sh", "bash":
		return true
	default:
		return false
	}
}

func (s *Server) streamK8sPodTerminal(w http.ResponseWriter, r *http.Request, sess store.K8sPodExecSession) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	streamAuth, ticketClaimed := terminalStreamAuthFromRequest(r)
	claimID := streamAuth.ClaimID
	expectedStatus := "ready"
	if ticketClaimed {
		expectedStatus = "connecting"
	}
	if streamAuth.SessionID != "" && streamAuth.SessionID != sess.ID {
		writeOpenAIError(w, http.StatusUnauthorized, "terminal ticket session mismatch", "invalid_request_error", "terminal_ticket_invalid")
		return
	}
	if sess.Status != expectedStatus {
		writeOpenAIError(w, http.StatusConflict, "terminal session must be approved and ready", "invalid_request_error", "terminal_session_not_ready")
		return
	}
	if !isInteractiveShell(sess.Command) {
		if ticketClaimed {
			s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "interactive terminal shell is invalid")
		}
		writeOpenAIError(w, http.StatusBadRequest, "interactive terminal only supports /bin/sh or /bin/bash", "invalid_request_error", "terminal_shell_invalid")
		return
	}
	policy := k8sExecSessionPolicy(sess)
	if fmt.Sprint(policy["access_mode"]) != "full_tty" {
		if ticketClaimed {
			s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "session was not approved as full_tty")
		}
		writeOpenAIError(w, http.StatusConflict, "session was not approved as full_tty", "invalid_request_error", "terminal_full_tty_required")
		return
	}
	if !ticketClaimed {
		claimID = newID("k8sttyclaim")
		connecting, err := s.db.MarkK8sPodExecSessionConnecting(r.Context(), sess.ID, adminID(r), claimID)
		if errors.Is(err, store.ErrInvalidTransition) {
			writeOpenAIError(w, http.StatusConflict, "terminal session is already connecting or closed", "invalid_request_error", "terminal_session_bad_state")
			return
		}
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, "terminal session claim failed", "server_error", "terminal_session_claim_failed")
			return
		}
		sess = connecting
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), sess.ClusterID)
	if err != nil {
		s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "cluster not found")
		writeOpenAIError(w, http.StatusNotFound, "cluster not found", "invalid_request_error", "cluster_not_found")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "Kubernetes connection setup failed: "+err.Error())
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	terminalClient, ok := client.(kube.PodTerminalExecutor)
	if !ok {
		s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "cluster client does not support interactive terminal")
		writeOpenAIError(w, http.StatusNotImplemented, "cluster client does not support interactive terminal", "invalid_request_error", "terminal_unsupported")
		return
	}
	timeout := execSessionTimeout(sess.MaxSessionMinutes)
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	browser, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "browser WebSocket upgrade failed")
		return
	}
	defer browser.Close()
	browser.SetReadLimit(64 * 1024)
	kubeStream, err := terminalClient.OpenPodTerminal(ctx, sess.Namespace, sess.Pod, kube.PodTerminalOptions{Container: sess.Container, Shell: sess.Command})
	if err != nil {
		_ = writeTerminalBrowserJSON(browser, browserTerminalMessage{Type: "error", Data: "Pod terminal 연결 실패: " + err.Error()})
		s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "Pod terminal connection failed: "+err.Error())
		return
	}
	defer kubeStream.Close()
	transitionCtx, transitionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	running, err := s.db.MarkK8sPodExecSessionConnected(transitionCtx, sess.ID, claimID)
	transitionCancel()
	if err != nil {
		_ = writeTerminalBrowserJSON(browser, browserTerminalMessage{Type: "error", Data: "세션 상태를 running으로 전환하지 못했습니다."})
		s.failK8sPodTerminalConnection(sess, claimID, adminID(r), "terminal session connected transition failed")
		return
	}
	sess = running
	s.auditAdmin(r, "k8s.pod.terminal.connect", sess.ID, auditJSON(map[string]any{
		"cluster_id": sess.ClusterID, "namespace": sess.Namespace, "pod": sess.Pod, "container": sess.Container, "shell": sess.Command,
	}))
	_ = writeTerminalBrowserJSON(browser, browserTerminalMessage{Type: "status", Data: "connected"})

	input := make(chan browserTerminalMessage, 32)
	readErr := make(chan error, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			var msg browserTerminalMessage
			if err := browser.ReadJSON(&msg); err != nil {
				select {
				case readErr <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case input <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()
	type terminalOutput struct {
		channel byte
		data    []byte
		err     error
	}
	output := make(chan terminalOutput, 16)
	receiverDone := make(chan struct{})
	go func() {
		defer close(receiverDone)
		for {
			channel, data, err := kubeStream.Receive()
			select {
			case output <- terminalOutput{channel: channel, data: data, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil || channel == 3 {
				return
			}
		}
	}()

	var transcript strings.Builder
	var inputBytes, outputBytes int64
	appendTranscript := func(prefix, value string) {
		if transcript.Len() >= 8000 || value == "" {
			return
		}
		value = analyzer.MaskSensitive(value)
		remain := 8000 - transcript.Len()
		line := prefix + value
		if len(line) > remain {
			line = line[:remain]
		}
		transcript.WriteString(line)
	}
	status, errMsg, exitCode := "completed", "", 0
loop:
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				status, errMsg, exitCode = "failed", "terminal session expired", 124
			} else {
				status, errMsg, exitCode = "failed", "terminal session canceled", 1
			}
			_ = writeTerminalBrowserJSON(browser, browserTerminalMessage{Type: "error", Data: errMsg})
			break loop
		case err := <-readErr:
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				status, errMsg, exitCode = "failed", "browser terminal disconnected", 1
			}
			break loop
		case msg := <-input:
			switch msg.Type {
			case "input":
				// Never persist raw interactive input: it may contain a password typed
				// into a no-echo prompt. Audit byte counts and masked output instead.
				inputBytes += int64(len(msg.Data))
				if err := kubeStream.SendInput([]byte(msg.Data)); err != nil {
					status, errMsg, exitCode = "failed", err.Error(), 1
					break loop
				}
			case "resize":
				_ = kubeStream.Resize(msg.Cols, msg.Rows)
			case "close":
				break loop
			}
		case out := <-output:
			if out.err != nil {
				if !errors.Is(out.err, io.EOF) {
					status, errMsg, exitCode = "failed", out.err.Error(), 1
				}
				break loop
			}
			if out.channel == 3 {
				if len(strings.TrimSpace(string(out.data))) > 0 {
					status, errMsg, exitCode = "failed", string(out.data), 1
				}
				break loop
			}
			outputBytes += int64(len(out.data))
			appendTranscript("\n[output] ", string(out.data))
			if err := writeTerminalBrowserBinary(browser, out.data); err != nil {
				status, errMsg, exitCode = "failed", "browser terminal write failed", 1
				break loop
			}
		}
	}
	cancel()
	_ = kubeStream.Close()
	maskedErr := truncateRunes(analyzer.MaskSensitive(errMsg), 2000)
	finalizeCtx, finalizeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	updated, finalizeErr := s.db.UpdateK8sPodTerminalSessionExecution(finalizeCtx, sess.ID, claimID, status, adminID(r), transcript.String(), maskedErr, exitCode)
	finalizeCancel()
	if finalizeErr == nil {
		_ = writeTerminalBrowserJSON(browser, browserTerminalMessage{Type: "status", Data: updated.Status})
	}
	_ = browser.Close()
	for _, done := range []<-chan struct{}{readerDone, receiverDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	s.auditAdmin(r, "k8s.pod.terminal.close", sess.ID, auditJSON(map[string]any{
		"cluster_id": sess.ClusterID, "namespace": sess.Namespace, "pod": sess.Pod, "container": sess.Container,
		"shell": sess.Command, "status": status, "exit_code": exitCode, "input_bytes": inputBytes, "output_bytes": outputBytes,
	}))
}

func (s *Server) failK8sPodTerminalConnection(sess store.K8sPodExecSession, claimID, actor, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.db.UpdateK8sPodTerminalSessionExecution(
		ctx, sess.ID, claimID, "failed", actor, "", truncateRunes(analyzer.MaskSensitive(message), 2000), 1,
	)
}
