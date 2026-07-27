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

type terminalTicket struct {
	SessionID string
	ExpiresAt time.Time
}

func (s *Server) issueTerminalTicket(w http.ResponseWriter, r *http.Request, sess store.K8sPodExecSession) {
	if sess.Status != "ready" || !isInteractiveShell(sess.Command) || fmt.Sprint(k8sExecSessionPolicy(sess)["access_mode"]) != "full_tty" {
		writeOpenAIError(w, http.StatusConflict, "approved full_tty shell session is required", "invalid_request_error", "terminal_session_not_ready")
		return
	}
	now := time.Now().UTC()
	s.terminalTickets.Range(func(key, value any) bool {
		if entry, ok := value.(terminalTicket); !ok || !now.Before(entry.ExpiresAt) {
			s.terminalTickets.Delete(key)
		}
		return true
	})
	ticket := newID("k8stty")
	expires := now.Add(30 * time.Second)
	s.terminalTickets.Store(ticket, terminalTicket{SessionID: sess.ID, ExpiresAt: expires})
	writeJSON(w, http.StatusCreated, map[string]any{"ticket": ticket, "expires_at": expires.Format(time.RFC3339)})
}

func (s *Server) consumeTerminalTicket(sessionID, ticket string) bool {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		return false
	}
	raw, ok := s.terminalTickets.LoadAndDelete(ticket)
	if !ok {
		return false
	}
	value, ok := raw.(terminalTicket)
	return ok && value.SessionID == sessionID && time.Now().UTC().Before(value.ExpiresAt)
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
	if sess.Status != "ready" {
		writeOpenAIError(w, http.StatusConflict, "terminal session must be approved and ready", "invalid_request_error", "terminal_session_not_ready")
		return
	}
	if !isInteractiveShell(sess.Command) {
		writeOpenAIError(w, http.StatusBadRequest, "interactive terminal only supports /bin/sh or /bin/bash", "invalid_request_error", "terminal_shell_invalid")
		return
	}
	policy := k8sExecSessionPolicy(sess)
	if fmt.Sprint(policy["access_mode"]) != "full_tty" {
		writeOpenAIError(w, http.StatusConflict, "session was not approved as full_tty", "invalid_request_error", "terminal_full_tty_required")
		return
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), sess.ClusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found", "invalid_request_error", "cluster_not_found")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	terminalClient, ok := client.(kube.PodTerminalExecutor)
	if !ok {
		writeOpenAIError(w, http.StatusNotImplemented, "cluster client does not support interactive terminal", "invalid_request_error", "terminal_unsupported")
		return
	}
	timeout := execSessionTimeout(sess.MaxSessionMinutes)
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	kubeStream, err := terminalClient.OpenPodTerminal(ctx, sess.Namespace, sess.Pod, kube.PodTerminalOptions{Container: sess.Container, Shell: sess.Command})
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "Pod terminal 연결 실패: "+err.Error(), "server_error", "terminal_connect_failed")
		return
	}
	defer kubeStream.Close()
	browser, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer browser.Close()
	browser.SetReadLimit(64 * 1024)
	running, err := s.db.MarkK8sPodExecSessionRunning(context.Background(), sess.ID, adminID(r))
	if err != nil {
		_ = browser.WriteJSON(browserTerminalMessage{Type: "error", Data: "세션 상태를 running으로 전환하지 못했습니다."})
		return
	}
	sess = running
	s.auditAdmin(r, "k8s.pod.terminal.connect", sess.ID, auditJSON(map[string]any{
		"cluster_id": sess.ClusterID, "namespace": sess.Namespace, "pod": sess.Pod, "container": sess.Container, "shell": sess.Command,
	}))
	_ = browser.WriteJSON(browserTerminalMessage{Type: "status", Data: "connected"})

	input := make(chan browserTerminalMessage, 32)
	readErr := make(chan error, 1)
	go func() {
		for {
			var msg browserTerminalMessage
			if err := browser.ReadJSON(&msg); err != nil {
				readErr <- err
				return
			}
			input <- msg
		}
	}()
	type terminalOutput struct {
		channel byte
		data    []byte
		err     error
	}
	output := make(chan terminalOutput, 16)
	go func() {
		for {
			channel, data, err := kubeStream.Receive()
			output <- terminalOutput{channel: channel, data: data, err: err}
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
			status, errMsg, exitCode = "failed", "terminal session expired", 124
			_ = browser.WriteJSON(browserTerminalMessage{Type: "error", Data: errMsg})
			break loop
		case err := <-readErr:
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				errMsg = "browser terminal disconnected"
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
			if err := browser.WriteMessage(websocket.BinaryMessage, out.data); err != nil {
				break loop
			}
		}
	}
	maskedErr := truncateRunes(analyzer.MaskSensitive(errMsg), 2000)
	updated, finalizeErr := s.db.UpdateK8sPodExecSessionExecution(context.Background(), sess.ID, status, adminID(r), transcript.String(), maskedErr, exitCode)
	if finalizeErr == nil {
		_ = browser.WriteJSON(browserTerminalMessage{Type: "status", Data: updated.Status})
	}
	s.auditAdmin(r, "k8s.pod.terminal.close", sess.ID, auditJSON(map[string]any{
		"cluster_id": sess.ClusterID, "namespace": sess.Namespace, "pod": sess.Pod, "container": sess.Container,
		"shell": sess.Command, "status": status, "exit_code": exitCode, "input_bytes": inputBytes, "output_bytes": outputBytes,
	}))
}
