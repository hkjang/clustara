package kube

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PodCommandExecutor is the non-interactive Pod exec surface used by Clustara's
// policy-gated terminal session flow.
type PodCommandExecutor interface {
	PodExec(ctx context.Context, namespace, pod string, opts PodExecOptions) (PodExecResult, error)
}

type PodExecOptions struct {
	Container  string
	Command    string
	CommandArg []string
	LimitBytes int
}

type PodExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func (c *HTTPClient) PodExec(ctx context.Context, namespace, pod string, opts PodExecOptions) (PodExecResult, error) {
	args, err := podExecArgs(opts)
	if err != nil {
		return PodExecResult{}, err
	}
	opts.CommandArg = args
	if opts.LimitBytes <= 0 {
		opts.LimitBytes = 256 * 1024
	}
	if res, err := c.podExecWebSocket(ctx, namespace, pod, opts); err == nil {
		return res, nil
	} else {
		var upgradeErr websocketUpgradeError
		if !errors.As(err, &upgradeErr) {
			return res, err
		}
	}
	return c.podExecHTTP(ctx, namespace, pod, opts)
}

func podExecArgs(opts PodExecOptions) ([]string, error) {
	if len(opts.CommandArg) > 0 {
		out := []string{}
		for _, arg := range opts.CommandArg {
			if strings.TrimSpace(arg) != "" {
				out = append(out, strings.TrimSpace(arg))
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("command is required")
		}
		return out, nil
	}
	args, err := splitCommandLine(opts.Command)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("command is required")
	}
	return args, nil
}

func (c *HTTPClient) podExecHTTP(ctx context.Context, namespace, pod string, opts PodExecOptions) (PodExecResult, error) {
	req, path, err := c.podExecRequest(ctx, http.MethodPost, namespace, pod, opts)
	if err != nil {
		return PodExecResult{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return PodExecResult{}, err
	}
	defer resp.Body.Close()
	limit := int64(maxExecResponseBytes(opts.LimitBytes))
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PodExecResult{Stderr: string(body), ExitCode: 1}, fmt.Errorf("Kubernetes API POST %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return PodExecResult{Stdout: string(body), ExitCode: 0}, nil
}

func (c *HTTPClient) podExecRequest(ctx context.Context, method, namespace, pod string, opts PodExecOptions) (*http.Request, string, error) {
	u, path, err := c.podExecURL(namespace, pod, opts)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	return req, path, nil
}

func (c *HTTPClient) podExecURL(namespace, pod string, opts PodExecOptions) (*url.URL, string, error) {
	namespace = strings.TrimSpace(namespace)
	pod = strings.TrimSpace(pod)
	if namespace == "" || pod == "" {
		return nil, "", fmt.Errorf("namespace and pod are required")
	}
	args, err := podExecArgs(opts)
	if err != nil {
		return nil, "", err
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/exec"
	u, err := url.Parse(c.cfg.ServerURL + path)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	if opts.Container != "" {
		q.Set("container", strings.TrimSpace(opts.Container))
	}
	for _, arg := range args {
		q.Add("command", arg)
	}
	q.Set("stdin", "false")
	q.Set("stdout", "true")
	q.Set("stderr", "true")
	q.Set("tty", "false")
	u.RawQuery = q.Encode()
	return u, path, nil
}

func (c *HTTPClient) podExecWebSocket(ctx context.Context, namespace, pod string, opts PodExecOptions) (PodExecResult, error) {
	u, _, err := c.podExecURL(namespace, pod, opts)
	if err != nil {
		return PodExecResult{}, err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return PodExecResult{}, fmt.Errorf("unsupported exec scheme %q", u.Scheme)
	}
	conn, br, err := c.openExecWebSocket(ctx, u)
	if err != nil {
		return PodExecResult{}, websocketUpgradeError{err: err}
	}
	defer conn.Close()
	return readExecWebSocket(conn, br, opts.LimitBytes)
}

type websocketUpgradeError struct {
	err error
}

func (e websocketUpgradeError) Error() string {
	return e.err.Error()
}

func (e websocketUpgradeError) Unwrap() error {
	return e.err
}

func (c *HTTPClient) openExecWebSocket(ctx context.Context, u *url.URL) (net.Conn, *bufio.Reader, error) {
	dialer := &net.Dialer{Timeout: c.cfg.Timeout}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	var conn net.Conn
	var err error
	if u.Scheme == "wss" {
		tlsConf, tlsErr := c.execTLSConfig()
		if tlsErr != nil {
			return nil, nil, tlsErr
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", host, tlsConf)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, nil, err
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	var b strings.Builder
	b.WriteString("GET " + u.RequestURI() + " HTTP/1.1\r\n")
	b.WriteString("Host: " + u.Host + "\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	b.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	b.WriteString("Sec-WebSocket-Protocol: v5.channel.k8s.io, v4.channel.k8s.io, channel.k8s.io\r\n")
	b.WriteString("User-Agent: " + c.cfg.UserAgent + "\r\n")
	if c.cfg.Token != "" {
		b.WriteString("Authorization: Bearer " + c.cfg.Token + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		conn.Close()
		return nil, nil, fmt.Errorf("Kubernetes exec websocket upgrade returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), websocketAccept(key); got != want {
		conn.Close()
		return nil, nil, fmt.Errorf("invalid websocket accept header")
	}
	return conn, br, nil
}

func (c *HTTPClient) execTLSConfig() (*tls.Config, error) {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.cfg.InsecureTLS {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // kubeconfig may explicitly opt into this.
	}
	if len(c.cfg.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(c.cfg.CACertPEM); !ok {
			return nil, fmt.Errorf("invalid certificate-authority-data")
		}
		tlsConf.RootCAs = pool
	}
	if len(c.cfg.ClientCertPEM) > 0 || len(c.cfg.ClientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(c.cfg.ClientCertPEM, c.cfg.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("invalid client certificate/key: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}
	return tlsConf, nil
}

func readExecWebSocket(conn net.Conn, br *bufio.Reader, limitBytes int) (PodExecResult, error) {
	limit := maxExecResponseBytes(limitBytes)
	var stdout, stderr bytes.Buffer
	exitCode := 0
	for stdout.Len()+stderr.Len() < limit {
		op, payload, err := readWebSocketFrame(br)
		if err != nil {
			if err == io.EOF {
				break
			}
			return PodExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode}, err
		}
		switch op {
		case 0x8:
			return PodExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode}, nil
		case 0x9:
			_ = writeWebSocketFrame(conn, 0xA, payload)
			continue
		case 0x1, 0x2:
			if len(payload) == 0 {
				continue
			}
			channel, data := payload[0], payload[1:]
			switch channel {
			case 1:
				writeLimited(&stdout, data, limit)
			case 2:
				writeLimited(&stderr, data, limit)
			case 3:
				writeLimited(&stderr, data, limit)
				if code := exitCodeFromStatus(data); code != 0 {
					exitCode = code
				} else if len(bytes.TrimSpace(data)) > 0 && exitCode == 0 {
					exitCode = 1
				}
			}
		}
	}
	return PodExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode}, nil
}

func readWebSocketFrame(r *bufio.Reader) (byte, []byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}
	opcode := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	length := int64(h[1] & 0x7f)
	switch length {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(b[:]))
	}
	if length < 0 || length > 16*1024*1024 {
		return 0, nil, fmt.Errorf("websocket frame too large: %d", length)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func writeWebSocketFrame(w io.Writer, opcode byte, payload []byte) error {
	key := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	h := []byte{0x80 | opcode}
	l := len(payload)
	switch {
	case l < 126:
		h = append(h, 0x80|byte(l))
	case l <= 0xffff:
		h = append(h, 0x80|126, byte(l>>8), byte(l))
	default:
		h = append(h, 0x80|127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(l))
		h = append(h, b[:]...)
	}
	h = append(h, key...)
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ key[i%4]
	}
	if _, err := w.Write(h); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

func writeLimited(dst *bytes.Buffer, data []byte, limit int) {
	remain := limit - dst.Len()
	if remain <= 0 {
		return
	}
	if len(data) > remain {
		data = data[:remain]
	}
	_, _ = dst.Write(data)
}

func exitCodeFromStatus(data []byte) int {
	var st struct {
		Details struct {
			Causes []struct {
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"causes"`
		} `json:"details"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &st); err == nil {
		for _, c := range st.Details.Causes {
			if strings.EqualFold(c.Reason, "ExitCode") {
				if n, err := strconv.Atoi(strings.TrimSpace(c.Message)); err == nil {
					return n
				}
			}
		}
	}
	if idx := strings.LastIndex(strings.ToLower(string(data)), "exit code "); idx >= 0 {
		raw := strings.TrimSpace(string(data)[idx+10:])
		fields := strings.Fields(raw)
		if len(fields) > 0 {
			if n, err := strconv.Atoi(fields[0]); err == nil {
				return n
			}
		}
	}
	return 0
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func maxExecResponseBytes(limitBytes int) int {
	if limitBytes > 0 && limitBytes < 1024*1024 {
		return limitBytes
	}
	return 1024 * 1024
}

func splitCommandLine(command string) ([]string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, nil
	}
	out := []string{}
	var b strings.Builder
	var quote rune
	escaped := false
	for _, r := range command {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if escaped {
		b.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in command")
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out, nil
}
