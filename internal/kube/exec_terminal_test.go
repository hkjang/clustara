package kube

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHTTPClientInteractivePodTerminalStreamsInputOutputAndResize(t *testing.T) {
	inputSeen := make(chan string, 1)
	resizeSeen := make(chan string, 1)
	upgrader := websocket.Upgrader{Subprotocols: []string{"v5.channel.k8s.io"}, CheckOrigin: func(*http.Request) bool { return true }}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("stdin") != "true" || q.Get("stdout") != "true" || q.Get("tty") != "true" || q.Get("stderr") != "false" {
			t.Errorf("unexpected terminal query: %s", r.URL.RawQuery)
		}
		if strings.Join(q["command"], " ") != "/bin/sh" || q.Get("container") != "app" {
			t.Errorf("unexpected command/container query: %s", r.URL.RawQuery)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, []byte("ready $ ")...))
		for i := 0; i < 2; i++ {
			_, payload, err := conn.ReadMessage()
			if err != nil {
				t.Error(err)
				return
			}
			switch payload[0] {
			case 0:
				inputSeen <- string(payload[1:])
			case 4:
				resizeSeen <- string(payload[1:])
			}
		}
	}))
	defer api.Close()
	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenPodTerminal(context.Background(), "default", "api-1", PodTerminalOptions{Container: "app", Shell: "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	channel, data, err := stream.Receive()
	if err != nil || channel != 1 || string(data) != "ready $ " {
		t.Fatalf("output channel=%d data=%q err=%v", channel, data, err)
	}
	if err := stream.SendInput([]byte("id\r")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	if got := <-inputSeen; got != "id\r" {
		t.Fatalf("input=%q", got)
	}
	if got := <-resizeSeen; !strings.Contains(got, `"Width":120`) || !strings.Contains(got, `"Height":40`) {
		t.Fatalf("resize=%q", got)
	}
}

func TestHTTPClientInteractivePodTerminalRejectsUnsupportedShell(t *testing.T) {
	client, _ := NewHTTPClient(HTTPClientConfig{ServerURL: "http://127.0.0.1"})
	if _, err := client.OpenPodTerminal(context.Background(), "default", "api-1", PodTerminalOptions{Shell: "/usr/bin/zsh"}); err == nil {
		t.Fatal("unsupported interactive shell should be rejected before dialing")
	}
}

func TestHTTPClientInteractivePodTerminalCancellationClosesEstablishedSocket(t *testing.T) {
	upgraded := make(chan struct{})
	serverClosed := make(chan struct{})
	upgrader := websocket.Upgrader{Subprotocols: []string{"v5.channel.k8s.io"}, CheckOrigin: func(*http.Request) bool { return true }}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		close(upgraded)
		_, _, _ = conn.ReadMessage()
		close(serverClosed)
	}))
	defer api.Close()

	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := client.OpenPodTerminal(ctx, "default", "api-1", PodTerminalOptions{Shell: "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	select {
	case <-upgraded:
	case <-time.After(time.Second):
		t.Fatal("terminal WebSocket was not established")
	}

	receiveErr := make(chan error, 1)
	go func() {
		_, _, receiveErrValue := stream.Receive()
		receiveErr <- receiveErrValue
	}()
	cancel()

	select {
	case err := <-receiveErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive error=%v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Receive remained blocked after terminal context cancellation")
	}
	select {
	case <-serverClosed:
	case <-time.After(time.Second):
		t.Fatal("server-side terminal socket remained open after context cancellation")
	}
}

func TestHTTPClientInteractivePodTerminalHandshakeUsesClientTimeout(t *testing.T) {
	requestStarted := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer api.Close()

	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.OpenPodTerminal(context.Background(), "default", "api-1", PodTerminalOptions{Shell: "/bin/sh"})
	if err == nil {
		t.Fatal("stalled terminal WebSocket handshake must time out")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("handshake error=%T %v, want timeout", err, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("terminal handshake exceeded configured timeout: %v", elapsed)
	}
	select {
	case <-requestStarted:
	default:
		t.Fatal("terminal handshake request did not reach the server")
	}
}
