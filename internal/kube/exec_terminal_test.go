package kube

import (
	"context"
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
