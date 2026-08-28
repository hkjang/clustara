package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/kube"
)

// TestWatchReturnsWhenTheStreamGoesSilent pins the client-side backstop on a
// watch stream.
//
// A watch has no client Timeout by design — one would cut every stream short —
// so its only bound used to be the server-side timeoutSeconds. That bound is
// worthless on a half-open connection: an LB or NAT idle drop, a partitioned
// node, or a firewall that discards without RST all leave a socket that will
// never deliver another byte and never close. Decode then blocks forever.
//
// The failure is silent, which is what makes it serious: no error is recorded,
// no reconnect is counted, no events arrive, and the heartbeat goroutine keeps
// reporting the agent healthy while that resource kind stops updating entirely.
//
// The fake API server here reproduces exactly that: it accepts the request,
// flushes response headers, then holds the connection open and sends nothing.
// Before the fix this test hangs until the harness kills it.
func TestWatchReturnsWhenTheStreamGoesSilent(t *testing.T) {
	silent := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-silent // never a byte, never a close
	}))
	defer func() {
		close(silent)
		srv.Close()
	}()

	const watchTimeout = 300 * time.Millisecond
	r := stallTestRunner(t, srv.URL, watchTimeout)

	// The parent context outlives the client deadline by a wide margin, so a
	// return can only come from the watch's own bound — not from shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target := kube.ResourceTarget{Kind: "Pod", Path: "/api/v1/pods"}
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- r.watch(ctx, target, "1") }()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if !errors.Is(err, errWatchStalled) {
			t.Fatalf("watch returned %v; want errWatchStalled so the stall is counted as a reconnect", err)
		}
		if elapsed < watchTimeout {
			t.Fatalf("watch gave up after %s, before the %s server-side window — a healthy watch would be cut short", elapsed, watchTimeout)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("watch never returned on a silent stream: the goroutine is hung with no error, no reconnect, and no events, while the heartbeat still reports the agent healthy")
	}
}

// TestWatchClientDeadlineOutlivesTheServerWindow guards the margin. The API
// server is asked to close at WatchTimeout; if the client deadline were equal
// or shorter, every healthy watch would be torn down by the client instead and
// each cycle would be miscounted as a reconnect.
func TestWatchClientDeadlineOutlivesTheServerWindow(t *testing.T) {
	for _, watchTimeout := range []time.Duration{time.Second, 30 * time.Second, 5 * time.Minute} {
		r := stallTestRunner(t, "http://kubernetes.invalid", watchTimeout)
		if got := r.watchClientDeadline(); got <= watchTimeout {
			t.Fatalf("WatchTimeout=%s: client deadline %s does not outlive the server window", watchTimeout, got)
		}
	}
}

func stallTestRunner(t *testing.T, kubeAPI string, watchTimeout time.Duration) *Runner {
	t.Helper()
	dir := t.TempDir()
	r, err := NewRunner(Config{
		ClusterID:         "c1",
		AgentID:           "agent-a",
		Version:           "test",
		Endpoint:          "http://clustara.invalid/api/agent",
		KubeAPIServer:     kubeAPI,
		BatchInterval:     time.Second,
		HeartbeatInterval: time.Minute,
		WatchTimeout:      watchTimeout,
		RequestTimeout:    time.Second,
		QueueSize:         10,
		MaxBatchSize:      10,
		StateFile:         filepath.Join(dir, "state.json"),
		QueueFile:         filepath.Join(dir, "queue.ndjson"),
	})
	if err != nil {
		t.Fatalf("NewRunner returned error: %v", err)
	}
	return r
}
