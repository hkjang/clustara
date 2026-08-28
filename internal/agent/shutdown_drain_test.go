package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"clustara/internal/collector"
	"clustara/internal/kube"
)

// On SIGTERM the flush loop used to send only what it had already batched into
// `pending`, then return. Whatever was still sitting in the r.events buffer —
// up to QueueSize, 2000 by default — was dropped.
//
// Those are cluster transitions the watch stream already delivered and the agent
// already acknowledged, so nothing replays them: they are simply missing from
// inventory and incident history. And agents restart constantly, on every node
// drain and cluster upgrade.
//
// Draining costs nothing when the network is down, because flushEvents falls
// back to the on-disk offline queue.
func TestShutdownDrainsBufferedEvents(t *testing.T) {
	const queued = 250

	var mu sync.Mutex
	received := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch collector.AgentBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		received += len(batch.Events)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// testRunner's queue holds 10; this needs a buffer big enough to hold the
	// backlog with nothing consuming it, which is the situation being tested.
	r := drainTestRunner(t, server.URL, queued+64, 100)

	for i := 0; i < queued; i++ {
		r.events <- queuedEvent{
			target:          kube.ResourceTarget{Kind: "Pod", Path: "/api/v1/pods"},
			watchType:       "ADDED",
			object:          map[string]any{"metadata": map[string]any{"name": "p", "namespace": "default"}},
			resourceVersion: "1",
			receivedAt:      time.Now().UTC(),
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shut down immediately: nothing has been batched yet

	if err := r.flushLoop(ctx); err != nil {
		t.Fatalf("flushLoop returned %v", err)
	}

	mu.Lock()
	got := received
	mu.Unlock()
	if got != queued {
		t.Fatalf("shutdown delivered %d of %d buffered events; the rest were dropped from the channel "+
			"and nothing replays them — those cluster transitions are simply missing", got, queued)
	}
}

// The drain must terminate. A loop that blocks on the channel instead of
// consuming what is buffered would hang shutdown past the pod's grace period,
// which is worse than the bug it fixes.
func TestShutdownDrainTerminatesOnAnEmptyChannel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	r := drainTestRunner(t, server.URL, 16, 8)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- r.flushLoop(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("flushLoop returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("flushLoop did not return on an empty channel: the shutdown drain blocks")
	}
}

// drainTestRunner builds a runner whose event buffer can hold the backlog under
// test, with the batch and heartbeat tickers pushed far enough out that the
// shutdown drain is the only thing that can move an event.
func drainTestRunner(t *testing.T, endpoint string, queueSize, maxBatch int) *Runner {
	t.Helper()
	dir := t.TempDir()
	r, err := NewRunner(Config{
		ClusterID:         "c1",
		AgentID:           "agent-a",
		Version:           "test",
		Endpoint:          endpoint,
		KubeAPIServer:     "http://kubernetes.invalid",
		BatchInterval:     time.Hour,
		HeartbeatInterval: time.Hour,
		WatchTimeout:      time.Minute,
		RequestTimeout:    5 * time.Second,
		QueueSize:         queueSize,
		MaxBatchSize:      maxBatch,
		StateFile:         filepath.Join(dir, "state.json"),
		QueueFile:         filepath.Join(dir, "queue.ndjson"),
	})
	if err != nil {
		t.Fatalf("NewRunner returned error: %v", err)
	}
	return r
}
