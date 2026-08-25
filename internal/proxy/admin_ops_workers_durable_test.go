package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func newDurableWorkerTestServer(t *testing.T) *Server {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.Workers.RolloutReconcilerEnabled = true
	cfg.Workers.TerminalReaperEnabled = true
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func fetchWorkerStatuses(t *testing.T, server *Server) map[string]workerStatus {
	t.Helper()
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/admin/ops/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	var payload struct {
		Overall string         `json:"overall"`
		Workers []workerStatus `json:"workers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	byName := map[string]workerStatus{}
	for _, ws := range payload.Workers {
		byName[ws.Name] = ws
	}
	return byName
}

// A worker that config says should be running, but is not, is an availability
// outage: rollouts stop converging with no error anywhere.
func TestOpsWorkersFlagsEnabledButUnstartedDurableWorkers(t *testing.T) {
	server := newDurableWorkerTestServer(t)
	byName := fetchWorkerStatuses(t, server)

	for _, name := range []string{"k8s_rollout_reconciler", "k8s_terminal_session_reaper"} {
		ws, ok := byName[name]
		if !ok {
			t.Fatalf("%s is missing from /admin/ops/workers", name)
		}
		if ws.Running {
			t.Fatalf("%s reports running before it was started", name)
		}
		if ws.Status != "critical" {
			t.Fatalf("%s status = %q, want critical when enabled but not started", name, ws.Status)
		}
	}
}

func TestOpsWorkersReportsRunningDurableWorkers(t *testing.T) {
	server := newDurableWorkerTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reconciler := server.StartK8sRolloutReconciler(ctx, K8sRolloutReconcilerOptions{
		OwnerID: "replica-under-test", Interval: 50 * time.Millisecond, LeaseTTL: time.Minute,
	})
	reaper := server.StartK8sTerminalSessionReaper(ctx, K8sTerminalSessionReaperOptions{
		Interval: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		cancel()
		reconciler.Stop(5 * time.Second)
		reaper.Stop(5 * time.Second)
	})

	waitFor(t, 5*time.Second, func() bool {
		return reconciler.Status().LastSuccess != "" && reaper.Status().LastSuccess != ""
	})

	byName := fetchWorkerStatuses(t, server)
	rollout := byName["k8s_rollout_reconciler"]
	if !rollout.Running || rollout.Status != "ok" {
		t.Fatalf("rollout reconciler = %+v, want a running ok worker", rollout)
	}
	if !strings.Contains(rollout.Detail, "replica-under-test") {
		t.Fatalf("rollout detail %q should name the lease owner", rollout.Detail)
	}
	if reap := byName["k8s_terminal_session_reaper"]; !reap.Running || reap.Status != "ok" {
		t.Fatalf("terminal reaper = %+v, want a running ok worker", reap)
	}
}

func TestMetricsEndpointExposesDurableWorkerSeries(t *testing.T) {
	server := newDurableWorkerTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reconciler := server.StartK8sRolloutReconciler(ctx, K8sRolloutReconcilerOptions{
		OwnerID: "metrics-owner", Interval: 50 * time.Millisecond, LeaseTTL: time.Minute,
	})
	t.Cleanup(func() { cancel(); reconciler.Stop(5 * time.Second) })
	waitFor(t, 5*time.Second, func() bool { return reconciler.Status().Ticks > 0 })

	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		`clustara_worker_running{worker="k8s_rollout_reconciler"} 1`,
		`clustara_worker_ticks_total{worker="k8s_rollout_reconciler"}`,
		`clustara_worker_running{worker="k8s_terminal_session_reaper"} 0`,
		"proxy_requests_total",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("/metrics missing %q", want)
		}
	}
}
