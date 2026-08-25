package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// backgroundWorkerStatus is one durable worker's observable health. It is the
// input to /admin/ops/workers and to the Prometheus worker gauges, so every
// field must be safe to read while the worker is mid-tick.
type backgroundWorkerStatus struct {
	Name                string `json:"name"`
	Running             bool   `json:"running"`
	Interval            string `json:"interval"`
	CurrentDelay        string `json:"current_delay"`
	NextRunAt           string `json:"next_run_at"`
	LastRun             string `json:"last_run"`
	LastSuccess         string `json:"last_success"`
	LastError           string `json:"last_error"`
	Ticks               uint64 `json:"ticks"`
	Failures            uint64 `json:"failures"`
	ConsecutiveFailures uint64 `json:"consecutive_failures"`
	Processed           uint64 `json:"processed"`
}

// workerTick performs one unit of work and reports how many items it handled.
// Returning an error triggers exponential backoff on the next tick.
type workerTick func(ctx context.Context, now time.Time) (int, error)

// backgroundWorker is the shared loop behind the durable Kubernetes workers.
// It owns the tick cadence, failure backoff, panic containment and the
// counters that make the worker observable from outside the process.
type backgroundWorker struct {
	name       string
	interval   time.Duration
	maxBackoff time.Duration

	started     atomic.Bool
	running     atomic.Bool
	lastRun     atomic.Value // string, RFC3339Nano
	lastSuccess atomic.Value // string, RFC3339Nano
	lastError   atomic.Value // string
	nextRunAt   atomic.Value // string, RFC3339Nano
	ticks       atomic.Uint64
	failures    atomic.Uint64
	consecutive atomic.Uint64
	processed   atomic.Uint64
	delay       atomic.Int64 // current inter-tick delay in nanoseconds
	done        chan struct{}
	closeOnce   sync.Once
}

func newBackgroundWorker(name string, interval, maxBackoff time.Duration) *backgroundWorker {
	if interval <= 0 {
		interval = time.Second
	}
	if maxBackoff < interval {
		maxBackoff = interval
	}
	w := &backgroundWorker{name: name, interval: interval, maxBackoff: maxBackoff, done: make(chan struct{})}
	w.lastRun.Store("")
	w.lastSuccess.Store("")
	w.lastError.Store("")
	w.nextRunAt.Store("")
	w.delay.Store(int64(interval))
	return w
}

// start launches the loop. It marks the worker started synchronously so a
// caller may immediately wait on it without racing the goroutine scheduler.
func (w *backgroundWorker) start(ctx context.Context, tick workerTick) {
	if w == nil || !w.started.CompareAndSwap(false, true) {
		return
	}
	go w.loop(ctx, tick)
}

func (w *backgroundWorker) loop(ctx context.Context, tick workerTick) {
	w.running.Store(true)
	defer func() {
		w.running.Store(false)
		w.nextRunAt.Store("")
		w.closeOnce.Do(func() { close(w.done) })
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		w.runTick(ctx, tick)
		delay := w.nextDelay()
		w.nextRunAt.Store(time.Now().UTC().Add(delay).Format(time.RFC3339Nano))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// runTick executes one tick and folds the outcome into the worker counters.
// A cancelled context is shutdown, not a failure, so it never trips backoff.
func (w *backgroundWorker) runTick(ctx context.Context, tick workerTick) {
	if ctx.Err() != nil {
		return
	}
	now := time.Now().UTC()
	w.lastRun.Store(now.Format(time.RFC3339Nano))
	w.ticks.Add(1)
	processed, err := w.invoke(ctx, tick, now)
	if processed > 0 {
		w.processed.Add(uint64(processed))
	}
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		w.failures.Add(1)
		w.consecutive.Add(1)
		w.lastError.Store(err.Error())
		slog.Warn("background worker tick failed", "worker", w.name,
			"consecutive_failures", w.consecutive.Load(), "error", err)
		return
	}
	w.consecutive.Store(0)
	w.lastError.Store("")
	w.lastSuccess.Store(time.Now().UTC().Format(time.RFC3339Nano))
}

// invoke contains a panicking tick. Without this a single bad row would take
// the whole process down, since a panic in a goroutine is not recoverable by
// the caller that started it.
func (w *backgroundWorker) invoke(ctx context.Context, tick workerTick, now time.Time) (processed int, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("worker %s panicked: %v", w.name, recovered)
			slog.Error("background worker panicked", "worker", w.name,
				"panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
		}
	}()
	return tick(ctx, now)
}

// nextDelay backs off exponentially while ticks keep failing so a broken
// database or API server is not hammered every interval, and snaps back to the
// base interval on the first success.
func (w *backgroundWorker) nextDelay() time.Duration {
	consecutive := w.consecutive.Load()
	delay := w.interval
	for i := uint64(1); i < consecutive && i < 32 && delay < w.maxBackoff; i++ {
		delay *= 2
	}
	if delay > w.maxBackoff {
		delay = w.maxBackoff
	}
	w.delay.Store(int64(delay))
	return delay
}

// wait blocks until the loop has returned, bounded by timeout. It reports
// whether the worker stopped in time; false means an in-flight tick is still
// running and its lease will only be reclaimed after the lease TTL expires.
func (w *backgroundWorker) wait(timeout time.Duration) bool {
	if w == nil || !w.started.Load() {
		return true
	}
	if timeout <= 0 {
		<-w.done
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-w.done:
		return true
	case <-timer.C:
		return false
	}
}

func (w *backgroundWorker) status() backgroundWorkerStatus {
	if w == nil {
		return backgroundWorkerStatus{}
	}
	return backgroundWorkerStatus{
		Name:                w.name,
		Running:             w.running.Load(),
		Interval:            w.interval.String(),
		CurrentDelay:        time.Duration(w.delay.Load()).String(),
		NextRunAt:           workerStringValue(&w.nextRunAt),
		LastRun:             workerStringValue(&w.lastRun),
		LastSuccess:         workerStringValue(&w.lastSuccess),
		LastError:           workerStringValue(&w.lastError),
		Ticks:               w.ticks.Load(),
		Failures:            w.failures.Load(),
		ConsecutiveFailures: w.consecutive.Load(),
		Processed:           w.processed.Load(),
	}
}

func workerStringValue(v *atomic.Value) string {
	if v == nil {
		return ""
	}
	if s, ok := v.Load().(string); ok {
		return s
	}
	return ""
}

// backgroundWorkerPrometheus renders the durable workers as labelled gauges and
// counters. Alerting on clustara_worker_consecutive_failures or on a stale
// clustara_worker_last_success_seconds is how an operator learns that rollout
// or terminal-session convergence has stopped.
func backgroundWorkerPrometheus(statuses []backgroundWorkerStatus) string {
	var b strings.Builder
	b.WriteString("# HELP clustara_worker_running Whether the durable background worker loop is running.\n")
	b.WriteString("# TYPE clustara_worker_running gauge\n")
	for _, st := range statuses {
		b.WriteString(fmt.Sprintf("clustara_worker_running{worker=%q} %d\n", st.Name, boolGaugeValue(st.Running)))
	}
	b.WriteString("# HELP clustara_worker_ticks_total Background worker ticks executed.\n")
	b.WriteString("# TYPE clustara_worker_ticks_total counter\n")
	for _, st := range statuses {
		b.WriteString(fmt.Sprintf("clustara_worker_ticks_total{worker=%q} %d\n", st.Name, st.Ticks))
	}
	b.WriteString("# HELP clustara_worker_failures_total Background worker ticks that returned an error.\n")
	b.WriteString("# TYPE clustara_worker_failures_total counter\n")
	for _, st := range statuses {
		b.WriteString(fmt.Sprintf("clustara_worker_failures_total{worker=%q} %d\n", st.Name, st.Failures))
	}
	b.WriteString("# HELP clustara_worker_processed_total Items advanced by the background worker.\n")
	b.WriteString("# TYPE clustara_worker_processed_total counter\n")
	for _, st := range statuses {
		b.WriteString(fmt.Sprintf("clustara_worker_processed_total{worker=%q} %d\n", st.Name, st.Processed))
	}
	b.WriteString("# HELP clustara_worker_consecutive_failures Consecutive failing ticks; non-zero means the worker is backing off.\n")
	b.WriteString("# TYPE clustara_worker_consecutive_failures gauge\n")
	for _, st := range statuses {
		b.WriteString(fmt.Sprintf("clustara_worker_consecutive_failures{worker=%q} %d\n", st.Name, st.ConsecutiveFailures))
	}
	b.WriteString("# HELP clustara_worker_last_success_seconds Seconds since the worker last completed a tick without error.\n")
	b.WriteString("# TYPE clustara_worker_last_success_seconds gauge\n")
	for _, st := range statuses {
		b.WriteString(fmt.Sprintf("clustara_worker_last_success_seconds{worker=%q} %d\n", st.Name, secondsSinceRFC3339(st.LastSuccess)))
	}
	return b.String()
}

func boolGaugeValue(value bool) int {
	if value {
		return 1
	}
	return 0
}
