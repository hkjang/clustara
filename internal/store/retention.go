package store

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"clustara/internal/config"
)

type RetentionWorker struct {
	store       *SQLStore
	conf        atomic.Pointer[config.RetentionConfig] // current config (swappable at runtime)
	reload      chan struct{}                          // signals the run loop to recreate its ticker
	done        chan struct{}
	wg          sync.WaitGroup
	lastRun     atomic.Value // string RFC3339
	lastSuccess atomic.Value // string RFC3339; only stamped when a run had no failures
	lastError   atomic.Value // string; the most recent failure, cleared by a clean run
	errorCount  atomic.Uint64
	deleted     atomic.Int64
}

func NewRetentionWorker(s *SQLStore, cfg config.RetentionConfig) *RetentionWorker {
	w := &RetentionWorker{store: s, done: make(chan struct{}), reload: make(chan struct{}, 1)}
	w.conf.Store(&cfg)
	w.lastRun.Store("")
	w.lastSuccess.Store("")
	w.lastError.Store("")
	return w
}

func (w *RetentionWorker) curConf() config.RetentionConfig {
	if p := w.conf.Load(); p != nil {
		return *p
	}
	return config.RetentionConfig{}
}

// Reconfigure swaps the retention config at runtime. Day thresholds take effect on the
// next run; an interval change recreates the ticker. Safe to call from another goroutine.
func (w *RetentionWorker) Reconfigure(cfg config.RetentionConfig) {
	w.conf.Store(&cfg)
	select {
	case w.reload <- struct{}{}:
	default:
	}
}

func (w *RetentionWorker) Start() {
	if w.curConf().Interval <= 0 {
		return
	}
	w.wg.Add(1)
	go w.run()
}

func (w *RetentionWorker) Stop() {
	close(w.done)
	w.wg.Wait()
}

func (w *RetentionWorker) run() {
	defer w.wg.Done()
	interval := w.curConf().Interval
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	w.runOnce()
	for {
		select {
		case <-t.C:
			w.runOnce()
		case <-w.reload:
			t.Stop()
			iv := w.curConf().Interval
			if iv <= 0 {
				iv = time.Hour
			}
			t = time.NewTicker(iv)
		case <-w.done:
			return
		}
	}
}

func (w *RetentionWorker) RunOnce(ctx context.Context) int64 {
	return w.runOnceWith(ctx)
}

func (w *RetentionWorker) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	w.runOnceWith(ctx)
}

func (w *RetentionWorker) runOnceWith(ctx context.Context) int64 {
	cfg := w.curConf()
	// Failures are collected rather than only logged. Retention is what bounds
	// the store's growth, so a run whose purges all failed must not be able to
	// present itself as a successful run on the operations page.
	var failures []string
	fail := func(step string, err error) {
		slog.Warn("retention step failed", "step", step, "error", err)
		failures = append(failures, step+": "+err.Error())
	}

	// Roll up the last few days into analytics_daily BEFORE purging detailed logs,
	// so long-term aggregates survive retention even though the raw rows are gone.
	now := time.Now().UTC()
	if _, err := w.store.RollupRange(ctx, now.AddDate(0, 0, -3), now); err != nil {
		fail("rollup", err)
		_ = w.store.InsertSystemError(ctx, "retention", "Retention rollup failed: "+err.Error())
	}

	var totalDeleted int64
	purge := func(step string, n int64, err error) {
		if err != nil {
			fail(step, err)
			return
		}
		totalDeleted += n
	}
	if cfg.PromptDays > 0 && (cfg.RequestDays <= 0 || cfg.PromptDays < cfg.RequestDays) {
		n, err := w.store.PurgeOlderThan(ctx, "prompt_logs", cfg.PromptDays)
		purge("purge prompt_logs", n, err)
	}
	if cfg.ResponseDays > 0 && (cfg.RequestDays <= 0 || cfg.ResponseDays < cfg.RequestDays) {
		n, err := w.store.PurgeOlderThan(ctx, "response_logs", cfg.ResponseDays)
		purge("purge response_logs", n, err)
	}
	if cfg.RequestDays > 0 {
		n, err := w.store.PurgeOlderThan(ctx, "request_logs", cfg.RequestDays)
		purge("purge request_logs", n, err)
	}
	if cfg.Text2SQLReplayDays > 0 {
		n, err := w.store.PurgeText2SQLReplayBundles(ctx, cfg.Text2SQLReplayDays)
		purge("purge text2sql_replay_bundles", n, err)
	}
	n, err := w.store.PurgeChatSemanticExpired(ctx)
	purge("purge chat_semantic_cache", n, err)

	w.deleted.Add(totalDeleted)
	stamp := time.Now().UTC().Format(time.RFC3339)
	w.lastRun.Store(stamp)
	if len(failures) > 0 {
		w.errorCount.Add(uint64(len(failures)))
		w.lastError.Store(strings.Join(failures, "; "))
		return totalDeleted
	}
	w.lastError.Store("")
	w.lastSuccess.Store(stamp)
	return totalDeleted
}

func (w *RetentionWorker) LastRun() string {
	return retentionStringValue(&w.lastRun)
}

// LastSuccess is the last run in which every step succeeded. It stays behind
// LastRun while retention is failing, which is the signal that the store is no
// longer being bounded.
func (w *RetentionWorker) LastSuccess() string {
	return retentionStringValue(&w.lastSuccess)
}

// LastError describes the failures from the most recent run, empty after a
// clean one.
func (w *RetentionWorker) LastError() string {
	return retentionStringValue(&w.lastError)
}

// ErrorCount is the cumulative number of failed retention steps.
func (w *RetentionWorker) ErrorCount() uint64 {
	return w.errorCount.Load()
}

func retentionStringValue(v *atomic.Value) string {
	if s, ok := v.Load().(string); ok {
		return s
	}
	return ""
}

func (w *RetentionWorker) TotalDeleted() int64 {
	return w.deleted.Load()
}

func (w *RetentionWorker) Config() config.RetentionConfig {
	return w.curConf()
}
