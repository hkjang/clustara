package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"clustara/internal/store"
)

type K8sTerminalSessionReaperOptions struct {
	Interval   time.Duration
	BatchSize  int
	MaxBackoff time.Duration
}

type K8sTerminalSessionReaper struct {
	server    *Server
	worker    *backgroundWorker
	batchSize int
}

func (s *Server) NewK8sTerminalSessionReaper(options K8sTerminalSessionReaperOptions) *K8sTerminalSessionReaper {
	interval := options.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = 250
	}
	return &K8sTerminalSessionReaper{
		server:    s,
		worker:    newBackgroundWorker("k8s_terminal_session_reaper", interval, options.MaxBackoff),
		batchSize: batchSize,
	}
}

func (s *Server) StartK8sTerminalSessionReaper(ctx context.Context, options K8sTerminalSessionReaperOptions) *K8sTerminalSessionReaper {
	reaper := s.NewK8sTerminalSessionReaper(options)
	reaper.Start(ctx)
	return reaper
}

// Start runs the reap loop until ctx is cancelled and publishes the handle on
// the server so /admin/ops/workers can report it.
func (w *K8sTerminalSessionReaper) Start(ctx context.Context) {
	if w == nil || w.server == nil || w.server.db == nil {
		return
	}
	w.server.terminalReaper.Store(w)
	w.worker.start(ctx, w.reapBatch)
}

// Run keeps the original blocking entrypoint for callers that manage their own
// goroutine.
func (w *K8sTerminalSessionReaper) Run(ctx context.Context) {
	if w == nil || w.server == nil || w.server.db == nil {
		return
	}
	if !w.worker.started.CompareAndSwap(false, true) {
		return
	}
	w.server.terminalReaper.Store(w)
	w.worker.loop(ctx, w.reapBatch)
}

// Stop waits for an in-flight reap to finish. It reports whether the worker
// stopped within timeout.
func (w *K8sTerminalSessionReaper) Stop(timeout time.Duration) bool {
	if w == nil {
		return true
	}
	return w.worker.wait(timeout)
}

// Status reports the worker's observable health.
func (w *K8sTerminalSessionReaper) Status() backgroundWorkerStatus {
	if w == nil {
		return backgroundWorkerStatus{Name: "k8s_terminal_session_reaper"}
	}
	return w.worker.status()
}

// ReapOnce recovers a connection claim that died before becoming running and
// terminalizes a running transport whose owning process disappeared. The
// timeout plus grace is longer than the transport's own context deadline.
func (w *K8sTerminalSessionReaper) ReapOnce(ctx context.Context, now time.Time) error {
	_, err := w.reapBatch(ctx, now)
	return err
}

// reapBatch reaps one batch and reports how many sessions it actually
// transitioned, so the worker loop can surface throughput alongside failures.
func (w *K8sTerminalSessionReaper) reapBatch(ctx context.Context, now time.Time) (int, error) {
	if w == nil || w.server == nil || w.server.db == nil {
		return 0, errors.New("terminal session reaper is not attached to a server store")
	}
	sessions, err := w.server.db.ListK8sPodExecSessionsForRecovery(ctx, w.batchSize)
	if err != nil {
		return 0, err
	}
	reaped := 0
	var failures []error
	for _, session := range sessions {
		if ctx.Err() != nil {
			return reaped, errors.Join(append(failures, ctx.Err())...)
		}
		updatedAt, parseErr := time.Parse(time.RFC3339Nano, session.UpdatedAt)
		if parseErr != nil {
			failures = append(failures, fmt.Errorf("session %s updated_at: %w", session.ID, parseErr))
			continue
		}
		if now.Before(updatedAt.Add(execSessionTimeout(session.MaxSessionMinutes) + 30*time.Second)) {
			continue
		}
		switch session.Status {
		case "connecting":
			recovered, recoverErr := w.server.db.RecoverStaleK8sPodExecSessionConnection(ctx, session.ID, updatedAt)
			if recoverErr != nil {
				failures = append(failures, fmt.Errorf("recover connecting session %s: %w", session.ID, recoverErr))
			} else if recovered {
				reaped++
				if auditErr := w.server.db.InsertAdminAudit(ctx, store.AdminAuditLog{
					ID: newID("audit"), AdminID: "system:terminal-session-reaper", Action: "k8s.pod.terminal.connection_recovered",
					BeforeValue: session.ID, AfterValue: auditJSON(map[string]any{"status": "ready"}),
				}); auditErr != nil {
					failures = append(failures, fmt.Errorf("audit connecting recovery %s: %w", session.ID, auditErr))
				}
			}
		case "running":
			expired, expireErr := w.server.db.ExpireStaleK8sPodExecSession(
				ctx, session.ID, session.Status, session.UpdatedAt,
				"terminal owner disappeared after the maximum session duration",
			)
			if expireErr != nil {
				failures = append(failures, fmt.Errorf("expire running session %s: %w", session.ID, expireErr))
			} else if expired {
				reaped++
				if auditErr := w.server.db.InsertAdminAudit(ctx, store.AdminAuditLog{
					ID: newID("audit"), AdminID: "system:terminal-session-reaper", Action: "k8s.pod.terminal.expired",
					BeforeValue: session.ID, AfterValue: auditJSON(map[string]any{"status": "failed", "exit_code": 124}),
				}); auditErr != nil {
					failures = append(failures, fmt.Errorf("audit running expiry %s: %w", session.ID, auditErr))
				}
			}
		}
	}
	return reaped, errors.Join(failures...)
}
