package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"clustara/internal/store"
)

// K8sRolloutReconcilerOptions controls the durable rollout worker. OwnerID must
// be unique per process/replica when supplied by production wiring.
type K8sRolloutReconcilerOptions struct {
	OwnerID    string
	Interval   time.Duration
	LeaseTTL   time.Duration
	BatchSize  int
	MaxBackoff time.Duration
}

// K8sRolloutReconciler resumes active rollout and rollback records from the
// database. It has no dependency on an HTTP request, SSE client or browser tab.
type K8sRolloutReconciler struct {
	server    *Server
	worker    *backgroundWorker
	ownerID   string
	leaseTTL  time.Duration
	batchSize int
}

// NewK8sRolloutReconciler constructs, but does not start, a reconciler. This
// separation lets cmd wiring decide lifecycle and shutdown ownership.
func (s *Server) NewK8sRolloutReconciler(options K8sRolloutReconcilerOptions) *K8sRolloutReconciler {
	ownerID := strings.TrimSpace(options.OwnerID)
	if ownerID == "" {
		ownerID = newID("rollrecon")
	}
	interval := options.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	leaseTTL := options.LeaseTTL
	if leaseTTL <= 0 {
		leaseTTL = time.Minute
	}
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	// A lease that expires within one tick would let a second replica adopt a
	// rollout this one is still driving, so keep the floor here even when a
	// caller bypasses config validation.
	if leaseTTL < interval {
		leaseTTL = interval
	}
	return &K8sRolloutReconciler{
		server:    s,
		worker:    newBackgroundWorker("k8s_rollout_reconciler", interval, options.MaxBackoff),
		ownerID:   ownerID,
		leaseTTL:  leaseTTL,
		batchSize: batchSize,
	}
}

// StartK8sRolloutReconciler starts a background worker and returns its handle.
// Cancelling ctx stops the worker. NewServer intentionally does not call this;
// the application entrypoint can wire it alongside its other managed workers.
func (s *Server) StartK8sRolloutReconciler(ctx context.Context, options K8sRolloutReconcilerOptions) *K8sRolloutReconciler {
	worker := s.NewK8sRolloutReconciler(options)
	worker.Start(ctx)
	return worker
}

// Start runs the reconcile loop until ctx is cancelled and publishes the handle
// on the server so /admin/ops/workers can report it.
func (w *K8sRolloutReconciler) Start(ctx context.Context) {
	if w == nil || w.server == nil || w.server.db == nil {
		return
	}
	w.server.rolloutReconciler.Store(w)
	w.worker.start(ctx, func(tickCtx context.Context, _ time.Time) (int, error) {
		return w.reconcileBatch(tickCtx)
	})
}

// Run keeps the original blocking entrypoint for callers that manage their own
// goroutine.
func (w *K8sRolloutReconciler) Run(ctx context.Context) {
	if w == nil || w.server == nil || w.server.db == nil {
		return
	}
	if !w.worker.started.CompareAndSwap(false, true) {
		return
	}
	w.server.rolloutReconciler.Store(w)
	w.worker.loop(ctx, func(tickCtx context.Context, _ time.Time) (int, error) {
		return w.reconcileBatch(tickCtx)
	})
}

// Stop waits for an in-flight tick to finish so its lease is released before
// the process exits. It reports whether the worker stopped within timeout.
func (w *K8sRolloutReconciler) Stop(timeout time.Duration) bool {
	if w == nil {
		return true
	}
	return w.worker.wait(timeout)
}

// Status reports the worker's observable health.
func (w *K8sRolloutReconciler) Status() backgroundWorkerStatus {
	if w == nil {
		return backgroundWorkerStatus{Name: "k8s_rollout_reconciler"}
	}
	return w.worker.status()
}

// OwnerID is this reconciler's cross-replica lease identity.
func (w *K8sRolloutReconciler) OwnerID() string {
	if w == nil {
		return ""
	}
	return w.ownerID
}

// ReconcileOnce is exposed for managed schedulers and deterministic tests.
func (w *K8sRolloutReconciler) ReconcileOnce(ctx context.Context) error {
	_, err := w.reconcileBatch(ctx)
	return err
}

// reconcileBatch drains one batch of due rollouts and reports how many it
// advanced, so the worker loop can surface throughput alongside failures.
func (w *K8sRolloutReconciler) reconcileBatch(ctx context.Context) (int, error) {
	if w == nil || w.server == nil || w.server.db == nil {
		return 0, errors.New("rollout reconciler is not attached to a server store")
	}
	items, err := w.server.db.ListK8sRolloutActionsDue(ctx, w.batchSize)
	if err != nil {
		return 0, err
	}
	reconciled := 0
	var failures []error
	for _, item := range items {
		if ctx.Err() != nil {
			return reconciled, errors.Join(append(failures, ctx.Err())...)
		}
		if err := w.reconcileOne(ctx, item.ID); err != nil {
			failures = append(failures, fmt.Errorf("rollout %s: %w", item.ID, err))
			continue
		}
		reconciled++
	}
	return reconciled, errors.Join(failures...)
}

func (w *K8sRolloutReconciler) reconcileOne(ctx context.Context, rolloutID string) error {
	acquired, err := w.server.db.TryAcquireK8sRolloutReconcileLease(ctx, rolloutID, w.ownerID, time.Now().UTC(), w.leaseTTL)
	if err != nil || !acquired {
		return err
	}
	defer func() {
		if releaseErr := w.server.db.ReleaseK8sRolloutReconcileLease(context.WithoutCancel(ctx), rolloutID, w.ownerID); releaseErr != nil {
			slog.Warn("release k8s rollout reconcile lease failed", "owner_id", w.ownerID, "rollout_id", rolloutID, "error", releaseErr)
		}
	}()
	current, err := w.server.db.GetK8sRolloutAction(ctx, rolloutID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if current.StartedAt == "" &&
		(current.Status == "approved" || current.Status == "approval_required") &&
		current.ActionRequestID != "" {
		action, actionErr := w.server.db.GetK8sActionRequest(ctx, current.ActionRequestID)
		if actionErr != nil {
			return actionErr
		}
		if action.Status == "approved" {
			result := w.server.runApprovedK8sAction(ctx, "system:"+w.ownerID, action)
			if result.Err != nil {
				return result.Err
			}
			return nil
		}
	}
	// Do not short-circuit on the primary status alone. A terminal rollout can
	// still carry live rollback work, and reconcileRolloutContext is what owns
	// the auto-rollback request plus the rollback monitoring and timeout
	// transitions. Returning early on "failed"/"timed_out" stranded those
	// forever while the row stayed permanently due, spinning every tick.
	//
	// syncRolloutActionRequest is a no-op for a non-terminal rollout, so the
	// two exits below stay equivalent to the previous behaviour for rows that
	// genuinely have nothing left to reconcile.
	if !rolloutNeedsReconcile(current) {
		return w.server.syncRolloutActionRequest(ctx, current)
	}
	current, err = w.server.reconcileRolloutContext(ctx, "system:"+w.ownerID, current)
	if err != nil {
		return err
	}
	return w.server.syncRolloutActionRequest(ctx, current)
}
