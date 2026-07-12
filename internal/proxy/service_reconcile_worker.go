package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"clustara/internal/store"
)

const serviceReconcileWorkerTick = 30 * time.Second

type serviceReconcileRuntime struct {
	runMu  sync.Mutex
	mu     sync.RWMutex
	status ServiceReconcileWorkerStatus
	owner  string
}

type ServiceReconcileWorkerStatus struct {
	Running             bool   `json:"running"`
	Enabled             bool   `json:"enabled"`
	OwnerID             string `json:"owner_id"`
	IntervalSeconds     int    `json:"interval_seconds"`
	BatchSize           int    `json:"batch_size"`
	TimeoutSeconds      int    `json:"timeout_seconds"`
	InventoryStaleAfter int    `json:"inventory_stale_seconds"`
	LastRun             string `json:"last_run"`
	LastSuccess         string `json:"last_success"`
	LastError           string `json:"last_error"`
	Selected            int    `json:"selected"`
	Reconciled          int    `json:"reconciled"`
	Collecting          int    `json:"collecting"`
	Failed              int    `json:"failed"`
	LeaseSkipped        int    `json:"lease_skipped"`
	PrunedSnapshots     int64  `json:"pruned_snapshots"`
}

type serviceReconcileBatchResult struct {
	Selected     int                      `json:"selected"`
	Reconciled   int                      `json:"reconciled"`
	Collecting   int                      `json:"collecting"`
	Failed       int                      `json:"failed"`
	LeaseSkipped int                      `json:"lease_skipped"`
	Errors       []string                 `json:"errors"`
	Previews     []serviceReconcileResult `json:"previews,omitempty"`
}

func newServiceReconcileRuntime() *serviceReconcileRuntime {
	host, _ := os.Hostname()
	return &serviceReconcileRuntime{owner: firstNonEmpty(strings.TrimSpace(host), "clustara") + "_" + newID("svcr")}
}

func (s *Server) serviceReconcileScheduler() {
	ticker := time.NewTicker(serviceReconcileWorkerTick)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		if _, err := s.runServiceReconcileBatch(ctx, false, true, 0); err != nil && ctx.Err() == nil {
			slog.Warn("service reconcile scheduler failed", "error", err)
		}
		cancel()
	}
}

func (s *Server) serviceReconcileSettings(ctx context.Context) ServiceReconcileWorkerStatus {
	return ServiceReconcileWorkerStatus{
		Enabled:             s.monitoringBool(ctx, "k8s.services.reconcile_enabled", true),
		IntervalSeconds:     s.monitoringInt(ctx, "k8s.services.reconcile_interval_seconds", 300),
		BatchSize:           s.monitoringInt(ctx, "k8s.services.reconcile_batch_size", 100),
		TimeoutSeconds:      s.monitoringInt(ctx, "k8s.services.reconcile_timeout_seconds", 30),
		InventoryStaleAfter: s.monitoringInt(ctx, "k8s.services.inventory_stale_seconds", 900),
	}
}

func (s *Server) serviceReconcileWorkerStatus(ctx context.Context) ServiceReconcileWorkerStatus {
	settings := s.serviceReconcileSettings(ctx)
	runtime := s.serviceReconcile
	if runtime == nil {
		return settings
	}
	runtime.mu.RLock()
	status := runtime.status
	runtime.mu.RUnlock()
	status.Enabled = settings.Enabled
	status.IntervalSeconds = settings.IntervalSeconds
	status.BatchSize = settings.BatchSize
	status.TimeoutSeconds = settings.TimeoutSeconds
	status.InventoryStaleAfter = settings.InventoryStaleAfter
	status.OwnerID = runtime.owner
	return status
}

func (s *Server) runServiceReconcileBatch(ctx context.Context, force, persist bool, requestedLimit int) (serviceReconcileBatchResult, error) {
	result := serviceReconcileBatchResult{Errors: []string{}, Previews: []serviceReconcileResult{}}
	runtime := s.serviceReconcile
	if runtime == nil {
		return result, fmt.Errorf("service reconcile runtime is not initialized")
	}
	settings := s.serviceReconcileSettings(ctx)
	if !force && !settings.Enabled {
		return result, nil
	}
	if !runtime.runMu.TryLock() {
		return result, fmt.Errorf("service reconcile is already running on this pod")
	}
	defer runtime.runMu.Unlock()
	runtime.mu.Lock()
	runtime.status.Running = true
	runtime.status.LastRun = time.Now().UTC().Format(time.RFC3339Nano)
	runtime.mu.Unlock()

	limit := settings.BatchSize
	if requestedLimit > 0 && requestedLimit < limit {
		limit = requestedLimit
	}
	if limit < 1 {
		limit = 1
	}
	interval := time.Duration(settings.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	before := time.Now().UTC().Add(-interval)
	if force {
		before = time.Now().UTC().Add(time.Second)
	}
	instances, err := s.db.ListK8sServiceInstancesDue(ctx, before.Format(time.RFC3339Nano), limit)
	if err != nil {
		s.updateServiceReconcileStatus(settings, result, err)
		return result, err
	}
	result.Selected = len(instances)
	timeout := time.Duration(settings.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	for _, instance := range instances {
		if ctx.Err() != nil {
			break
		}
		if persist {
			acquired, acquireErr := s.db.TryAcquireK8sServiceReconcileLease(ctx, instance.ID, runtime.owner, time.Now().UTC(), timeout+30*time.Second)
			if acquireErr != nil {
				result.Failed++
				result.Errors = append(result.Errors, instance.ID+": lease: "+acquireErr.Error())
				continue
			}
			if !acquired {
				result.LeaseSkipped++
				continue
			}
		}
		instanceCtx, cancel := context.WithTimeout(ctx, timeout)
		reconciled, reconcileErr := s.reconcileServiceInstance(instanceCtx, instance, persist)
		cancel()
		if persist {
			_ = s.db.ReleaseK8sServiceReconcileLease(context.Background(), instance.ID, runtime.owner)
		}
		if reconcileErr != nil {
			result.Failed++
			result.Errors = append(result.Errors, instance.ID+": "+reconcileErr.Error())
			if persist {
				_ = s.db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: instance.ClusterID, Collector: "service_reconcile", Status: "error", LastError: reconcileErr.Error()})
			}
			continue
		}
		result.Reconciled++
		if reconciled.Health.CollectionStatus != "observed" {
			result.Collecting++
		}
		if !persist && len(result.Previews) < 20 {
			result.Previews = append(result.Previews, reconciled)
		}
		collectorStatus, collectorError := "ok", ""
		if reconciled.Health.CollectionStatus != "observed" {
			collectorStatus, collectorError = "warning", "inventory "+reconciled.Health.CollectionStatus
		}
		if persist {
			_ = s.db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: instance.ClusterID, Collector: "service_reconcile", Status: collectorStatus, LastSuccessAt: time.Now().UTC().Format(time.RFC3339Nano), LastError: collectorError})
		}
	}
	if err := ctx.Err(); err != nil {
		s.updateServiceReconcileStatus(settings, result, err)
		return result, err
	}
	if persist {
		retentionDays := s.monitoringInt(ctx, "k8s.services.health_retention_days", 90)
		pruned, pruneErr := s.db.PruneK8sServiceHealthSnapshots(ctx, time.Now().UTC().Add(-time.Duration(retentionDays)*24*time.Hour).Format(time.RFC3339Nano))
		if pruneErr == nil {
			runtime.mu.Lock()
			runtime.status.PrunedSnapshots = pruned
			runtime.mu.Unlock()
		}
	}
	s.updateServiceReconcileStatus(settings, result, nil)
	return result, nil
}

func (s *Server) updateServiceReconcileStatus(settings ServiceReconcileWorkerStatus, result serviceReconcileBatchResult, runErr error) {
	if s.serviceReconcile == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s.serviceReconcile.mu.Lock()
	defer s.serviceReconcile.mu.Unlock()
	previousPruned := s.serviceReconcile.status.PrunedSnapshots
	previousSuccess := s.serviceReconcile.status.LastSuccess
	status := settings
	status.OwnerID = s.serviceReconcile.owner
	status.LastRun = now
	status.Selected, status.Reconciled, status.Collecting, status.Failed, status.LeaseSkipped = result.Selected, result.Reconciled, result.Collecting, result.Failed, result.LeaseSkipped
	status.Running = false
	status.PrunedSnapshots = previousPruned
	status.LastSuccess = previousSuccess
	if runErr != nil {
		status.LastError = runErr.Error()
	} else {
		status.LastSuccess = now
		if len(result.Errors) > 0 {
			status.LastError = strings.Join(result.Errors, "; ")
		}
	}
	s.serviceReconcile.status = status
}

func (s *Server) handleServiceReconcileWorker(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized", "permission_error", "authentication_required")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"worker": s.serviceReconcileWorkerStatus(r.Context()), "note": "collection_status=missing/stale이면 실제 장애로 확정하지 않고 collecting으로 분리합니다."})
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var input struct {
		DryRun bool `json:"dry_run"`
		Force  bool `json:"force"`
		Limit  int  `json:"limit"`
	}
	_ = json.NewDecoder(r.Body).Decode(&input)
	if input.Limit < 0 || input.Limit > 1000 {
		writeOpenAIError(w, http.StatusBadRequest, "limit must be between 0 and 1000", "invalid_request_error", "invalid_limit")
		return
	}
	result, err := s.runServiceReconcileBatch(r.Context(), input.Force || input.DryRun, !input.DryRun, input.Limit)
	if err != nil {
		writeOpenAIError(w, http.StatusConflict, err.Error(), "invalid_request_error", "service_reconcile_busy")
		return
	}
	s.auditAdmin(r, "k8s.service_reconcile.run", "", auditJSON(map[string]any{"dry_run": input.DryRun, "force": input.Force, "selected": result.Selected, "reconciled": result.Reconciled, "failed": result.Failed}))
	writeJSON(w, http.StatusOK, map[string]any{"result": result, "worker": s.serviceReconcileWorkerStatus(r.Context()), "dry_run": input.DryRun})
}
