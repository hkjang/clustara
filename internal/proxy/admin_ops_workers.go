package proxy

import (
	"net/http"
	"strings"
	"time"

	"clustara/internal/store"
)

// workerStatus is one background worker's observable health.
type workerStatus struct {
	Name        string `json:"name"`
	Running     bool   `json:"running"`
	Status      string `json:"status"` // ok | warn | critical | idle
	QueueDepth  int    `json:"queue_depth"`
	Capacity    int    `json:"capacity"`
	Dropped     int64  `json:"dropped"`
	LastRun     string `json:"last_run"`
	LastSuccess string `json:"last_success"`
	LastError   string `json:"last_error"`
	ErrorCount  uint64 `json:"error_count"`
	LagSeconds  int64  `json:"lag_seconds"`
	Detail      string `json:"detail"`
}

// handleOpsWorkers reports the runtime state of the gateway's background workers (async logger,
// per-request fact ingest queue, ClickHouse sink, fact-retry backlog, retention). Read-only.
// GET /admin/ops/workers
func (s *Server) handleOpsWorkers(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	workers := []workerStatus{}

	// Async request logger.
	if s.logger != nil {
		depth := s.logger.QueueDepth()
		dropped := int64(s.logger.Dropped())
		ws := workerStatus{Name: "async_logger", Running: true, Status: "ok", QueueDepth: depth, Capacity: s.logger.QueueCapacity(), Dropped: dropped,
			LastSuccess: s.logger.LastSuccess(), LastError: s.logger.LastError(), ErrorCount: s.logger.Failed(),
			Detail: "written=" + itoaProxy(int(s.logger.Written()))}
		if dropped > 0 {
			ws.Status = "warn"
		}
		if ws.LastError != "" {
			ws.Status = worseStatus(ws.Status, "warn")
		}
		if ws.Capacity > 0 && depth >= ws.Capacity*9/10 {
			ws.Status = "critical"
			ws.Detail = "audit queue near capacity"
		} else if depth > 5000 {
			ws.Status = "critical"
		}
		workers = append(workers, ws)
	}

	// Per-request fact ingest queue (feeds the ClickHouse fact loop).
	if s.chFactQueue != nil {
		depth, capn := len(s.chFactQueue), cap(s.chFactQueue)
		dropped := s.chFactDropped.Load()
		ws := workerStatus{Name: "clickhouse_fact_queue", Running: true, Status: "ok", QueueDepth: depth, Capacity: capn, Dropped: dropped,
			Detail: "per-request fact ingest"}
		if dropped > 0 {
			ws.Status = "warn"
		}
		if capn > 0 && depth >= capn*9/10 {
			ws.Status = "critical"
			ws.Detail = "queue near capacity"
		}
		workers = append(workers, ws)
	}

	// ClickHouse rollup sink worker (managed lifecycle).
	ch := s.chConf()
	s.chSinkMu.Lock()
	sinkRunning := s.chSinkStop != nil
	sinkStarted := s.chSinkStarted
	s.chSinkMu.Unlock()
	sink := workerStatus{Name: "clickhouse_sink", Running: sinkRunning, Status: "idle", Detail: "ClickHouse rollup sink"}
	switch {
	case ch.URL == "":
		sink.Detail = "ClickHouse 미설정"
	case sinkRunning:
		sink.Status = "ok"
		sink.Detail = "rollup sink 실행 중"
	case sinkStarted:
		sink.Status = "warn"
		sink.Detail = "설정됐으나 sink 미실행 (interval/URL 확인)"
	}
	workers = append(workers, sink)

	// Fact-retry backlog (failed inserts awaiting retry).
	if ch.URL != "" {
		retry := workerStatus{Name: "clickhouse_fact_retry", Running: true, Status: "ok", Detail: "재시도 대기 fact 배치"}
		if n, err := s.db.CountClickHouseFactRetries(r.Context()); err == nil {
			retry.QueueDepth = n
			if n > 0 {
				retry.Status = "warn"
			}
			if n >= 50 {
				retry.Status = "critical"
			}
		} else {
			retry.Status, retry.Detail = "warn", "백로그 조회 실패"
		}
		workers = append(workers, retry)
	}

	// Retention worker.
	if s.retention != nil {
		cfg := s.retention.Config()
		// LastSuccess is deliberately not LastRun: retention stamps a run even
		// when every purge inside it failed, and that is exactly when the store
		// stops being bounded.
		ws := workerStatus{Name: "retention", Running: cfg.Interval > 0, Status: "ok", LastRun: s.retention.LastRun(),
			LastSuccess: s.retention.LastSuccess(), LastError: s.retention.LastError(),
			ErrorCount: s.retention.ErrorCount(), LagSeconds: secondsSinceRFC3339(s.retention.LastSuccess()),
			Detail: "interval=" + cfg.Interval.String() + " requests=" + itoaProxy(cfg.RequestDays) + "d"}
		if cfg.Interval <= 0 {
			ws.Status, ws.Detail = "idle", "보존 주기 비활성(Interval=0)"
		} else if ws.LastRun == "" {
			ws.Status = "warn"
			ws.Detail += " · 아직 실행 이력 없음"
		} else if ws.LastSuccess == "" {
			ws.Status = "critical"
			ws.Detail += " · 성공한 실행이 한 번도 없음(보존 미동작)"
		} else if ws.LastError != "" {
			ws.Status = "warn"
			ws.Detail += " · 최근 실행 실패: " + ws.LastError
		} else if cfg.Interval > 0 && time.Duration(ws.LagSeconds)*time.Second > cfg.Interval*3 {
			ws.Status = "warn"
			ws.Detail += " · 최근 성공 지연"
		}
		workers = append(workers, ws)
	}

	if aw := s.alertWorker.Load(); aw != nil {
		st := aw.Status()
		ws := workerStatus{Name: "alert_worker", Running: st.Running, Status: "ok",
			LastRun: st.LastRun, LastSuccess: st.LastSuccess, LastError: st.LastError, ErrorCount: st.ErrorCount,
			LagSeconds: secondsSinceRFC3339(st.LastSuccess), Detail: "interval=" + st.Interval + " fired=" + itoaProxy(int(st.FiredCount))}
		if !st.Running {
			ws.Status = "idle"
		}
		if st.LastError != "" {
			ws.Status = worseStatus(ws.Status, "warn")
		}
		workers = append(workers, ws)
	} else {
		workers = append(workers, workerStatus{Name: "alert_worker", Running: false, Status: "idle", Detail: "alert worker not attached"})
	}

	// Durable Kubernetes workers. These converge rollout and terminal-session
	// state with no browser tab attached, so a stalled one is an availability
	// problem an operator has to see rather than infer from logs.
	rolloutDetail := "롤아웃 리컨실러"
	if owner := s.rolloutReconciler.Load().OwnerID(); owner != "" {
		rolloutDetail += " (owner=" + owner + ")"
	}
	workers = append(workers,
		durableWorkerStatus(s.rolloutReconciler.Load().Status(), s.cfg.Workers.RolloutReconcilerEnabled, rolloutDetail),
		durableWorkerStatus(s.terminalReaper.Load().Status(), s.cfg.Workers.TerminalReaperEnabled, "터미널 세션 리퍼"),
	)

	// Schedulers NewServer owns (inventory collection, node metrics, cost
	// snapshots, report delivery, service reconcile, Text2SQL reports). Each one
	// reports measured state: a scheduler that self-disabled or died shows as
	// idle/critical rather than being assumed healthy.
	for _, st := range s.schedulerStatuses() {
		workers = append(workers, schedulerWorkerStatus(st))
	}

	// Ingestion collector health. Five subsystems record into k8s_collector_status
	// and nothing read it, so a collector could be failing every batch with no
	// operator surface showing it. Worst status first; bounded so a large fleet
	// cannot swamp the board.
	if s.db != nil {
		if rows, err := s.db.ListK8sCollectorStatus(r.Context(), 50); err == nil {
			for _, st := range rows {
				workers = append(workers, collectorWorkerStatus(st))
			}
		} else {
			workers = append(workers, workerStatus{Name: "k8s_collectors", Running: false, Status: "warn",
				Detail: "수집기 상태 조회 실패: " + err.Error()})
		}
	}

	overall := "ok"
	for _, ws := range workers {
		overall = worseStatus(overall, ws.Status)
	}
	writeJSON(w, http.StatusOK, map[string]any{"overall": overall, "workers": workers})
}

// durableWorkerStatus maps a background worker's counters onto the shared
// workerStatus shape. A worker that is configured on but not running, or one
// whose ticks keep failing, escalates so the ops page shows it as degraded.
func durableWorkerStatus(st backgroundWorkerStatus, enabled bool, detail string) workerStatus {
	ws := workerStatus{
		Name: st.Name, Running: st.Running, Status: "ok",
		LastRun: st.LastRun, LastSuccess: st.LastSuccess, LastError: st.LastError,
		ErrorCount: st.Failures, LagSeconds: secondsSinceRFC3339(st.LastSuccess),
		Detail: detail + " · interval=" + st.Interval + " ticks=" + itoaProxy(int(st.Ticks)) +
			" processed=" + itoaProxy(int(st.Processed)),
	}
	switch {
	case !enabled:
		ws.Status, ws.Detail = "idle", detail+" · 비활성(설정으로 꺼짐)"
	case !st.Running:
		ws.Status, ws.Detail = "critical", detail+" · 활성 설정이지만 실행 중이 아님"
	case st.ConsecutiveFailures >= 3:
		ws.Status = "critical"
		ws.Detail += " · 연속 실패 " + itoaProxy(int(st.ConsecutiveFailures)) + "회, backoff=" + st.CurrentDelay
	case st.LastError != "":
		ws.Status = "warn"
		ws.Detail += " · 최근 tick 실패"
	case st.LastSuccess == "":
		ws.Status = "warn"
		ws.Detail += " · 아직 성공 이력 없음"
	}
	return ws
}

// schedulerWorkerStatus maps a NewServer-owned scheduler onto the shared
// workerStatus shape. Unlike the durable K8s workers there is no enable flag:
// a scheduler that is not running either self-disabled (no execute DB, no
// reload interval) or exited, and both are worth surfacing.
func schedulerWorkerStatus(st backgroundWorkerStatus) workerStatus {
	ws := workerStatus{
		Name: st.Name, Running: st.Running, Status: "ok",
		LastRun: st.LastRun, LastSuccess: st.LastSuccess, LastError: st.LastError,
		ErrorCount: st.Failures, LagSeconds: secondsSinceRFC3339(st.LastSuccess),
		Detail: "interval=" + st.Interval + " ticks=" + itoaProxy(int(st.Ticks)) +
			" processed=" + itoaProxy(int(st.Processed)),
	}
	switch {
	case !st.Running && !st.Enabled:
		// Deliberately inert: switched off, or self-disabled with a stated reason.
		ws.Status = "idle"
		ws.Detail += " · 비활성"
		if st.DisabledReason != "" {
			ws.Detail += "(" + st.DisabledReason + ")"
		}
	case !st.Running:
		// Started and then stopped. Nothing restarts a scheduler, so this is permanent until
		// the process is restarted — the same condition durableWorkerStatus calls critical.
		// Both states used to render as "idle", so a dead scheduler and one that was never
		// meant to run were the same line on the board.
		ws.Status = "critical"
		ws.Detail += " · 시작됐으나 실행 중이 아님 — 재시작 전까지 복구되지 않음"
	case st.ConsecutiveFailures >= 3:
		ws.Status = "critical"
		ws.Detail += " · 연속 실패 " + itoaProxy(int(st.ConsecutiveFailures)) + "회"
	case st.LastError != "":
		ws.Status = "warn"
		ws.Detail += " · 최근 tick 실패"
	}
	return ws
}

// collectorWorkerStatus renders one recorded ingestion collector onto the board.
// last_success is reported separately from the current status for the same reason
// the retention worker does: a collector erroring now may still have succeeded
// recently, and one that has never succeeded is a different problem entirely.
func collectorWorkerStatus(st store.K8sCollectorStatus) workerStatus {
	ws := workerStatus{
		Name:        "k8s_collector:" + st.Collector + "@" + st.ClusterID,
		Running:     true,
		Status:      "ok",
		LastRun:     st.UpdatedAt,
		LastSuccess: st.LastSuccessAt,
		LastError:   st.LastError,
		LagSeconds:  secondsSinceRFC3339(st.LastSuccessAt),
		Detail:      "cluster=" + st.ClusterID + " collector=" + st.Collector,
	}
	if st.LagSeconds > 0 {
		ws.LagSeconds = int64(st.LagSeconds)
	}
	switch {
	case strings.EqualFold(st.Status, "error"):
		ws.Status = "critical"
		if st.LastError != "" {
			ws.Detail += " · " + st.LastError
		}
		if st.LastSuccessAt == "" {
			ws.Detail += " · 성공한 수집이 한 번도 없음"
		}
	case strings.EqualFold(st.Status, "warn"):
		ws.Status = "warn"
	case st.LastSuccessAt == "":
		ws.Status = "warn"
		ws.Detail += " · 성공 이력 없음"
	}
	return ws
}

func secondsSinceRFC3339(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return 0
		}
	}
	if ts.IsZero() {
		return 0
	}
	return int64(time.Since(ts).Seconds())
}
