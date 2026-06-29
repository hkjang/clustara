package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"clustara/internal/store"
)

type AlertWorker struct {
	db          *store.SQLStore
	metrics     *Metrics
	interval    time.Duration
	client      *http.Client
	done        chan struct{}
	wg          sync.WaitGroup
	started     atomic.Bool
	lastRun     atomic.Value // string RFC3339Nano
	lastSuccess atomic.Value // string RFC3339Nano
	lastError   atomic.Value // string
	errorCount  atomic.Uint64
	firedCount  atomic.Uint64
}

type AlertWorkerStatus struct {
	Running     bool   `json:"running"`
	Interval    string `json:"interval"`
	LastRun     string `json:"last_run"`
	LastSuccess string `json:"last_success"`
	LastError   string `json:"last_error"`
	ErrorCount  uint64 `json:"error_count"`
	FiredCount  uint64 `json:"fired_count"`
}

func NewAlertWorker(db *store.SQLStore, metrics *Metrics, interval time.Duration) *AlertWorker {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	w := &AlertWorker{
		db:       db,
		metrics:  metrics,
		interval: interval,
		client:   &http.Client{Timeout: 10 * time.Second},
		done:     make(chan struct{}),
	}
	w.lastRun.Store("")
	w.lastSuccess.Store("")
	w.lastError.Store("")
	return w
}

func (w *AlertWorker) Start() {
	w.started.Store(true)
	w.wg.Add(1)
	go w.run()
}

func (w *AlertWorker) Stop() {
	close(w.done)
	w.wg.Wait()
	w.started.Store(false)
}

func (w *AlertWorker) Status() AlertWorkerStatus {
	return AlertWorkerStatus{
		Running:     w.started.Load(),
		Interval:    w.interval.String(),
		LastRun:     alertWorkerStringValue(&w.lastRun),
		LastSuccess: alertWorkerStringValue(&w.lastSuccess),
		LastError:   alertWorkerStringValue(&w.lastError),
		ErrorCount:  w.errorCount.Load(),
		FiredCount:  w.firedCount.Load(),
	}
}

func (w *AlertWorker) run() {
	defer w.wg.Done()
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			w.evaluate()
		case <-w.done:
			return
		}
	}
}

func (w *AlertWorker) evaluate() {
	nowRun := time.Now().UTC().Format(time.RFC3339Nano)
	w.lastRun.Store(nowRun)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rules, err := w.db.ListAlertRules(ctx)
	if err != nil {
		slog.Warn("alert worker: list rules failed", "error", err)
		w.recordError(err)
		return
	}
	now := time.Now()
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		// debounce: don't refire within window after last fire
		if rule.LastFiredAt != nil && now.Sub(*rule.LastFiredAt) < time.Duration(rule.WindowSeconds)*time.Second {
			continue
		}
		since := now.Add(-time.Duration(rule.WindowSeconds) * time.Second)
		snapshot, err := w.db.MetricSince(ctx, rule.Scope, rule.ScopeValue, since)
		if err != nil {
			slog.Warn("alert worker: metric query failed", "rule", rule.Name, "error", err)
			w.recordError(err)
			continue
		}
		value := metricValue(rule.Metric, snapshot)
		if value < rule.Threshold {
			continue
		}
		w.fire(ctx, rule, value)
	}
	w.lastSuccess.Store(time.Now().UTC().Format(time.RFC3339Nano))
	w.lastError.Store("")
}

func metricValue(metric string, snapshot store.AlertMetricSnapshot) float64 {
	switch metric {
	case "requests":
		return float64(snapshot.Requests)
	case "errors":
		if snapshot.Requests == 0 {
			return 0
		}
		return float64(snapshot.Errors) / float64(snapshot.Requests)
	case "krw":
		return snapshot.CostKRW
	case "tokens":
		return float64(snapshot.Tokens)
	case "latency_p95_ms":
		return snapshot.LatencyP95MS
	case "first_chunk_p95_ms":
		return snapshot.FirstChunkP95MS
	case "llm_eval_failures":
		return float64(snapshot.LLMEvalFailures)
	case "llm_eval_failure_rate":
		if snapshot.LLMEvaluations == 0 {
			return 0
		}
		return float64(snapshot.LLMEvalFailures) / float64(snapshot.LLMEvaluations)
	case "tool_errors":
		return float64(snapshot.ToolErrors)
	case "tool_error_rate":
		if snapshot.ToolCalls == 0 {
			return 0
		}
		return float64(snapshot.ToolErrors) / float64(snapshot.ToolCalls)
	case "tool_loop":
		return float64(snapshot.MaxSessionToolCall)
	case "mcp_new_tools":
		return float64(snapshot.NewCatalogTools)
	case "anomaly_zmax":
		return snapshot.MaxAnomalyZ
	case "budget_burn_ratio":
		return snapshot.MaxBudgetRatio
	}
	return 0
}

func (w *AlertWorker) fire(ctx context.Context, rule store.AlertRule, value float64) {
	now := time.Now().UTC()
	w.metrics.IncAlertFired()
	w.firedCount.Add(1)
	event := store.AlertEvent{
		ID:        newID("alertev"),
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		Metric:    rule.Metric,
		Value:     value,
		Threshold: rule.Threshold,
		CreatedAt: now,
	}
	if rule.WebhookURL != "" {
		if err := w.postWebhook(ctx, rule, value); err != nil {
			event.DeliveryError = err.Error()
			w.recordError(err)
		} else {
			event.Delivered = true
			w.metrics.IncAlertDelivered()
		}
	}
	if err := w.db.InsertAlertEvent(ctx, event); err != nil {
		slog.Warn("alert worker: insert event failed", "rule", rule.Name, "error", err)
		w.recordError(err)
	}
	if err := w.db.UpdateAlertFireState(ctx, rule.ID, value, now); err != nil {
		slog.Warn("alert worker: update fire state failed", "rule", rule.Name, "error", err)
		w.recordError(err)
	}
}

func (w *AlertWorker) recordError(err error) {
	if err == nil {
		return
	}
	w.errorCount.Add(1)
	w.lastError.Store(err.Error())
}

func alertWorkerStringValue(v *atomic.Value) string {
	if v == nil {
		return ""
	}
	if s, ok := v.Load().(string); ok {
		return s
	}
	return ""
}

func (w *AlertWorker) postWebhook(ctx context.Context, rule store.AlertRule, value float64) error {
	text := fmt.Sprintf("[Clustara 알림] 규칙 %q 임계치 도달: %s = %s (>= %s, 윈도우 %ds, 대상 %s/%s)",
		rule.Name, rule.Metric, formatMetricValue(rule.Metric, value),
		formatMetricValue(rule.Metric, rule.Threshold), rule.WindowSeconds, rule.Scope, rule.ScopeValue)
	body, _ := json.Marshal(map[string]any{
		"text":           text,
		"rule":           rule.Name,
		"metric":         rule.Metric,
		"value":          value,
		"threshold":      rule.Threshold,
		"window_seconds": rule.WindowSeconds,
		"scope":          rule.Scope,
		"scope_value":    rule.ScopeValue,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rule.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func formatMetricValue(metric string, value float64) string {
	switch metric {
	case "krw":
		return fmt.Sprintf("₩%.0f", value)
	case "errors", "llm_eval_failure_rate", "tool_error_rate":
		return fmt.Sprintf("%.1f%%", value*100)
	case "llm_eval_failures":
		return fmt.Sprintf("%.0f failures", value)
	case "latency_p95_ms", "first_chunk_p95_ms":
		return fmt.Sprintf("%.0f ms", value)
	default:
		return fmt.Sprintf("%.0f", value)
	}
}
