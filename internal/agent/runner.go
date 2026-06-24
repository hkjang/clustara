package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"clustara/internal/collector"
	"clustara/internal/kube"
)

type Runner struct {
	cfg            Config
	kubeToken      string
	kubeHTTP       *http.Client
	clustaraHTTP   *http.Client
	targets        []kube.ResourceTarget
	events         chan queuedEvent
	state          *stateStore
	queueMu        sync.Mutex
	statsMu        sync.Mutex
	reconnects     int64
	eventsTotal    int64
	lastError      string
	lastResourceRV string
}

type queuedEvent struct {
	target          kube.ResourceTarget
	watchType       string
	object          map[string]any
	resourceVersion string
	receivedAt      time.Time
}

type watchEnvelope struct {
	Type   string         `json:"type"`
	Object map[string]any `json:"object"`
}

type listResponse struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []map[string]any `json:"items"`
}

type apiError struct {
	Status int
	Body   string
}

func (e apiError) Error() string {
	return fmt.Sprintf("Kubernetes API returned %d: %s", e.Status, strings.TrimSpace(e.Body))
}

func NewRunner(cfg Config) (*Runner, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	kubeHTTP, kubeToken, err := newKubeHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	targets, err := selectTargets(cfg.WatchKinds)
	if err != nil {
		return nil, err
	}
	return &Runner{
		cfg:          cfg,
		kubeToken:    kubeToken,
		kubeHTTP:     kubeHTTP,
		clustaraHTTP: &http.Client{Timeout: cfg.RequestTimeout},
		targets:      targets,
		events:       make(chan queuedEvent, cfg.QueueSize),
		state:        loadState(cfg.StateFile),
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	slog.Info("starting clustara-agent", "cluster_id", r.cfg.ClusterID, "agent_id", r.cfg.AgentID, "targets", len(r.targets), "endpoint", r.cfg.Endpoint)
	for _, target := range r.targets {
		target := target
		go r.watchLoop(ctx, target)
	}
	return r.flushLoop(ctx)
}

func (r *Runner) watchLoop(ctx context.Context, target kube.ResourceTarget) {
	backoff := time.Second
	for ctx.Err() == nil {
		rv := r.state.Get(target.Kind)
		if rv == "" {
			nextRV, err := r.listCurrent(ctx, target)
			if err != nil {
				r.recordError(fmt.Errorf("%s list failed: %w", target.Kind, err))
				wait(ctx, backoff)
				backoff = nextBackoff(backoff)
				continue
			}
			rv = nextRV
		}
		err := r.watch(ctx, target, rv)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = time.Second
			continue
		}
		if isResourceVersionExpired(err) {
			_ = r.state.Clear(target.Kind)
			r.recordError(fmt.Errorf("%s resourceVersion expired; relisting", target.Kind))
			backoff = time.Second
			continue
		}
		if target.Optional && isOptionalUnavailable(err) {
			r.recordError(fmt.Errorf("%s watch disabled or unavailable: %w", target.Kind, err))
			wait(ctx, 5*time.Minute)
			continue
		}
		r.incrementReconnect(err)
		wait(ctx, backoff)
		backoff = nextBackoff(backoff)
	}
}

func (r *Runner) listCurrent(ctx context.Context, target kube.ResourceTarget) (string, error) {
	continueToken := ""
	lastRV := ""
	for {
		var body listResponse
		if err := r.getKubeJSON(ctx, listPath(target.Path, continueToken), &body); err != nil {
			if target.Optional && isOptionalUnavailable(err) {
				return "", nil
			}
			return "", err
		}
		pageRV := strings.TrimSpace(body.Metadata.ResourceVersion)
		if pageRV != "" {
			lastRV = pageRV
		}
		for _, obj := range body.Items {
			rv := firstNonEmpty(objectResourceVersion(obj), pageRV)
			if rv != "" {
				lastRV = rv
			}
			if err := r.enqueue(ctx, queuedEvent{
				target:          target,
				watchType:       collector.AgentAdded,
				object:          obj,
				resourceVersion: rv,
				receivedAt:      time.Now().UTC(),
			}); err != nil {
				return lastRV, err
			}
		}
		continueToken = strings.TrimSpace(body.Metadata.Continue)
		if continueToken == "" {
			break
		}
	}
	if lastRV != "" {
		if err := r.state.Set(target.Kind, lastRV); err != nil {
			r.recordError(fmt.Errorf("save %s resourceVersion: %w", target.Kind, err))
		}
		r.setLastResourceVersion(lastRV)
	}
	return lastRV, nil
}

func (r *Runner) watch(ctx context.Context, target kube.ResourceTarget, rv string) error {
	reqURL, err := url.Parse(r.cfg.KubeAPIServer + target.Path)
	if err != nil {
		return err
	}
	q := reqURL.Query()
	q.Set("watch", "true")
	q.Set("allowWatchBookmarks", "true")
	q.Set("timeoutSeconds", strconv.Itoa(maxInt(1, int(r.cfg.WatchTimeout/time.Second))))
	if strings.TrimSpace(rv) != "" {
		q.Set("resourceVersion", strings.TrimSpace(rv))
	}
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return err
	}
	r.setKubeHeaders(req)
	resp, err := r.kubeHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return apiError{Status: resp.StatusCode, Body: string(b)}
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev watchEnvelope
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		watchType := strings.ToUpper(strings.TrimSpace(ev.Type))
		rv := objectResourceVersion(ev.Object)
		if watchType == "ERROR" {
			return statusObjectError(ev.Object)
		}
		if rv != "" {
			if err := r.state.Set(target.Kind, rv); err != nil {
				r.recordError(fmt.Errorf("save %s resourceVersion: %w", target.Kind, err))
			}
			r.setLastResourceVersion(rv)
		}
		if watchType == "BOOKMARK" {
			continue
		}
		if watchType != collector.AgentAdded && watchType != collector.AgentModified && watchType != collector.AgentDeleted {
			continue
		}
		if err := r.enqueue(ctx, queuedEvent{
			target:          target,
			watchType:       watchType,
			object:          ev.Object,
			resourceVersion: rv,
			receivedAt:      time.Now().UTC(),
		}); err != nil {
			return err
		}
	}
}

func (r *Runner) flushLoop(ctx context.Context) error {
	batchTicker := time.NewTicker(r.cfg.BatchInterval)
	defer batchTicker.Stop()
	heartbeatTicker := time.NewTicker(r.cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	pending := make([]queuedEvent, 0, r.cfg.MaxBatchSize)
	for {
		select {
		case ev := <-r.events:
			pending = append(pending, ev)
			if len(pending) >= r.cfg.MaxBatchSize {
				r.flushEvents(ctx, pending)
				pending = make([]queuedEvent, 0, r.cfg.MaxBatchSize)
			}
		case <-batchTicker.C:
			if len(pending) > 0 {
				r.flushEvents(ctx, pending)
				pending = make([]queuedEvent, 0, r.cfg.MaxBatchSize)
			}
		case <-heartbeatTicker.C:
			if len(pending) > 0 {
				r.flushEvents(ctx, pending)
				pending = make([]queuedEvent, 0, r.cfg.MaxBatchSize)
			} else {
				r.flushEvents(ctx, nil)
			}
		case <-ctx.Done():
			if len(pending) > 0 {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), r.cfg.RequestTimeout)
				r.flushEvents(shutdownCtx, pending)
				cancel()
			}
			return nil
		}
	}
}

func (r *Runner) flushEvents(ctx context.Context, events []queuedEvent) {
	batch := r.buildBatch(events)
	if err := r.replayQueued(ctx); err != nil {
		r.recordError(err)
		if hasPayload(batch) {
			if qerr := r.queueBatch(batch); qerr != nil {
				r.recordError(qerr)
			}
		}
		return
	}
	if err := r.postBatch(ctx, batch); err != nil {
		r.recordError(err)
		if hasPayload(batch) {
			if qerr := r.queueBatch(batch); qerr != nil {
				r.recordError(qerr)
			}
		}
		return
	}
	r.clearError()
}

func (r *Runner) buildBatch(events []queuedEvent) collector.AgentBatch {
	now := time.Now().UTC()
	reconnects, total, lastErr, lastRV := r.stats()
	batch := collector.AgentBatch{
		ClusterID:       r.cfg.ClusterID,
		AgentID:         r.cfg.AgentID,
		Version:         r.cfg.Version,
		ResourceVersion: lastRV,
		ObservedAt:      now.Format(time.RFC3339Nano),
		Reconnects:      reconnects,
		EventsTotal:     total,
		LastError:       lastErr,
		Events:          []collector.AgentEvent{},
	}
	var maxLag time.Duration
	for _, ev := range events {
		if lag := now.Sub(ev.receivedAt); lag > maxLag {
			maxLag = lag
		}
		rv := firstNonEmpty(ev.resourceVersion, objectResourceVersion(ev.object))
		if rv != "" {
			batch.ResourceVersion = rv
		}
		if ev.target.KubernetesEvents {
			if ev.watchType == collector.AgentDeleted {
				continue
			}
			k8sEvent := kube.EventFromObject(ev.object)
			if strings.TrimSpace(k8sEvent.Reason) == "" && strings.TrimSpace(k8sEvent.Message) == "" {
				continue
			}
			k8sEvent.LastSeen = firstNonEmpty(k8sEvent.LastSeen, batch.ObservedAt)
			k8sEvent.FirstSeen = firstNonEmpty(k8sEvent.FirstSeen, k8sEvent.LastSeen)
			batch.K8sEvents = append(batch.K8sEvents, k8sEvent)
			continue
		}
		item := kube.InventoryFromObject(ev.target.Kind, ev.target.APIVersion, ev.object)
		if item.Name == "" {
			continue
		}
		item.ObservedAt = batch.ObservedAt
		batch.Events = append(batch.Events, collector.AgentEvent{
			Type:            ev.watchType,
			ResourceVersion: rv,
			Object:          item,
		})
	}
	batch.WatchLagMS = maxLag.Milliseconds()
	return batch
}

func (r *Runner) enqueue(ctx context.Context, ev queuedEvent) error {
	select {
	case r.events <- ev:
		r.statsMu.Lock()
		r.eventsTotal++
		if ev.resourceVersion != "" {
			r.lastResourceRV = ev.resourceVersion
		}
		r.statsMu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runner) postBatch(ctx context.Context, batch collector.AgentBatch) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(batch); err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, r.cfg.Endpoint, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clustara-agent/"+r.cfg.Version)
	if r.cfg.ClustaraToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.ClustaraToken)
	}
	resp, err := r.clustaraHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("post Clustara agent batch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("post Clustara agent batch returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (r *Runner) replayQueued(ctx context.Context) error {
	if r.cfg.QueueFile == "" {
		return nil
	}
	r.queueMu.Lock()
	defer r.queueMu.Unlock()
	b, err := os.ReadFile(r.cfg.QueueFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read offline queue: %w", err)
	}
	lines := bytes.Split(b, []byte("\n"))
	remaining := make([][]byte, 0)
	failed := false
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if failed {
			remaining = append(remaining, append([]byte{}, line...))
			continue
		}
		var batch collector.AgentBatch
		if err := json.Unmarshal(line, &batch); err != nil {
			slog.Warn("dropping corrupt clustara-agent offline queue entry", "error", err)
			continue
		}
		if err := r.postBatch(ctx, batch); err != nil {
			remaining = append(remaining, append([]byte{}, line...))
			failed = true
		}
	}
	if len(remaining) == 0 {
		if err := os.Remove(r.cfg.QueueFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clear offline queue: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.cfg.QueueFile), 0o755); err != nil {
		return fmt.Errorf("prepare offline queue dir: %w", err)
	}
	var out bytes.Buffer
	for _, line := range remaining {
		out.Write(line)
		out.WriteByte('\n')
	}
	if err := os.WriteFile(r.cfg.QueueFile, out.Bytes(), 0o600); err != nil {
		return fmt.Errorf("rewrite offline queue: %w", err)
	}
	return fmt.Errorf("offline queue replay paused after %d pending batch(es)", len(remaining))
}

func (r *Runner) queueBatch(batch collector.AgentBatch) error {
	if r.cfg.QueueFile == "" || !hasPayload(batch) {
		return nil
	}
	r.queueMu.Lock()
	defer r.queueMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(r.cfg.QueueFile), 0o755); err != nil {
		return fmt.Errorf("prepare offline queue dir: %w", err)
	}
	f, err := os.OpenFile(r.cfg.QueueFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open offline queue: %w", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(batch)
}

func (r *Runner) getKubeJSON(ctx context.Context, path string, out any) error {
	reqCtx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, r.cfg.KubeAPIServer+path, nil)
	if err != nil {
		return err
	}
	r.setKubeHeaders(req)
	resp, err := r.kubeHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return apiError{Status: resp.StatusCode, Body: string(b)}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (r *Runner) setKubeHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "clustara-agent/"+r.cfg.Version)
	if r.kubeToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.kubeToken)
	}
}

func (r *Runner) stats() (int64, int64, string, string) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.reconnects, r.eventsTotal, r.lastError, r.lastResourceRV
}

func (r *Runner) incrementReconnect(err error) {
	r.statsMu.Lock()
	r.reconnects++
	r.lastError = truncateError(err)
	r.statsMu.Unlock()
	slog.Warn("Kubernetes watch reconnecting", "error", err)
}

func (r *Runner) recordError(err error) {
	if err == nil {
		return
	}
	r.statsMu.Lock()
	r.lastError = truncateError(err)
	r.statsMu.Unlock()
	slog.Warn("clustara-agent warning", "error", err)
}

func (r *Runner) clearError() {
	r.statsMu.Lock()
	r.lastError = ""
	r.statsMu.Unlock()
}

func (r *Runner) setLastResourceVersion(rv string) {
	if rv == "" {
		return
	}
	r.statsMu.Lock()
	r.lastResourceRV = rv
	r.statsMu.Unlock()
}

func newKubeHTTPClient(cfg Config) (*http.Client, string, error) {
	token := ""
	if cfg.KubeTokenFile != "" {
		if b, err := os.ReadFile(cfg.KubeTokenFile); err == nil {
			token = strings.TrimSpace(string(b))
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("read KUBE_TOKEN_FILE: %w", err)
		}
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.KubeInsecureTLS {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // explicit operator opt-in for private test clusters.
	}
	if cfg.KubeCAFile != "" {
		if ca, err := os.ReadFile(cfg.KubeCAFile); err == nil && len(ca) > 0 {
			pool := x509.NewCertPool()
			if ok := pool.AppendCertsFromPEM(ca); !ok {
				return nil, "", fmt.Errorf("invalid KUBE_CA_FILE")
			}
			tlsConf.RootCAs = pool
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("read KUBE_CA_FILE: %w", err)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConf
	return &http.Client{Transport: transport}, token, nil
}

func selectTargets(kinds []string) ([]kube.ResourceTarget, error) {
	all := kube.DefaultWatchTargets()
	if len(kinds) == 0 {
		return all, nil
	}
	wantAll := false
	want := map[string]bool{}
	for _, kind := range kinds {
		key := strings.ToLower(strings.TrimSpace(kind))
		if key == "all" || key == "*" {
			wantAll = true
			break
		}
		if key != "" {
			want[key] = true
		}
	}
	if wantAll {
		return all, nil
	}
	out := make([]kube.ResourceTarget, 0, len(all))
	for _, target := range all {
		if want[strings.ToLower(target.Kind)] {
			out = append(out, target)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("WATCH_KINDS did not match any known Kubernetes resource")
	}
	return out, nil
}

func listPath(path string, continueToken string) string {
	u := url.URL{Path: path}
	q := u.Query()
	q.Set("limit", "500")
	if continueToken != "" {
		q.Set("continue", continueToken)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func objectResourceVersion(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	return anyString(meta["resourceVersion"])
}

func statusObjectError(obj map[string]any) error {
	code := 0
	if n, ok := obj["code"].(float64); ok {
		code = int(n)
	}
	msg := firstNonEmpty(anyString(obj["message"]), anyString(obj["reason"]), "watch error")
	return apiError{Status: code, Body: msg}
}

func anyString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func hasPayload(batch collector.AgentBatch) bool {
	return len(batch.Events) > 0 || len(batch.K8sEvents) > 0
}

func isOptionalUnavailable(err error) bool {
	var apiErr apiError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusForbidden
	}
	return false
}

func isResourceVersionExpired(err error) bool {
	var apiErr apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Status == http.StatusGone {
		return true
	}
	body := strings.ToLower(apiErr.Body)
	return strings.Contains(body, "too old resource version") || strings.Contains(body, "expired")
}

func wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > 30*time.Second {
		return 30 * time.Second
	}
	return next
}

func truncateError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 600 {
		return msg[:600]
	}
	return msg
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type stateStore struct {
	path string
	mu   sync.Mutex
	data agentState
}

type agentState struct {
	ResourceVersions map[string]string `json:"resource_versions"`
}

func loadState(path string) *stateStore {
	st := &stateStore{path: path, data: agentState{ResourceVersions: map[string]string{}}}
	if path == "" {
		return st
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st.data)
	if st.data.ResourceVersions == nil {
		st.data.ResourceVersions = map[string]string{}
	}
	return st
}

func (s *stateStore) Get(kind string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.ResourceVersions[kind]
}

func (s *stateStore) Set(kind, rv string) error {
	if s == nil || strings.TrimSpace(kind) == "" || strings.TrimSpace(rv) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rv = strings.TrimSpace(rv)
	if s.data.ResourceVersions[kind] == rv {
		return nil
	}
	s.data.ResourceVersions[kind] = rv
	return s.saveLocked()
}

func (s *stateStore) Clear(kind string) error {
	if s == nil || strings.TrimSpace(kind) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.ResourceVersions, kind)
	return s.saveLocked()
}

func (s *stateStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.data); err != nil {
		return err
	}
	return os.WriteFile(s.path, body.Bytes(), 0o600)
}

func readQueuedBatches(path string) ([]collector.AgentBatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []collector.AgentBatch{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var batch collector.AgentBatch
		if err := json.Unmarshal([]byte(line), &batch); err != nil {
			return nil, err
		}
		out = append(out, batch)
	}
	return out, scanner.Err()
}
