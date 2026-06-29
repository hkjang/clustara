package proxy

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

type k8sPodView struct {
	store.K8sInventoryItem
	Phase          string                   `json:"phase"`
	Ready          string                   `json:"ready"`
	ReadyCount     int                      `json:"ready_count"`
	ContainerCount int                      `json:"container_count"`
	RestartCount   int                      `json:"restart_count"`
	NodeName       string                   `json:"node_name"`
	PodIP          string                   `json:"pod_ip"`
	QoSClass       string                   `json:"qos_class"`
	OwnerKind      string                   `json:"owner_kind"`
	OwnerName      string                   `json:"owner_name"`
	Images         []string                 `json:"images"`
	Age            string                   `json:"age"`
	WarningEvents  int                      `json:"warning_events"`
	Containers     []k8sContainerStatusView `json:"containers,omitempty"`
}

type k8sContainerStatusView struct {
	Name         string `json:"name"`
	Image        string `json:"image"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restart_count"`
	State        string `json:"state"`
	Reason       string `json:"reason"`
	ExitCode     int    `json:"exit_code"`
	LastState    string `json:"last_state"`
	LastReason   string `json:"last_reason"`
}

type k8sPodLogLine struct {
	Number int    `json:"number"`
	Level  string `json:"level"`
	Text   string `json:"text"`
}

type k8sPodLogResponse struct {
	ClusterID    string              `json:"cluster_id"`
	Namespace    string              `json:"namespace"`
	Pod          string              `json:"pod"`
	Container    string              `json:"container"`
	Previous     bool                `json:"previous"`
	TailLines    int                 `json:"tail_lines"`
	SinceSeconds int                 `json:"since_seconds"`
	SinceTime    string              `json:"since_time"`
	Query        string              `json:"query"`
	ErrorOnly    bool                `json:"error_only"`
	Masked       bool                `json:"masked"`
	Summary      analyzer.LogSummary `json:"summary"`
	Lines        []k8sPodLogLine     `json:"lines"`
	Text         string              `json:"text"`
}

type k8sPodLogAnalysisPattern struct {
	Key       string          `json:"key"`
	Category  string          `json:"category"`
	Severity  string          `json:"severity"`
	Message   string          `json:"message"`
	Count     int             `json:"count"`
	FirstLine int             `json:"first_line"`
	LastLine  int             `json:"last_line"`
	Samples   []k8sPodLogLine `json:"samples"`
}

type k8sPodLogInsight struct {
	Condition string   `json:"condition"`
	Severity  string   `json:"severity"`
	Cause     string   `json:"cause"`
	Evidence  []string `json:"evidence"`
	Actions   []string `json:"actions"`
}

type k8sPodLogAnalysisResponse struct {
	ClusterID     string                     `json:"cluster_id"`
	Namespace     string                     `json:"namespace"`
	Pod           string                     `json:"pod"`
	Container     string                     `json:"container"`
	TailLines     int                        `json:"tail_lines"`
	SinceSeconds  int                        `json:"since_seconds"`
	SinceTime     string                     `json:"since_time"`
	Masked        bool                       `json:"masked"`
	Current       analyzer.LogSummary        `json:"current"`
	Previous      analyzer.LogSummary        `json:"previous"`
	PreviousError string                     `json:"previous_error,omitempty"`
	Patterns      []k8sPodLogAnalysisPattern `json:"patterns"`
	Insights      []k8sPodLogInsight         `json:"insights"`
}

type k8sPodGoldenDiffChange struct {
	Field    string `json:"field"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Golden   string `json:"golden"`
}

type k8sPodReplayEntry struct {
	At        string `json:"at"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Ref       string `json:"ref,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

type podLogReader interface {
	PodLogs(ctx context.Context, namespace, pod string, opts kube.PodLogOptions) (string, error)
}

type podLogStreamer interface {
	PodLogsStream(ctx context.Context, namespace, pod string, opts kube.PodLogOptions) (io.ReadCloser, error)
}

func (s *Server) handleK8sPods(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/pods"), "/")
	if trimmed == "" {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sPodList(w, r)
		return
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		writeOpenAIError(w, http.StatusBadRequest, "namespace and pod name are required", "invalid_request_error", "missing_pod")
		return
	}
	namespace, _ := url.PathUnescape(parts[0])
	pod, _ := url.PathUnescape(parts[1])
	if len(parts) == 2 {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sPodDetail(w, r, namespace, pod)
		return
	}
	if parts[2] == "evidence-bundle" {
		if r.Method != http.MethodPost {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sPodEvidenceBundle(w, r, namespace, pod)
		return
	}
	if parts[2] == "golden-diff" {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sPodGoldenDiff(w, r, namespace, pod)
		return
	}
	if parts[2] == "health-replay" {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sPodHealthReplay(w, r, namespace, pod)
		return
	}
	if parts[2] == "exec" && len(parts) > 3 && parts[3] == "sessions" {
		s.handleK8sPodExecSessions(w, r, namespace, pod)
		return
	}
	if parts[2] == "logs" {
		if len(parts) > 3 && parts[3] == "stream" {
			if r.Method != http.MethodGet {
				writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
				return
			}
			s.handleK8sPodLogStream(w, r, namespace, pod)
			return
		}
		if len(parts) > 3 && parts[3] == "analyze" {
			if r.Method != http.MethodPost {
				writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
				return
			}
			s.handleK8sPodLogAnalyze(w, r, namespace, pod)
			return
		}
		if len(parts) > 3 && parts[3] == "export" {
			if r.Method != http.MethodPost {
				writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
				return
			}
			s.handleK8sPodLogExport(w, r, namespace, pod)
			return
		}
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sPodLogs(w, r, namespace, pod)
		return
	}
	writeOpenAIError(w, http.StatusNotFound, "unknown pod command: "+parts[2], "invalid_request_error", "unknown_pod_command")
}

func (s *Server) handleK8sPodList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clusterID := strings.TrimSpace(q.Get("cluster_id"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Pod", Limit: recentLimit(r)})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pods_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	views := make([]k8sPodView, 0, len(items))
	for _, item := range items {
		view := podView(item, events, false)
		if !podMatchesFilters(view, q) {
			continue
		}
		views = append(views, view)
	}
	critical, warning, restarts := 0, 0, 0
	for _, p := range views {
		if p.RiskLevel == "critical" || p.RiskLevel == "high" || podStatusRisk(p.Status) == "high" {
			critical++
		}
		if p.WarningEvents > 0 {
			warning++
		}
		restarts += p.RestartCount
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pods": views,
		"summary": map[string]int{
			"total": len(views), "risky": critical, "with_warning_events": warning, "restarts": restarts,
		},
	})
}

func (s *Server) handleK8sPodDetail(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	relatedEvents := filterPodEvents(events, namespace, pod)
	metrics, _ := s.db.ListK8sMetricSamples(r.Context(), clusterID, 1000)
	relatedMetrics := []store.K8sMetricSample{}
	for _, m := range metrics {
		if strings.EqualFold(m.ResourceKind, "Pod") && m.Namespace == namespace && m.ResourceName == pod {
			relatedMetrics = append(relatedMetrics, m)
			if len(relatedMetrics) >= 10 {
				break
			}
		}
	}
	logQueries, _ := s.db.ListK8sPodLogQueries(r.Context(), clusterID, 100)
	relatedLogQueries := []store.K8sPodLogQuery{}
	for _, q := range logQueries {
		if q.Namespace == namespace && q.Pod == pod {
			relatedLogQueries = append(relatedLogQueries, q)
			if len(relatedLogQueries) >= 10 {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pod":         podView(item, events, true),
		"events":      relatedEvents,
		"metrics":     relatedMetrics,
		"log_queries": relatedLogQueries,
		"manifest":    assembleManifest(item),
	})
}

func (s *Server) handleK8sPodLogs(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	resp, err := s.readPodLogs(r.Context(), r, namespace, pod)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_pod_logs_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleK8sPodLogStream(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	if err := s.streamPodLogs(w, r, namespace, pod); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_pod_logs_stream_failed")
	}
}

func (s *Server) handleK8sPodLogExport(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	resp, err := s.readPodLogs(r.Context(), r, namespace, pod)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_pod_logs_export_failed")
		return
	}
	name := sanitizeDownloadName(resp.ClusterID + "_" + namespace + "_" + pod + "_logs.txt")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(resp.Text))
}

func (s *Server) handleK8sPodLogAnalyze(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	resp, err := s.analyzePodLogs(r.Context(), r, namespace, pod)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_pod_logs_analyze_failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleK8sPodEvidenceBundle(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(nil, r, namespace, pod)
	if !ok {
		writeOpenAIError(w, http.StatusBadRequest, "pod not found or cluster_id is missing", "invalid_request_error", "pod_not_found")
		return
	}
	buf, err := s.buildPodEvidenceBundle(r, clusterID, item)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_pod_evidence_bundle_failed")
		return
	}
	s.auditAdmin(r, "k8s.pod.evidence_bundle", "", auditJSON(map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod,
	}))
	name := sanitizeDownloadName(clusterID + "_" + namespace + "_" + pod + "_evidence.zip")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleK8sPodGoldenDiff(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, target, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	golden, autoSelected, err := s.selectGoldenPod(r.Context(), clusterID, target, strings.TrimSpace(r.URL.Query().Get("golden")), events)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, err.Error(), "invalid_request_error", "golden_pod_not_found")
		return
	}
	targetView := podView(target, events, true)
	goldenView := podView(golden, events, true)
	changes := comparePodsForGoldenDiff(targetView, goldenView)
	summary := map[string]int{"total": len(changes), "high": 0, "medium": 0, "low": 0}
	for _, c := range changes {
		summary[c.Severity]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id":     clusterID,
		"namespace":      namespace,
		"target":         targetView,
		"golden":         goldenView,
		"owner":          map[string]string{"kind": targetView.OwnerKind, "name": targetView.OwnerName},
		"auto_selected":  autoSelected,
		"masked":         true,
		"summary":        summary,
		"changes":        changes,
		"selection_note": goldenSelectionNote(targetView, goldenView, autoSelected),
	})
}

func (s *Server) handleK8sPodHealthReplay(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	clusterID, item, ok := s.resolvePodInventory(w, r, namespace, pod)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := boundedInt(q.Get("limit"), 200, 10, 1000)
	windowMinutes := boundedInt(q.Get("window_minutes"), 60, 5, 7*24*60)
	entries, err := s.buildPodHealthReplay(r.Context(), clusterID, item, limit)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_health_replay_failed")
		return
	}
	filtered := entries
	if strings.TrimSpace(q.Get("center_at")) != "" || strings.TrimSpace(q.Get("window_minutes")) != "" {
		center := parseReplayTime(strings.TrimSpace(q.Get("center_at")))
		if center.IsZero() {
			center = latestReplayTime(entries)
		}
		filtered = filterReplayWindow(entries, center, time.Duration(windowMinutes)*time.Minute)
	}
	if len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id":     clusterID,
		"namespace":      namespace,
		"pod":            pod,
		"window_minutes": windowMinutes,
		"entries":        filtered,
		"summary":        podReplaySummary(filtered),
	})
}

func (s *Server) readPodLogs(ctx context.Context, r *http.Request, namespace, pod string) (k8sPodLogResponse, error) {
	clusterID, item, ok := s.resolvePodInventory(nil, r, namespace, pod)
	if !ok {
		return k8sPodLogResponse{}, fmt.Errorf("pod not found or cluster_id is missing")
	}
	cluster, err := s.db.GetK8sCluster(ctx, clusterID)
	if err != nil {
		return k8sPodLogResponse{}, err
	}
	client, err := s.k8sClientForCluster(ctx, cluster)
	if err != nil {
		return k8sPodLogResponse{}, err
	}
	reader, ok := client.(podLogReader)
	if !ok {
		return k8sPodLogResponse{}, fmt.Errorf("cluster client does not support Pod logs")
	}
	q := r.URL.Query()
	tailLines := boundedInt(q.Get("tail_lines"), 200, 1, 2000)
	sinceSeconds := parseSinceSeconds(q.Get("since"))
	opts := kube.PodLogOptions{
		Container:    strings.TrimSpace(q.Get("container")),
		Previous:     parseBool(q.Get("previous")),
		TailLines:    tailLines,
		SinceSeconds: sinceSeconds,
		SinceTime:    strings.TrimSpace(q.Get("since_time")),
		Timestamps:   parseBool(q.Get("timestamps")),
		LimitBytes:   boundedInt(q.Get("limit_bytes"), 2*1024*1024, 4096, 10*1024*1024),
	}
	raw, err := reader.PodLogs(ctx, namespace, pod, opts)
	if err != nil {
		return k8sPodLogResponse{}, err
	}
	processed := processPodLogs(raw, strings.TrimSpace(q.Get("q")), parseBool(q.Get("error_only")))
	if opts.Container == "" {
		opts.Container = defaultContainerName(item)
	}
	if err := s.db.InsertK8sPodLogQuery(ctx, store.K8sPodLogQuery{
		ID:           newID("k8splog"),
		ClusterID:    clusterID,
		Namespace:    namespace,
		Pod:          pod,
		Container:    opts.Container,
		Previous:     opts.Previous,
		TailLines:    opts.TailLines,
		SinceSeconds: opts.SinceSeconds,
		SinceTime:    opts.SinceTime,
		Query:        strings.TrimSpace(q.Get("q")),
		RequestedBy:  adminID(r),
		Masked:       true,
		LineCount:    processed.Summary.Lines,
		ErrorCount:   processed.Summary.Error,
		WarnCount:    processed.Summary.Warn,
	}); err != nil {
		return k8sPodLogResponse{}, err
	}
	s.auditAdmin(r, "k8s.pod.logs", "", auditJSON(map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod, "container": opts.Container,
		"previous": opts.Previous, "tail_lines": opts.TailLines, "query": strings.TrimSpace(q.Get("q")),
	}))
	processed.ClusterID = clusterID
	processed.Namespace = namespace
	processed.Pod = pod
	processed.Container = opts.Container
	processed.Previous = opts.Previous
	processed.TailLines = opts.TailLines
	processed.SinceSeconds = opts.SinceSeconds
	processed.SinceTime = opts.SinceTime
	processed.Query = strings.TrimSpace(q.Get("q"))
	processed.ErrorOnly = parseBool(q.Get("error_only"))
	processed.Masked = true
	return processed, nil
}

func (s *Server) analyzePodLogs(ctx context.Context, r *http.Request, namespace, pod string) (k8sPodLogAnalysisResponse, error) {
	clusterID, item, ok := s.resolvePodInventory(nil, r, namespace, pod)
	if !ok {
		return k8sPodLogAnalysisResponse{}, fmt.Errorf("pod not found or cluster_id is missing")
	}
	cluster, err := s.db.GetK8sCluster(ctx, clusterID)
	if err != nil {
		return k8sPodLogAnalysisResponse{}, err
	}
	client, err := s.k8sClientForCluster(ctx, cluster)
	if err != nil {
		return k8sPodLogAnalysisResponse{}, err
	}
	reader, ok := client.(podLogReader)
	if !ok {
		return k8sPodLogAnalysisResponse{}, fmt.Errorf("cluster client does not support Pod logs")
	}
	q := r.URL.Query()
	opts := kube.PodLogOptions{
		Container:    strings.TrimSpace(q.Get("container")),
		TailLines:    boundedInt(q.Get("tail_lines"), 500, 20, 5000),
		SinceSeconds: parseSinceSeconds(q.Get("since")),
		SinceTime:    strings.TrimSpace(q.Get("since_time")),
		Timestamps:   parseBool(q.Get("timestamps")),
		LimitBytes:   boundedInt(q.Get("limit_bytes"), 4*1024*1024, 4096, 20*1024*1024),
	}
	if opts.Container == "" {
		opts.Container = defaultContainerName(item)
	}
	currentRaw, err := reader.PodLogs(ctx, namespace, pod, opts)
	if err != nil {
		return k8sPodLogAnalysisResponse{}, err
	}
	current := processPodLogs(currentRaw, "", false)
	if err := s.insertPodLogAnalysisAudit(ctx, r, clusterID, namespace, pod, opts, false, current.Summary); err != nil {
		return k8sPodLogAnalysisResponse{}, err
	}

	previous := k8sPodLogResponse{}
	previousErr := ""
	includePrevious := true
	if raw := strings.TrimSpace(q.Get("include_previous")); raw != "" {
		includePrevious = parseBool(raw)
	}
	if includePrevious {
		prevOpts := opts
		prevOpts.Previous = true
		if previousRaw, err := reader.PodLogs(ctx, namespace, pod, prevOpts); err == nil {
			previous = processPodLogs(previousRaw, "", false)
			if err := s.insertPodLogAnalysisAudit(ctx, r, clusterID, namespace, pod, prevOpts, true, previous.Summary); err != nil {
				return k8sPodLogAnalysisResponse{}, err
			}
		} else {
			previousErr = err.Error()
		}
	}

	patterns := analyzeLogPatterns(current.Lines, previous.Lines)
	insights := logInsightsFromPatterns(patterns, podView(item, nil, true))
	s.auditAdmin(r, "k8s.pod.logs.analyze", "", auditJSON(map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod, "container": opts.Container,
		"tail_lines": opts.TailLines, "patterns": len(patterns), "insights": len(insights), "include_previous": includePrevious,
	}))
	return k8sPodLogAnalysisResponse{
		ClusterID: clusterID, Namespace: namespace, Pod: pod, Container: opts.Container,
		TailLines: opts.TailLines, SinceSeconds: opts.SinceSeconds, SinceTime: opts.SinceTime,
		Masked: true, Current: current.Summary, Previous: previous.Summary, PreviousError: previousErr,
		Patterns: patterns, Insights: insights,
	}, nil
}

func (s *Server) insertPodLogAnalysisAudit(ctx context.Context, r *http.Request, clusterID, namespace, pod string, opts kube.PodLogOptions, previous bool, summary analyzer.LogSummary) error {
	return s.db.InsertK8sPodLogQuery(ctx, store.K8sPodLogQuery{
		ID:           newID("k8splog"),
		ClusterID:    clusterID,
		Namespace:    namespace,
		Pod:          pod,
		Container:    opts.Container,
		Previous:     previous,
		TailLines:    opts.TailLines,
		SinceSeconds: opts.SinceSeconds,
		SinceTime:    opts.SinceTime,
		Query:        "log_analyze",
		RequestedBy:  adminID(r),
		Masked:       true,
		LineCount:    summary.Lines,
		ErrorCount:   summary.Error,
		WarnCount:    summary.Warn,
	})
}

func (s *Server) streamPodLogs(w http.ResponseWriter, r *http.Request, namespace, pod string) error {
	q := r.URL.Query()
	if parseBool(q.Get("previous")) {
		return fmt.Errorf("previous logs cannot be followed; use the regular log viewer")
	}
	clusterID, item, ok := s.resolvePodInventory(nil, r, namespace, pod)
	if !ok {
		return fmt.Errorf("pod not found or cluster_id is missing")
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), clusterID)
	if err != nil {
		return err
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		return err
	}
	streamer, ok := client.(podLogStreamer)
	if !ok {
		return fmt.Errorf("cluster client does not support Pod log streaming")
	}
	opts := kube.PodLogOptions{
		Container:    strings.TrimSpace(q.Get("container")),
		Follow:       true,
		TailLines:    boundedInt(q.Get("tail_lines"), 100, 1, 1000),
		SinceSeconds: parseSinceSeconds(q.Get("since")),
		SinceTime:    strings.TrimSpace(q.Get("since_time")),
		Timestamps:   parseBool(q.Get("timestamps")),
		LimitBytes:   boundedInt(q.Get("limit_bytes"), 2*1024*1024, 4096, 10*1024*1024),
	}
	if opts.Container == "" {
		opts.Container = defaultContainerName(item)
	}
	if err := s.db.InsertK8sPodLogQuery(r.Context(), store.K8sPodLogQuery{
		ID:           newID("k8splog"),
		ClusterID:    clusterID,
		Namespace:    namespace,
		Pod:          pod,
		Container:    opts.Container,
		Stream:       true,
		TailLines:    opts.TailLines,
		SinceSeconds: opts.SinceSeconds,
		SinceTime:    opts.SinceTime,
		Query:        strings.TrimSpace(q.Get("q")),
		RequestedBy:  adminID(r),
		Masked:       true,
	}); err != nil {
		return err
	}
	s.auditAdmin(r, "k8s.pod.logs.stream", "", auditJSON(map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod, "container": opts.Container,
		"tail_lines": opts.TailLines, "query": strings.TrimSpace(q.Get("q")),
	}))
	body, err := streamer.PodLogsStream(r.Context(), namespace, pod, opts)
	if err != nil {
		return err
	}
	defer body.Close()
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming is not supported by this response writer")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	writeSSE(w, "meta", map[string]any{
		"cluster_id": clusterID, "namespace": namespace, "pod": pod, "container": opts.Container,
		"tail_lines": opts.TailLines, "masked": true,
	})
	flusher.Flush()
	needle := strings.ToLower(strings.TrimSpace(q.Get("q")))
	errorOnly := parseBool(q.Get("error_only"))
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := analyzer.MaskSensitive(scanner.Text())
		if needle != "" && !strings.Contains(strings.ToLower(line), needle) {
			continue
		}
		level := string(analyzer.ClassifyLogLine(line))
		if errorOnly && level == string(analyzer.LogInfo) {
			continue
		}
		writeSSE(w, "line", k8sPodLogLine{Number: lineNo, Level: level, Text: line})
		flusher.Flush()
	}
	if err := scanner.Err(); err != nil && r.Context().Err() == nil {
		writeSSE(w, "error", map[string]string{"message": err.Error()})
		flusher.Flush()
		return nil
	}
	writeSSE(w, "done", map[string]any{"lines_seen": lineNo})
	flusher.Flush()
	return nil
}

func writeSSE(w http.ResponseWriter, event string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte(`{"error":"marshal failed"}`)
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}

func (s *Server) buildPodEvidenceBundle(r *http.Request, clusterID string, item store.K8sInventoryItem) (*bytes.Buffer, error) {
	ctx := r.Context()
	namespace, pod := item.Namespace, item.Name
	events, _ := s.db.ListK8sEvents(ctx, clusterID, 1000)
	relatedEvents := filterPodEvents(events, namespace, pod)
	metrics, _ := s.db.ListK8sMetricSamples(ctx, clusterID, 1000)
	relatedMetrics := []store.K8sMetricSample{}
	for _, m := range metrics {
		if strings.EqualFold(m.ResourceKind, "Pod") && m.Namespace == namespace && m.ResourceName == pod {
			relatedMetrics = append(relatedMetrics, m)
			if len(relatedMetrics) >= 30 {
				break
			}
		}
	}
	logQueries, _ := s.db.ListK8sPodLogQueries(ctx, clusterID, 100)
	relatedLogQueries := []store.K8sPodLogQuery{}
	for _, q := range logQueries {
		if q.Namespace == namespace && q.Pod == pod {
			relatedLogQueries = append(relatedLogQueries, q)
			if len(relatedLogQueries) >= 30 {
				break
			}
		}
	}
	revisions, _ := s.db.ListK8sRevisions(ctx, store.K8sRevisionFilter{ClusterID: clusterID, Kind: "Pod", Namespace: namespace, Name: pod, Limit: 20})
	allItems, _ := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	allRevisions, _ := s.db.ListK8sRevisions(ctx, store.K8sRevisionFilter{ClusterID: clusterID, Limit: 500})
	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(allItems, events), allRevisions, time.Now().UTC(), 24*time.Hour)
	relatedRCA := filterPodRCA(rca, namespace, pod)
	view := podView(item, events, true)
	manifest := assembleManifest(item)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	generatedAt := time.Now().UTC().Format(time.RFC3339Nano)
	summary := podEvidenceSummaryMarkdown(generatedAt, clusterID, view, relatedEvents, relatedMetrics, relatedRCA)
	if err := zipWriteText(zw, "summary.md", summary); err != nil {
		return nil, err
	}
	if err := zipWriteJSON(zw, "bundle.json", map[string]any{
		"generated_at": generatedAt,
		"cluster_id":   clusterID,
		"namespace":    namespace,
		"pod":          pod,
		"masked":       true,
		"files": []string{
			"summary.md", "pod.json", "manifest.json", "events.json", "metrics.json", "revisions.json", "rca.json", "log-audit.json", "logs/current.log", "logs/previous.log",
		},
	}); err != nil {
		return nil, err
	}
	if err := zipWriteJSON(zw, "pod.json", view); err != nil {
		return nil, err
	}
	if err := zipWriteJSON(zw, "manifest.json", manifest); err != nil {
		return nil, err
	}
	if ownerKind, ownerName := view.OwnerKind, view.OwnerName; ownerKind != "" && ownerName != "" {
		if owner, err := s.db.GetK8sInventoryItem(ctx, clusterID, ownerKind, namespace, ownerName); err == nil {
			_ = zipWriteJSON(zw, "owner-manifest.json", assembleManifest(owner))
		}
	}
	if err := zipWriteJSON(zw, "events.json", relatedEvents); err != nil {
		return nil, err
	}
	if err := zipWriteJSON(zw, "metrics.json", relatedMetrics); err != nil {
		return nil, err
	}
	if err := zipWriteJSON(zw, "revisions.json", revisions); err != nil {
		return nil, err
	}
	if err := zipWriteJSON(zw, "rca.json", relatedRCA); err != nil {
		return nil, err
	}
	if err := zipWriteJSON(zw, "log-audit.json", relatedLogQueries); err != nil {
		return nil, err
	}
	if err := s.addPodEvidenceLogs(ctx, r, zw, clusterID, item); err != nil {
		_ = zipWriteText(zw, "logs/client.error.txt", err.Error())
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

func (s *Server) addPodEvidenceLogs(ctx context.Context, r *http.Request, zw *zip.Writer, clusterID string, item store.K8sInventoryItem) error {
	cluster, err := s.db.GetK8sCluster(ctx, clusterID)
	if err != nil {
		return err
	}
	client, err := s.k8sClientForCluster(ctx, cluster)
	if err != nil {
		return err
	}
	reader, ok := client.(podLogReader)
	if !ok {
		return fmt.Errorf("cluster client does not support Pod logs")
	}
	q := r.URL.Query()
	container := strings.TrimSpace(q.Get("container"))
	if container == "" {
		container = defaultContainerName(item)
	}
	tailLines := boundedInt(q.Get("tail_lines"), 500, 1, 5000)
	opts := kube.PodLogOptions{
		Container:    container,
		TailLines:    tailLines,
		SinceSeconds: parseSinceSeconds(q.Get("since")),
		SinceTime:    strings.TrimSpace(q.Get("since_time")),
		Timestamps:   parseBool(q.Get("timestamps")),
		LimitBytes:   boundedInt(q.Get("limit_bytes"), 5*1024*1024, 4096, 10*1024*1024),
	}
	for _, previous := range []bool{false, true} {
		mode := "current"
		if previous {
			mode = "previous"
		}
		opts.Previous = previous
		raw, err := reader.PodLogs(ctx, item.Namespace, item.Name, opts)
		if err != nil {
			if zerr := zipWriteText(zw, "logs/"+mode+".error.txt", err.Error()); zerr != nil {
				return zerr
			}
			continue
		}
		processed := processPodLogs(raw, "", false)
		if err := zipWriteText(zw, "logs/"+mode+".log", processed.Text); err != nil {
			return err
		}
		if err := zipWriteJSON(zw, "logs/"+mode+".summary.json", processed.Summary); err != nil {
			return err
		}
		_ = s.db.InsertK8sPodLogQuery(ctx, store.K8sPodLogQuery{
			ID:           newID("k8splog"),
			ClusterID:    clusterID,
			Namespace:    item.Namespace,
			Pod:          item.Name,
			Container:    container,
			Previous:     previous,
			TailLines:    opts.TailLines,
			SinceSeconds: opts.SinceSeconds,
			SinceTime:    opts.SinceTime,
			Query:        "evidence_bundle",
			RequestedBy:  adminID(r),
			Masked:       true,
			LineCount:    processed.Summary.Lines,
			ErrorCount:   processed.Summary.Error,
			WarnCount:    processed.Summary.Warn,
		})
	}
	return nil
}

func zipWriteText(zw *zip.Writer, name, text string) error {
	f, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(text))
	return err
}

func zipWriteJSON(zw *zip.Writer, name string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return zipWriteText(zw, name, string(b)+"\n")
}

func podEvidenceSummaryMarkdown(generatedAt, clusterID string, pod k8sPodView, events []store.K8sEvent, metrics []store.K8sMetricSample, rca []analyzer.RCAFinding) string {
	var b strings.Builder
	b.WriteString("# Clustara Pod Evidence Bundle\n\n")
	b.WriteString("- Generated: " + generatedAt + "\n")
	b.WriteString("- Cluster: " + clusterID + "\n")
	b.WriteString("- Pod: " + pod.Namespace + "/" + pod.Name + "\n")
	b.WriteString("- Phase: " + firstNonEmpty(pod.Phase, pod.Status, "-") + "\n")
	b.WriteString("- Ready: " + firstNonEmpty(pod.Ready, "-") + "\n")
	b.WriteString("- Restarts: " + strconv.Itoa(pod.RestartCount) + "\n")
	b.WriteString("- Node: " + firstNonEmpty(pod.NodeName, "-") + "\n")
	owner := "-"
	if pod.OwnerKind != "" || pod.OwnerName != "" {
		owner = firstNonEmpty(pod.OwnerKind, "-") + "/" + firstNonEmpty(pod.OwnerName, "-")
	}
	b.WriteString("- Owner: " + owner + "\n")
	b.WriteString("- Masked: true\n\n")
	b.WriteString("## Counts\n\n")
	b.WriteString("- Events: " + strconv.Itoa(len(events)) + "\n")
	b.WriteString("- Metrics: " + strconv.Itoa(len(metrics)) + "\n")
	b.WriteString("- RCA candidates: " + strconv.Itoa(len(rca)) + "\n\n")
	b.WriteString("## Files\n\n")
	for _, f := range []string{"pod.json", "manifest.json", "events.json", "metrics.json", "revisions.json", "rca.json", "log-audit.json", "logs/current.log", "logs/previous.log"} {
		b.WriteString("- " + f + "\n")
	}
	return b.String()
}

func filterPodRCA(findings []analyzer.RCAFinding, namespace, pod string) []analyzer.RCAFinding {
	out := []analyzer.RCAFinding{}
	for _, f := range findings {
		if f.Namespace == namespace && strings.EqualFold(f.ResourceKind, "Pod") && f.ResourceName == pod {
			out = append(out, f)
			continue
		}
		for _, ev := range f.Evidence {
			if strings.Contains(ev, pod) && (f.Namespace == "" || f.Namespace == namespace) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func (s *Server) resolvePodInventory(w http.ResponseWriter, r *http.Request, namespace, pod string) (string, store.K8sInventoryItem, bool) {
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID != "" {
		item, err := s.db.GetK8sInventoryItem(r.Context(), clusterID, "Pod", namespace, pod)
		if err != nil {
			if w != nil {
				writeOpenAIError(w, http.StatusNotFound, "pod not found", "invalid_request_error", "pod_not_found")
			}
			return "", store.K8sInventoryItem{}, false
		}
		return clusterID, item, true
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{Kind: "Pod", Namespace: namespace, Limit: 1000})
	if err != nil {
		if w != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_pod_lookup_failed")
		}
		return "", store.K8sInventoryItem{}, false
	}
	var matched []store.K8sInventoryItem
	for _, item := range items {
		if item.Name == pod {
			matched = append(matched, item)
		}
	}
	if len(matched) != 1 {
		if w != nil {
			writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required when pod identity is ambiguous", "invalid_request_error", "cluster_id_required")
		}
		return "", store.K8sInventoryItem{}, false
	}
	return matched[0].ClusterID, matched[0], true
}

func (s *Server) buildPodHealthReplay(ctx context.Context, clusterID string, item store.K8sInventoryItem, limit int) ([]k8sPodReplayEntry, error) {
	namespace, pod := item.Namespace, item.Name
	events, err := s.db.ListK8sEvents(ctx, clusterID, 1000)
	if err != nil {
		return nil, err
	}
	entries := []k8sPodReplayEntry{}
	p := podView(item, events, true)
	entries = append(entries, k8sPodReplayEntry{
		At:        firstNonEmpty(item.ObservedAt, item.UpdatedAt, strAny(item.StatusObject["startTime"])),
		Category:  "status",
		Severity:  replaySeverityFromRisk(firstNonEmpty(p.RiskLevel, podStatusRisk(firstNonEmpty(p.Status, p.Phase)))),
		Title:     "Pod 상태 스냅샷",
		Detail:    fmt.Sprintf("phase %s · ready %s · restarts %d · node %s", firstNonEmpty(p.Phase, p.Status, "-"), firstNonEmpty(p.Ready, "-"), p.RestartCount, firstNonEmpty(p.NodeName, "-")),
		Namespace: namespace,
		Name:      pod,
	})
	for _, c := range p.Containers {
		if c.RestartCount == 0 && c.Ready && strings.EqualFold(c.State, "running") {
			continue
		}
		severity := "info"
		if c.RestartCount > 0 || !c.Ready || c.State == "waiting" || c.State == "terminated" {
			severity = "warning"
		}
		if strings.Contains(strings.ToLower(c.Reason+" "+c.LastReason), "crashloop") {
			severity = "critical"
		}
		entries = append(entries, k8sPodReplayEntry{
			At:        firstNonEmpty(item.ObservedAt, item.UpdatedAt, strAny(item.StatusObject["startTime"])),
			Category:  "container",
			Severity:  severity,
			Title:     "컨테이너 상태 · " + firstNonEmpty(c.Name, "-"),
			Detail:    fmt.Sprintf("ready %t · restarts %d · state %s · reason %s", c.Ready, c.RestartCount, firstNonEmpty(c.State, "-"), firstNonEmpty(c.Reason, c.LastReason, "-")),
			Namespace: namespace,
			Name:      pod,
		})
	}
	for _, e := range filterPodEvents(events, namespace, pod) {
		sev := "info"
		if strings.EqualFold(e.Type, "Warning") {
			sev = "warning"
		}
		entries = append(entries, k8sPodReplayEntry{
			At:        firstNonEmpty(e.LastSeen, e.FirstSeen, e.CreatedAt),
			Category:  "event",
			Severity:  sev,
			Title:     firstNonEmpty(e.Reason, e.Type, "Kubernetes event"),
			Detail:    e.Message,
			Ref:       e.ID,
			Namespace: e.Namespace,
			Name:      e.InvolvedName,
		})
	}
	metrics, err := s.db.ListK8sMetricSamples(ctx, clusterID, 1000)
	if err != nil {
		return nil, err
	}
	for _, m := range metrics {
		if !strings.EqualFold(m.ResourceKind, "Pod") || m.Namespace != namespace || m.ResourceName != pod {
			continue
		}
		entries = append(entries, k8sPodReplayEntry{
			At:        m.ObservedAt,
			Category:  "metric",
			Severity:  "info",
			Title:     "리소스 사용량",
			Detail:    fmt.Sprintf("cpu %.0fm · memory %.0fMi", m.CPUMillicores, m.MemoryBytes/1024/1024),
			Ref:       m.ID,
			Namespace: m.Namespace,
			Name:      m.ResourceName,
		})
	}
	revisions, err := s.db.ListK8sRevisions(ctx, store.K8sRevisionFilter{ClusterID: clusterID, Kind: "Pod", Namespace: namespace, Name: pod, Limit: limit})
	if err != nil {
		return nil, err
	}
	for _, rev := range revisions {
		detail := "spec 변경"
		if rev.ImageSet != "" {
			detail = "image: " + rev.ImageSet
		}
		if rev.Replica > 0 {
			detail += " · replicas: " + strconv.Itoa(rev.Replica)
		}
		entries = append(entries, k8sPodReplayEntry{
			At:        rev.ObservedAt,
			Category:  "revision",
			Severity:  "info",
			Title:     revisionTitle(rev.ChangeKind),
			Detail:    detail,
			Ref:       rev.ID,
			Namespace: rev.Namespace,
			Name:      rev.Name,
		})
	}
	logQueries, err := s.db.ListK8sPodLogQueries(ctx, clusterID, limit)
	if err != nil {
		return nil, err
	}
	for _, row := range logQueries {
		if row.Namespace != namespace || row.Pod != pod {
			continue
		}
		mode := "current"
		if row.Stream {
			mode = "stream"
		} else if row.Previous {
			mode = "previous"
		}
		sev := "info"
		if row.ErrorCount > 0 {
			sev = "warning"
		}
		entries = append(entries, k8sPodReplayEntry{
			At:        row.CreatedAt,
			Category:  "log",
			Severity:  sev,
			Title:     "로그 조회 · " + mode,
			Detail:    fmt.Sprintf("container %s · tail %d · lines %d · errors %d · query %s", firstNonEmpty(row.Container, "-"), row.TailLines, row.LineCount, row.ErrorCount, firstNonEmpty(row.Query, "-")),
			Ref:       row.ID,
			Namespace: row.Namespace,
			Name:      row.Pod,
		})
	}
	allItems, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Limit: 2000})
	if err != nil {
		return nil, err
	}
	allRevisions, _ := s.db.ListK8sRevisions(ctx, store.K8sRevisionFilter{ClusterID: clusterID, Limit: 500})
	for _, finding := range filterPodRCA(analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(allItems, events), allRevisions, time.Now().UTC(), 24*time.Hour), namespace, pod) {
		entries = append(entries, k8sPodReplayEntry{
			At:        firstNonEmpty(item.ObservedAt, item.UpdatedAt),
			Category:  "rca",
			Severity:  replaySeverityFromRisk(finding.Severity),
			Title:     firstNonEmpty(finding.Condition, "RCA 후보"),
			Detail:    finding.Cause,
			Namespace: finding.Namespace,
			Name:      finding.ResourceName,
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return replayEntryTime(entries[i]).Before(replayEntryTime(entries[j]))
	})
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries, nil
}

func replaySeverityFromRisk(value string) string {
	switch strings.ToLower(value) {
	case "critical", "high":
		return "critical"
	case "medium", "warning", "warn":
		return "warning"
	default:
		return "info"
	}
}

func replayEntryTime(e k8sPodReplayEntry) time.Time {
	return parseReplayTime(e.At)
}

func parseReplayTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

func latestReplayTime(entries []k8sPodReplayEntry) time.Time {
	var latest time.Time
	for _, e := range entries {
		if t := replayEntryTime(e); !t.IsZero() && t.After(latest) {
			latest = t
		}
	}
	return latest
}

func filterReplayWindow(entries []k8sPodReplayEntry, center time.Time, window time.Duration) []k8sPodReplayEntry {
	if center.IsZero() {
		return entries
	}
	start := center.Add(-window)
	end := center.Add(window)
	out := []k8sPodReplayEntry{}
	for _, e := range entries {
		t := replayEntryTime(e)
		if t.IsZero() || (!t.Before(start) && !t.After(end)) {
			out = append(out, e)
		}
	}
	return out
}

func podReplaySummary(entries []k8sPodReplayEntry) map[string]any {
	byCategory := map[string]int{}
	bySeverity := map[string]int{"critical": 0, "warning": 0, "info": 0}
	for _, e := range entries {
		byCategory[e.Category]++
		bySeverity[e.Severity]++
	}
	return map[string]any{
		"total":       len(entries),
		"by_category": byCategory,
		"by_severity": bySeverity,
	}
}

func (s *Server) selectGoldenPod(ctx context.Context, clusterID string, target store.K8sInventoryItem, explicitName string, events []store.K8sEvent) (store.K8sInventoryItem, bool, error) {
	items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Pod", Namespace: target.Namespace, Limit: 1000})
	if err != nil {
		return store.K8sInventoryItem{}, false, err
	}
	if explicitName != "" {
		for _, item := range items {
			if item.Name == explicitName && item.Name != target.Name {
				return item, false, nil
			}
		}
		return store.K8sInventoryItem{}, false, fmt.Errorf("golden pod %q was not found in namespace %s", explicitName, target.Namespace)
	}
	targetView := podView(target, events, false)
	type candidate struct {
		item  store.K8sInventoryItem
		view  k8sPodView
		score int
	}
	candidates := []candidate{}
	for _, item := range items {
		if item.Name == target.Name {
			continue
		}
		if !samePodWorkload(target, item) {
			continue
		}
		view := podView(item, events, false)
		candidates = append(candidates, candidate{item: item, view: view, score: goldenPodScore(view)})
	}
	if len(candidates) == 0 {
		return store.K8sInventoryItem{}, false, fmt.Errorf("no comparable golden pod found for %s/%s under %s", target.Namespace, target.Name, podOwnerLabel(targetView))
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].view.RestartCount != candidates[j].view.RestartCount {
			return candidates[i].view.RestartCount < candidates[j].view.RestartCount
		}
		return candidates[i].item.Name < candidates[j].item.Name
	})
	return candidates[0].item, true, nil
}

func samePodWorkload(a, b store.K8sInventoryItem) bool {
	ak, an := podOwner(a.Spec)
	bk, bn := podOwner(b.Spec)
	if ak != "" && an != "" && bk != "" && bn != "" {
		if strings.EqualFold(ak, bk) && an == bn {
			return true
		}
	}
	for _, key := range []string{"app.kubernetes.io/instance", "app.kubernetes.io/name", "app"} {
		if a.Labels[key] != "" && a.Labels[key] == b.Labels[key] {
			return true
		}
	}
	return false
}

func goldenPodScore(p k8sPodView) int {
	score := 0
	if strings.EqualFold(p.Phase, "Running") || strings.EqualFold(p.Status, "Running") {
		score += 60
	}
	if p.ContainerCount > 0 && p.ReadyCount == p.ContainerCount {
		score += 50
	} else {
		score += p.ReadyCount * 10
	}
	switch strings.ToLower(p.RiskLevel) {
	case "critical", "high":
		score -= 80
	case "medium", "warning":
		score -= 35
	}
	score -= p.WarningEvents * 15
	score -= p.RestartCount * 6
	if podStatusRisk(firstNonEmpty(p.Status, p.Phase)) == "high" {
		score -= 80
	}
	return score
}

func goldenSelectionNote(target, golden k8sPodView, autoSelected bool) string {
	if autoSelected {
		return "same owner/label workload에서 Running, Ready, 낮은 restart/warning 점수를 기준으로 자동 선택: " + podOwnerLabel(target)
	}
	return "사용자가 지정한 golden Pod와 비교했습니다: " + golden.Namespace + "/" + golden.Name
}

func podOwnerLabel(p k8sPodView) string {
	if p.OwnerKind != "" || p.OwnerName != "" {
		return firstNonEmpty(p.OwnerKind, "-") + "/" + firstNonEmpty(p.OwnerName, "-")
	}
	return "same workload"
}

func comparePodsForGoldenDiff(target, golden k8sPodView) []k8sPodGoldenDiffChange {
	targetFields := podCompareFields(target)
	goldenFields := podCompareFields(golden)
	keys := map[string]struct{}{}
	for k := range targetFields {
		keys[k] = struct{}{}
	}
	for k := range goldenFields {
		keys[k] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	changes := []k8sPodGoldenDiffChange{}
	for _, key := range ordered {
		tv, gv := targetFields[key], goldenFields[key]
		if tv == gv {
			continue
		}
		changes = append(changes, k8sPodGoldenDiffChange{
			Field:    key,
			Category: podDiffCategory(key),
			Severity: podDiffSeverity(key, tv, gv),
			Target:   tv,
			Golden:   gv,
		})
	}
	return changes
}

func podCompareFields(p k8sPodView) map[string]string {
	fields := map[string]string{
		"status.phase":         firstNonEmpty(p.Phase, p.Status),
		"status.ready":         p.Ready,
		"status.restart_count": strconv.Itoa(p.RestartCount),
		"placement.node":       p.NodeName,
		"placement.qos_class":  p.QoSClass,
		"spec.service_account": firstNonEmpty(strAny(p.Spec["serviceAccountName"]), strAny(p.Spec["serviceAccount"])),
		"spec.priority_class":  strAny(p.Spec["priorityClassName"]),
		"spec.scheduler":       strAny(p.Spec["schedulerName"]),
		"spec.images":          joinStableStrings(p.Images),
		"spec.volumes":         podVolumeSignature(p.Spec),
		"metadata.labels":      stringMapSignature(p.Labels),
		"metadata.annotations": stringMapSignature(maskedStringMapToStringMap(p.Annotations)),
		"container.names":      podContainerNameSignature(p.Spec),
		"init_container.names": podInitContainerNameSignature(p.Spec),
	}
	for _, c := range p.Containers {
		prefix := "container." + firstNonEmpty(c.Name, "-")
		fields[prefix+".ready"] = strconv.FormatBool(c.Ready)
		fields[prefix+".restart_count"] = strconv.Itoa(c.RestartCount)
		fields[prefix+".state"] = firstNonEmpty(c.State, "-")
		fields[prefix+".reason"] = firstNonEmpty(c.Reason, c.LastReason)
	}
	addContainerSpecFields(fields, "container", asSliceAny(p.Spec["containers"]))
	addContainerSpecFields(fields, "init_container", asSliceAny(p.Spec["initContainers"]))
	return fields
}

func addContainerSpecFields(fields map[string]string, group string, containers []any) {
	for _, raw := range containers {
		c := asMapAny(raw)
		name := firstNonEmpty(strAny(c["name"]), "-")
		prefix := group + "." + name
		fields[prefix+".image"] = strAny(c["image"])
		fields[prefix+".env"] = podEnvSignature(c)
		fields[prefix+".env_from"] = podEnvFromSignature(c)
		fields[prefix+".resources"] = compactMaskedJSON(c["resources"])
		fields[prefix+".probes"] = podProbeSignature(c)
		fields[prefix+".volume_mounts"] = podVolumeMountSignature(c)
	}
}

func podDiffCategory(field string) string {
	switch {
	case strings.Contains(field, "image"):
		return "image"
	case strings.Contains(field, "env") || strings.Contains(field, "labels") || strings.Contains(field, "annotations") || strings.Contains(field, "service_account"):
		return "config"
	case strings.Contains(field, "resource"):
		return "resource"
	case strings.Contains(field, "probe"):
		return "probe"
	case strings.Contains(field, "volume"):
		return "storage"
	case strings.Contains(field, "node") || strings.Contains(field, "qos") || strings.Contains(field, "scheduler") || strings.Contains(field, "priority"):
		return "placement"
	case strings.Contains(field, "ready") || strings.Contains(field, "restart") || strings.Contains(field, "state") || strings.Contains(field, "reason") || strings.Contains(field, "phase"):
		return "runtime"
	default:
		return "spec"
	}
}

func podDiffSeverity(field, target, golden string) string {
	switch podDiffCategory(field) {
	case "image", "config":
		return "high"
	case "runtime":
		if strings.Contains(field, "restart") && target != golden {
			return "high"
		}
		if strings.Contains(field, "ready") || strings.Contains(field, "state") || strings.Contains(field, "phase") {
			return "high"
		}
		return "medium"
	case "probe", "resource", "storage":
		return "medium"
	case "placement":
		return "low"
	default:
		return "low"
	}
}

func podContainerNameSignature(spec map[string]any) string {
	return podNamedListSignature(asSliceAny(spec["containers"]))
}

func podInitContainerNameSignature(spec map[string]any) string {
	return podNamedListSignature(asSliceAny(spec["initContainers"]))
}

func podNamedListSignature(values []any) string {
	names := []string{}
	for _, raw := range values {
		if name := strAny(asMapAny(raw)["name"]); name != "" {
			names = append(names, name)
		}
	}
	return joinStableStrings(names)
}

func podEnvSignature(container map[string]any) string {
	entries := []string{}
	for _, raw := range asSliceAny(container["env"]) {
		env := asMapAny(raw)
		name := strAny(env["name"])
		if name == "" {
			continue
		}
		source := "value:" + maskedValueFingerprint(strAny(env["value"]))
		if vf := asMapAny(env["valueFrom"]); len(vf) > 0 {
			source = "valueFrom"
			for _, key := range []string{"configMapKeyRef", "secretKeyRef", "fieldRef", "resourceFieldRef"} {
				if _, ok := vf[key]; ok {
					source = key
					break
				}
			}
		}
		entries = append(entries, name+"<-"+source)
	}
	return joinStableStrings(entries)
}

func maskedValueFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return maskedValue + "#" + hex.EncodeToString(sum[:4])
}

func podEnvFromSignature(container map[string]any) string {
	entries := []string{}
	for _, raw := range asSliceAny(container["envFrom"]) {
		envFrom := asMapAny(raw)
		prefix := strAny(envFrom["prefix"])
		source := ""
		switch {
		case len(asMapAny(envFrom["configMapRef"])) > 0:
			source = "configMapRef:" + strAny(asMapAny(envFrom["configMapRef"])["name"])
		case len(asMapAny(envFrom["secretRef"])) > 0:
			source = "secretRef:" + maskedValue
		}
		if source != "" {
			entries = append(entries, firstNonEmpty(prefix, "-")+":"+source)
		}
	}
	return joinStableStrings(entries)
}

func podProbeSignature(container map[string]any) string {
	entries := []string{}
	for _, key := range []string{"livenessProbe", "readinessProbe", "startupProbe"} {
		if v, ok := container[key]; ok {
			entries = append(entries, key+"="+compactMaskedJSON(v))
		}
	}
	return joinStableStrings(entries)
}

func podVolumeSignature(spec map[string]any) string {
	entries := []string{}
	for _, raw := range asSliceAny(spec["volumes"]) {
		v := asMapAny(raw)
		name := firstNonEmpty(strAny(v["name"]), "-")
		kind := "unknown"
		for _, key := range []string{"configMap", "secret", "persistentVolumeClaim", "emptyDir", "projected", "hostPath", "csi", "downwardAPI"} {
			if _, ok := v[key]; ok {
				kind = key
				break
			}
		}
		if kind == "secret" {
			entries = append(entries, name+":secret:"+maskedValue)
		} else {
			entries = append(entries, name+":"+kind)
		}
	}
	return joinStableStrings(entries)
}

func podVolumeMountSignature(container map[string]any) string {
	entries := []string{}
	for _, raw := range asSliceAny(container["volumeMounts"]) {
		mount := asMapAny(raw)
		name := firstNonEmpty(strAny(mount["name"]), "-")
		path := firstNonEmpty(strAny(mount["mountPath"]), "-")
		readOnly := ""
		if boolAny(mount["readOnly"]) {
			readOnly = ":ro"
		}
		entries = append(entries, name+":"+path+readOnly)
	}
	return joinStableStrings(entries)
}

func maskedStringMapToStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if isSensitivePath(k) {
			out[k] = maskedValue
		} else {
			out[k] = analyzer.MaskSensitive(v)
		}
	}
	return out
}

func stringMapSignature(in map[string]string) string {
	entries := []string{}
	for k, v := range in {
		entries = append(entries, k+"="+v)
	}
	return joinStableStrings(entries)
}

func compactMaskedJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(maskManifestValue(v))
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func joinStableStrings(values []string) string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func podView(item store.K8sInventoryItem, events []store.K8sEvent, includeContainers bool) k8sPodView {
	spec := item.Spec
	status := item.StatusObject
	containers := podContainerStatuses(spec, status)
	ready := 0
	restarts := 0
	images := []string{}
	for _, c := range containers {
		if c.Ready {
			ready++
		}
		restarts += c.RestartCount
		if c.Image != "" && !containsStringValue(images, c.Image) {
			images = append(images, c.Image)
		}
	}
	ownerKind, ownerName := podOwner(spec)
	view := k8sPodView{
		K8sInventoryItem: item,
		Phase:            firstNonEmpty(strAny(status["phase"]), item.Status),
		ReadyCount:       ready,
		ContainerCount:   len(containers),
		RestartCount:     restarts,
		NodeName:         strAny(spec["nodeName"]),
		PodIP:            strAny(status["podIP"]),
		QoSClass:         strAny(status["qosClass"]),
		OwnerKind:        ownerKind,
		OwnerName:        ownerName,
		Images:           images,
		Age:              ageFromTime(firstNonEmpty(strAny(status["startTime"]), item.ObservedAt)),
		WarningEvents:    countWarningEvents(events, item.Namespace, item.Name),
	}
	view.Ready = fmt.Sprintf("%d/%d", ready, len(containers))
	if includeContainers {
		view.Containers = containers
	}
	if view.RiskLevel == "" || view.RiskLevel == "low" {
		if risk := podStatusRisk(firstNonEmpty(item.Status, view.Phase)); risk != "" {
			view.RiskLevel = risk
		}
	}
	return view
}

func podContainerStatuses(spec, status map[string]any) []k8sContainerStatusView {
	imagesByName := map[string]string{}
	for _, raw := range append(asSliceAny(spec["initContainers"]), asSliceAny(spec["containers"])...) {
		m := asMapAny(raw)
		name := strAny(m["name"])
		if name != "" {
			imagesByName[name] = strAny(m["image"])
		}
	}
	out := []k8sContainerStatusView{}
	for _, raw := range append(asSliceAny(status["initContainerStatuses"]), asSliceAny(status["containerStatuses"])...) {
		m := asMapAny(raw)
		state, reason, exitCode := containerState(asMapAny(m["state"]))
		lastState, lastReason, _ := containerState(asMapAny(m["lastState"]))
		name := strAny(m["name"])
		image := firstNonEmpty(strAny(m["image"]), imagesByName[name])
		out = append(out, k8sContainerStatusView{
			Name: name, Image: image, Ready: boolAny(m["ready"]), RestartCount: intAny(m["restartCount"]),
			State: state, Reason: reason, ExitCode: exitCode, LastState: lastState, LastReason: lastReason,
		})
	}
	if len(out) == 0 {
		for name, image := range imagesByName {
			out = append(out, k8sContainerStatusView{Name: name, Image: image})
		}
	}
	return out
}

func containerState(state map[string]any) (string, string, int) {
	for _, key := range []string{"waiting", "terminated", "running"} {
		if v, ok := state[key]; ok {
			m := asMapAny(v)
			return key, strAny(m["reason"]), intAny(m["exitCode"])
		}
	}
	return "", "", 0
}

func podOwner(spec map[string]any) (string, string) {
	for _, raw := range asSliceAny(spec["ownerReferences"]) {
		m := asMapAny(raw)
		if boolAny(m["controller"]) || strAny(m["kind"]) != "" {
			return strAny(m["kind"]), strAny(m["name"])
		}
	}
	return "", ""
}

func defaultContainerName(item store.K8sInventoryItem) string {
	for _, c := range podContainerStatuses(item.Spec, item.StatusObject) {
		if c.Name != "" {
			return c.Name
		}
	}
	return ""
}

func filterPodEvents(events []store.K8sEvent, namespace, pod string) []store.K8sEvent {
	out := []store.K8sEvent{}
	for _, e := range events {
		if e.Namespace == namespace && e.InvolvedKind == "Pod" && e.InvolvedName == pod {
			out = append(out, e)
		}
	}
	return out
}

func countWarningEvents(events []store.K8sEvent, namespace, pod string) int {
	n := 0
	for _, e := range filterPodEvents(events, namespace, pod) {
		if strings.EqualFold(e.Type, "Warning") {
			n++
		}
	}
	return n
}

func podMatchesFilters(p k8sPodView, q url.Values) bool {
	if ns := strings.TrimSpace(q.Get("namespace")); ns != "" && p.Namespace != ns {
		return false
	}
	if node := strings.TrimSpace(q.Get("node")); node != "" && p.NodeName != node {
		return false
	}
	if status := strings.TrimSpace(q.Get("status")); status != "" && !strings.Contains(strings.ToLower(p.Status+" "+p.Phase), strings.ToLower(status)) {
		return false
	}
	if owner := strings.TrimSpace(q.Get("owner")); owner != "" && !strings.Contains(strings.ToLower(p.OwnerKind+"/"+p.OwnerName), strings.ToLower(owner)) {
		return false
	}
	if risk := strings.TrimSpace(q.Get("risk")); risk != "" && !strings.EqualFold(p.RiskLevel, risk) {
		return false
	}
	if query := strings.TrimSpace(q.Get("q")); query != "" {
		hay := strings.ToLower(p.Namespace + " " + p.Name + " " + p.Status + " " + p.Phase + " " + p.NodeName + " " + p.OwnerKind + " " + p.OwnerName + " " + strings.Join(p.Images, " "))
		if !strings.Contains(hay, strings.ToLower(query)) {
			return false
		}
	}
	return true
}

func podStatusRisk(status string) string {
	s := strings.ToLower(status)
	switch {
	case strings.Contains(s, "crashloop") || strings.Contains(s, "oom") || strings.Contains(s, "imagepull") || strings.Contains(s, "errimagepull") || strings.Contains(s, "evicted"):
		return "high"
	case strings.Contains(s, "pending") || strings.Contains(s, "terminating") || strings.Contains(s, "unavailable"):
		return "medium"
	default:
		return ""
	}
}

func processPodLogs(raw, query string, errorOnly bool) k8sPodLogResponse {
	masked := analyzer.MaskSensitive(raw)
	lines := []k8sPodLogLine{}
	textLines := []string{}
	needle := strings.ToLower(strings.TrimSpace(query))
	for i, line := range strings.Split(masked, "\n") {
		if needle != "" && !strings.Contains(strings.ToLower(line), needle) {
			continue
		}
		level := string(analyzer.ClassifyLogLine(line))
		if errorOnly && level == string(analyzer.LogInfo) {
			continue
		}
		lines = append(lines, k8sPodLogLine{Number: i + 1, Level: level, Text: line})
		textLines = append(textLines, line)
	}
	text := strings.Join(textLines, "\n")
	return k8sPodLogResponse{Lines: lines, Text: text, Summary: analyzer.SummarizeLog(text)}
}

func analyzeLogPatterns(current, previous []k8sPodLogLine) []k8sPodLogAnalysisPattern {
	type bucket struct {
		pattern k8sPodLogAnalysisPattern
	}
	buckets := map[string]*bucket{}
	add := func(line k8sPodLogLine) {
		if line.Level == string(analyzer.LogInfo) || strings.TrimSpace(line.Text) == "" {
			return
		}
		category := classifyLogPatternCategory(line.Text)
		key := category + ":" + normalizeLogPattern(line.Text)
		b, ok := buckets[key]
		if !ok {
			message := strings.TrimSpace(line.Text)
			if len(message) > 220 {
				message = message[:220] + "..."
			}
			b = &bucket{pattern: k8sPodLogAnalysisPattern{
				Key: key, Category: category, Severity: logPatternSeverity(category, line.Level),
				Message: message, FirstLine: line.Number,
			}}
			buckets[key] = b
		}
		b.pattern.Count++
		b.pattern.LastLine = line.Number
		if b.pattern.FirstLine == 0 || line.Number < b.pattern.FirstLine {
			b.pattern.FirstLine = line.Number
		}
		if len(b.pattern.Samples) < 3 {
			b.pattern.Samples = append(b.pattern.Samples, line)
		}
	}
	for _, line := range current {
		add(line)
	}
	for _, line := range previous {
		add(line)
	}
	out := make([]k8sPodLogAnalysisPattern, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, b.pattern)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if podLogSeverityRank(out[i].Severity) != podLogSeverityRank(out[j].Severity) {
			return podLogSeverityRank(out[i].Severity) > podLogSeverityRank(out[j].Severity)
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].FirstLine < out[j].FirstLine
	})
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

func normalizeLogPattern(line string) string {
	line = strings.ToLower(strings.TrimSpace(line))
	line = strings.Join(strings.Fields(line), " ")
	var b strings.Builder
	prevHash := false
	for _, r := range line {
		switch {
		case r >= '0' && r <= '9':
			if !prevHash {
				b.WriteRune('#')
				prevHash = true
			}
		default:
			prevHash = false
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 180 {
		out = out[:180]
	}
	return out
}

func classifyLogPatternCategory(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "out of memory") || strings.Contains(l, "oom") || strings.Contains(l, "killed"):
		return "oom"
	case strings.Contains(l, "connection refused") || strings.Contains(l, "connection reset") || strings.Contains(l, "no route") || strings.Contains(l, "broken pipe"):
		return "network"
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline exceeded") || strings.Contains(l, "timed out"):
		return "timeout"
	case strings.Contains(l, "no such host") || strings.Contains(l, "name resolution") || strings.Contains(l, "dns") || strings.Contains(l, "nxdomain"):
		return "dns"
	case strings.Contains(l, "unauthorized") || strings.Contains(l, "forbidden") || strings.Contains(l, "permission denied") || strings.Contains(l, "access denied"):
		return "auth"
	case strings.Contains(l, "readiness") || strings.Contains(l, "liveness") || strings.Contains(l, "probe"):
		return "probe"
	case strings.Contains(l, "imagepull") || strings.Contains(l, "errimagepull") || strings.Contains(l, "pull image"):
		return "image"
	case strings.Contains(l, "exception") || strings.Contains(l, "traceback") || strings.Contains(l, "stacktrace") || strings.Contains(l, "panic") || strings.Contains(l, "fatal"):
		return "exception"
	case strings.Contains(l, "retry") || strings.Contains(l, "throttl") || strings.Contains(l, "degraded"):
		return "warning"
	default:
		return "error"
	}
}

func logPatternSeverity(category, level string) string {
	switch category {
	case "oom", "exception", "image":
		return "high"
	case "timeout", "dns", "network", "auth", "probe":
		return "medium"
	default:
		if level == string(analyzer.LogError) {
			return "medium"
		}
		return "low"
	}
}

func logInsightsFromPatterns(patterns []k8sPodLogAnalysisPattern, pod k8sPodView) []k8sPodLogInsight {
	seen := map[string]bool{}
	out := []k8sPodLogInsight{}
	add := func(condition, severity, cause string, evidence, actions []string) {
		if seen[condition] {
			return
		}
		seen[condition] = true
		out = append(out, k8sPodLogInsight{Condition: condition, Severity: severity, Cause: cause, Evidence: evidence, Actions: actions})
	}
	for _, p := range patterns {
		evidence := []string{fmt.Sprintf("log:%s lines %d-%d count %d", p.Category, p.FirstLine, p.LastLine, p.Count)}
		if len(p.Samples) > 0 {
			evidence = append(evidence, fmt.Sprintf("sample line %d: %s", p.Samples[0].Number, p.Samples[0].Text))
		}
		switch p.Category {
		case "oom":
			add("LogOOMSignal", "high", "로그에 OOM 또는 메모리 부족 신호가 있습니다.", evidence,
				[]string{"Pod 리소스 탭에서 memory usage와 limit을 비교합니다.", "Rightsizing 권장값을 확인합니다.", "최근 배포/traffic 증가와 함께 memory leak 가능성을 점검합니다."})
		case "exception":
			add("ApplicationException", "high", "애플리케이션 예외 또는 panic/stacktrace가 반복됩니다.", evidence,
				[]string{"previous 로그의 첫 예외와 stacktrace 최상단 원인을 확인합니다.", "Golden Pod Diff에서 image/env/config 차이를 비교합니다.", "최근 리비전 diff와 배포 시점을 대조합니다."})
		case "image":
			add("ImagePullLogSignal", "high", "이미지 pull 또는 registry 관련 오류가 로그에 보입니다.", evidence,
				[]string{"image tag와 registry 경로를 확인합니다.", "imagePullSecret 만료와 ServiceAccount 연결을 점검합니다.", "노드에서 registry 접근 가능 여부를 확인합니다."})
		case "timeout":
			add("TimeoutSpike", "medium", "timeout/deadline 오류가 감지되었습니다.", evidence,
				[]string{"대상 dependency의 Service/Endpoint 상태를 확인합니다.", "최근 배포 이후 timeout 증가 여부를 Health Replay에서 확인합니다.", "readiness probe timeout과 애플리케이션 timeout 설정을 비교합니다."})
		case "dns":
			add("DNSResolutionFailure", "medium", "DNS 또는 name resolution 실패 가능성이 있습니다.", evidence,
				[]string{"Service 이름과 namespace를 확인합니다.", "CoreDNS Pod와 kube-dns Service 이벤트를 확인합니다.", "같은 namespace의 정상 Pod와 env/service 설정을 비교합니다."})
		case "network":
			add("NetworkConnectivityFailure", "medium", "connection refused/reset/no route 계열 네트워크 오류가 보입니다.", evidence,
				[]string{"대상 Service Endpoint가 존재하는지 확인합니다.", "NetworkPolicy와 port 설정을 점검합니다.", "Pod가 올라간 node의 네트워크 이벤트를 확인합니다."})
		case "auth":
			add("AuthorizationFailure", "medium", "권한/인증 실패 로그가 반복됩니다.", evidence,
				[]string{"ServiceAccount, Secret, token 만료 여부를 점검합니다.", "최근 Secret/ConfigMap 변경 리비전을 확인합니다.", "외부 API credential rotation 이력을 확인합니다."})
		case "probe":
			add("ProbeFailureSignal", "medium", "readiness/liveness probe 관련 로그가 보입니다.", evidence,
				[]string{"probe path, port, initialDelaySeconds, timeoutSeconds를 확인합니다.", "애플리케이션 시작 시간과 probe 시작 시점을 비교합니다.", "Endpoint 제외 여부와 서비스 영향도를 확인합니다."})
		}
	}
	if pod.RestartCount > 0 && !seen["RestartCorrelatedLogs"] {
		add("RestartCorrelatedLogs", "medium", "Pod restart와 로그 오류가 같은 분석 범위에 있습니다.",
			[]string{fmt.Sprintf("pod restarts: %d", pod.RestartCount)},
			[]string{"previous 로그를 우선 확인합니다.", "컨테이너 last state와 exit code를 확인합니다.", "반복 재시작이면 Evidence Bundle을 생성해 장애 증적을 고정합니다."})
	}
	if len(out) == 0 {
		add("NoStrongLogSignal", "low", "분석 범위에서 강한 에러 패턴은 발견되지 않았습니다.",
			[]string{"log summary has no grouped error/warn pattern"},
			[]string{"tail_lines 또는 since 범위를 넓혀 다시 분석합니다.", "Kubernetes 이벤트와 Health Replay에서 상태 변화를 확인합니다.", "Golden Pod Diff로 설정 차이를 비교합니다."})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return podLogSeverityRank(out[i].Severity) > podLogSeverityRank(out[j].Severity)
	})
	return out
}

func podLogSeverityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return 3
	case "warning", "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func parseSinceSeconds(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return n
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return int(d.Seconds())
	}
	return 0
}

func boundedInt(raw string, fallback, min, max int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		if n < min {
			return min
		}
		if n > max {
			return max
		}
		return n
	}
	return fallback
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func asMapAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asSliceAny(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func strAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func intAny(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func boolAny(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return parseBool(t)
	default:
		return false
	}
}

func containsStringValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func ageFromTime(raw string) string {
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return ""
	}
	d := time.Since(t)
	if d < time.Minute {
		return strconv.Itoa(int(d.Seconds())) + "s"
	}
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	}
	if d < 48*time.Hour {
		return strconv.Itoa(int(d.Hours())) + "h"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d"
}

func sanitizeDownloadName(name string) string {
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", "\"", "")
	name = repl.Replace(name)
	if name == "" {
		return "pod_logs.txt"
	}
	return name
}
