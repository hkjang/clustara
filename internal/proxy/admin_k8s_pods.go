package proxy

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	if parts[2] == "logs" {
		if len(parts) > 3 && parts[3] == "stream" {
			if r.Method != http.MethodGet {
				writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
				return
			}
			s.handleK8sPodLogStream(w, r, namespace, pod)
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
