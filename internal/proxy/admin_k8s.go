package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	k8saction "clustara/internal/action"
	"clustara/internal/analyzer"
	"clustara/internal/collector"
	"clustara/internal/kube"
	"clustara/internal/store"
)

type k8sClusterPayload struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	ServerURL   string            `json:"server_url"`
	AuthMode    string            `json:"auth_mode"`
	GroupID     string            `json:"group_id"`
	Labels      map[string]string `json:"labels"`
	Kubeconfig  string            `json:"kubeconfig"`
	Token       string            `json:"token"`
}

func (s *Server) handleK8sOverview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	overview, err := s.db.K8sOverview(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_overview_failed")
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleK8sClusters(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		clusters, err := s.db.ListK8sClusters(r.Context())
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_clusters_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"clusters": clusters})
	case http.MethodPost:
		var p k8sClusterPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		mode := kube.NormalizeAuthMode(p.AuthMode)
		if err := kube.ValidateClusterRegistration(p.Name, p.ServerURL, mode); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_k8s_cluster")
			return
		}
		id := strings.TrimSpace(p.ID)
		if id == "" {
			id = newID("k8scl")
		}
		cluster := store.K8sCluster{
			ID:          id,
			Name:        strings.TrimSpace(p.Name),
			Description: strings.TrimSpace(p.Description),
			ServerURL:   strings.TrimSpace(p.ServerURL),
			AuthMode:    mode,
			GroupID:     strings.TrimSpace(p.GroupID),
			Status:      "registered",
			Labels:      p.Labels,
		}
		if p.Kubeconfig != "" || p.Token != "" {
			kind, raw := "kubeconfig", p.Kubeconfig
			if raw == "" {
				kind, raw = "token", p.Token
			}
			encrypted, err := s.secrets.Load().Encrypt(raw)
			if err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_credential_encrypt_failed")
				return
			}
			credID := newID("k8scred")
			cluster.CredentialRef = credID
			if err := s.db.SaveK8sCredential(r.Context(), store.K8sClusterCredential{
				ID: credID, ClusterID: id, Kind: kind, EncryptedPayload: encrypted,
			}); err != nil {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_credential_save_failed")
				return
			}
		}
		if err := s.db.UpsertK8sCluster(r.Context(), cluster); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.cluster.upsert", "", auditJSON(map[string]any{
			"id": cluster.ID, "name": cluster.Name, "auth_mode": cluster.AuthMode, "credential_configured": cluster.CredentialRef != "",
		}))
		writeJSON(w, http.StatusCreated, map[string]any{"cluster": cluster})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sClusterByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/clusters/"), "/"), "/")
	id := ""
	if len(parts) > 0 {
		id = parts[0]
	}
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster id required", "invalid_request_error", "missing_cluster_id")
		return
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+id, "invalid_request_error", "cluster_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	if len(parts) > 1 {
		switch parts[1] {
		case "test":
			s.handleK8sClusterTest(w, r, cluster)
		case "collect":
			s.handleK8sClusterCollect(w, r, cluster)
		case "discover":
			s.handleK8sClusterDiscover(w, r, cluster)
		default:
			writeOpenAIError(w, http.StatusNotFound, "unknown cluster command: "+parts[1], "invalid_request_error", "unknown_cluster_command")
		}
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cluster": cluster})
}

func (s *Server) handleK8sClusterTest(w http.ResponseWriter, r *http.Request, cluster store.K8sCluster) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	probe, err := client.Probe(r.Context())
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cluster.LastConnectedAt = now
	cluster.KubernetesVersion = probe.KubernetesVersion
	cluster.NodeCount = probe.NodeCount
	cluster.NamespaceCount = probe.NamespaceCount
	cluster.LastError = ""
	cluster.Status = "ready"
	if err != nil {
		cluster.Status = "error"
		cluster.LastError = err.Error()
	}
	_ = s.db.UpsertK8sCluster(r.Context(), cluster)
	s.auditAdmin(r, "k8s.cluster.test", "", auditJSON(map[string]any{
		"id": cluster.ID, "ok": err == nil, "version": probe.KubernetesVersion, "nodes": probe.NodeCount, "namespaces": probe.NamespaceCount,
	}))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "cluster": cluster, "probe": probe, "error": "Kubernetes API 연결 테스트 실패: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cluster": cluster, "probe": probe})
}

// k8sCollectOutcome is the staged result of one inventory collection (used by both the manual
// endpoint and the background scheduler).
type k8sCollectOutcome struct {
	Cluster store.K8sCluster
	Probe   kube.ProbeResult
	Result  collector.ApplyResult
	Stage   string // client | probe | collect | snapshot | ok
	Err     error
}

// collectClusterInventory probes a cluster, pulls a full inventory snapshot, and persists it
// (updating the cluster's status + LastConnectedAt on every attempt). Shared by the manual collect
// endpoint and the adaptive scheduler so both behave identically.
func (s *Server) collectClusterInventory(ctx context.Context, cluster store.K8sCluster) k8sCollectOutcome {
	return s.collectClusterInventoryTriggered(ctx, cluster, "manual")
}

// collectClusterInventoryTriggered runs a collect and records the attempt's outcome (for the
// Collector SLO dashboard + Collect Gap RCA). trigger labels the caller (manual | scheduled).
func (s *Server) collectClusterInventoryTriggered(ctx context.Context, cluster store.K8sCluster, trigger string) k8sCollectOutcome {
	start := time.Now()
	out := s.runClusterCollect(ctx, cluster)
	s.recordCollectRun(ctx, out, trigger, time.Since(start).Milliseconds())
	return out
}

// recordCollectRun persists one collect attempt outcome, classifying failures via Collect Gap RCA.
func (s *Server) recordCollectRun(ctx context.Context, out k8sCollectOutcome, trigger string, latencyMS int64) {
	run := store.K8sCollectRun{
		ID:            newID("k8scrun"),
		ClusterID:     out.Cluster.ID,
		Trigger:       trigger,
		Stage:         out.Stage,
		OK:            out.Stage == "ok",
		LatencyMS:     latencyMS,
		ResourceCount: out.Result.Resources,
	}
	if out.Err != nil {
		run.ErrorText = out.Err.Error()
		run.Category = analyzer.ClassifyCollectGap(out.Stage, run.ErrorText).Category
	}
	_ = s.db.RecordK8sCollectRun(ctx, run) // best-effort telemetry
}

func (s *Server) runClusterCollect(ctx context.Context, cluster store.K8sCluster) k8sCollectOutcome {
	client, err := s.k8sClientForCluster(ctx, cluster)
	if err != nil {
		return k8sCollectOutcome{Cluster: cluster, Stage: "client", Err: err}
	}
	probe, probeErr := client.Probe(ctx)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cluster.LastConnectedAt = now
	cluster.KubernetesVersion = probe.KubernetesVersion
	cluster.NodeCount = probe.NodeCount
	cluster.NamespaceCount = probe.NamespaceCount
	cluster.Status = "ready"
	cluster.LastError = ""
	if probeErr != nil {
		cluster.Status = "error"
		cluster.LastError = probeErr.Error()
		_ = s.db.UpsertK8sCluster(ctx, cluster)
		return k8sCollectOutcome{Cluster: cluster, Probe: probe, Stage: "probe", Err: probeErr}
	}
	collected, err := client.Collect(ctx)
	if err != nil {
		cluster.Status = "error"
		cluster.LastError = err.Error()
		_ = s.db.UpsertK8sCluster(ctx, cluster)
		return k8sCollectOutcome{Cluster: cluster, Probe: probe, Stage: "collect", Err: err}
	}
	_ = s.db.UpsertK8sCluster(ctx, cluster)
	result, err := collector.ApplySnapshot(ctx, s.db, collector.Snapshot{
		ClusterID:     cluster.ID,
		ObservedAt:    now,
		Resources:     collected.Resources,
		Events:        collected.Events,
		Metrics:       collected.Metrics,
		FullSync:      true,
		FullSyncKinds: collected.FullSyncKinds,
	}, newID)
	if err != nil {
		return k8sCollectOutcome{Cluster: cluster, Probe: probe, Stage: "snapshot", Err: err}
	}
	return k8sCollectOutcome{Cluster: cluster, Probe: probe, Result: result, Stage: "ok"}
}

func (s *Server) handleK8sClusterCollect(w http.ResponseWriter, r *http.Request, cluster store.K8sCluster) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	out := s.collectClusterInventory(r.Context(), cluster)
	switch out.Stage {
	case "client":
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 수집 준비 실패: "+out.Err.Error(), "invalid_request_error", "k8s_client_failed")
	case "probe":
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "cluster": out.Cluster, "probe": out.Probe, "error": "Kubernetes API 연결 테스트 실패: " + out.Err.Error()})
	case "collect":
		writeOpenAIError(w, http.StatusServiceUnavailable, "Kubernetes 인벤토리 수집 실패: "+out.Err.Error(), "server_error", "k8s_collect_failed")
	case "snapshot":
		writeOpenAIError(w, http.StatusInternalServerError, out.Err.Error(), "server_error", "k8s_snapshot_failed")
	default:
		s.auditAdmin(r, "k8s.cluster.collect", "", auditJSON(out.Result))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cluster": out.Cluster, "probe": out.Probe, "result": out.Result})
	}
}

func (s *Server) k8sClientForCluster(ctx context.Context, cluster store.K8sCluster) (kube.Client, error) {
	cred, err := s.db.GetK8sCredential(ctx, cluster.ID)
	if errors.Is(err, store.ErrNotFound) {
		if kube.NormalizeAuthMode(cluster.AuthMode) == "in_cluster" || cluster.ServerURL != "" {
			return kube.NewClient(cluster, "", "")
		}
		return nil, errors.New("클러스터 credential이 없습니다")
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.secrets.Load().Decrypt(cred.EncryptedPayload)
	if err != nil {
		return nil, err
	}
	return kube.NewClient(cluster, cred.Kind, plain)
}

func (s *Server) handleK8sSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var snap collector.Snapshot
	if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if _, err := s.db.GetK8sCluster(r.Context(), snap.ClusterID); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+snap.ClusterID, "invalid_request_error", "cluster_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	result, err := collector.ApplySnapshot(r.Context(), s.db, snap, newID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_snapshot_failed")
		return
	}
	s.auditAdmin(r, "k8s.snapshot.apply", "", auditJSON(result))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleK8sInventory(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{
		ClusterID: q.Get("cluster_id"),
		Kind:      q.Get("kind"),
		Namespace: q.Get("namespace"),
		Status:    q.Get("status"),
		Limit:     intParam(q.Get("limit"), 200),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleK8sEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	events, err := s.db.ListK8sEvents(r.Context(), r.URL.Query().Get("cluster_id"), intParam(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_events_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleK8sFindings(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	findings, err := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{
		ClusterID: q.Get("cluster_id"),
		Severity:  q.Get("severity"),
		Status:    firstQuery(q.Get("status"), "open"),
		Limit:     intParam(q.Get("limit"), 100),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_findings_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

func (s *Server) handleK8sRCA(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 1000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, err := s.db.ListK8sEvents(r.Context(), clusterID, 500)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_events_failed")
		return
	}
	candidates := analyzer.AnalyzeRCA(items, events)
	// RCA-09: correlate each candidate with a recent spec change (revision) of the same resource.
	revisions, err := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Limit: 1000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_revisions_failed")
		return
	}
	now := time.Now().UTC()
	candidates = analyzer.EnrichWithConfigChanges(candidates, revisions, now, 24*time.Hour)
	// RCA-10: workloads whose errors appeared right after a deploy.
	candidates = append(candidates, analyzer.AnalyzePostDeploymentErrors(revisions, events, now, 24*time.Hour)...)
	// RCA-10 (latency): post-deploy latency regression from external latency samples.
	if latency, lerr := s.db.ListK8sMetricSamples(r.Context(), clusterID, 4000); lerr == nil {
		candidates = append(candidates, analyzer.AnalyzeLatencyRegressions(revisions, latency, now, 24*time.Hour)...)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"candidates": candidates,
		"count":      len(candidates),
		"note":       "저장된 인벤토리·Kubernetes Event·spec 리비전을 바탕으로 산출한 규칙 기반 원인 후보입니다. (probe·DNS·config 변경 포함)",
	})
}

func (s *Server) handleK8sScaleSimulate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	item, err := s.db.GetK8sInventoryItem(r.Context(), q.Get("cluster_id"), q.Get("kind"), q.Get("namespace"), q.Get("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "resource not found", "invalid_request_error", "resource_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	current := analyzer.ExtractReplica(item.Spec)
	target := intParam(q.Get("replicas"), current)
	sim := analyzer.SimulateScale(item.Spec, current, target)
	writeJSON(w, http.StatusOK, map[string]any{"simulation": sim})
}

func (s *Server) handleK8sCapacity(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	metrics, _ := s.db.ListK8sMetricSamples(r.Context(), clusterID, 2000)
	report := analyzer.AnalyzeCapacity(items, metrics)
	writeJSON(w, http.StatusOK, map[string]any{
		"report": report,
		"note":   "HPA 현황·과소/과다 할당·노드 packing·GPU를 인벤토리(spec+status)와 메트릭으로 산출한 결과입니다.",
	})
}

func (s *Server) handleK8sSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 2000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	report := analyzer.AnalyzeSecurity(items)
	actions, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: clusterID, Limit: 1000})
	anomalies := analyzer.DetectActionAnomalies(actions, time.Now().UTC(), time.Hour, 5)
	tls := analyzer.AnalyzeTLS(items, time.Now().UTC(), 30)
	writeJSON(w, http.StatusOK, map[string]any{
		"report":          report,
		"audit_anomalies": anomalies,
		"tls":             tls,
		"note":            "Pod Security Standards 등급, RBAC 위험, 이미지 태그, Secret 참조, NetworkPolicy 공백을 인벤토리로 점검한 결과입니다.",
	})
}

func (s *Server) handleK8sConnectivity(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 2000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, err := s.db.ListK8sEvents(r.Context(), clusterID, 500)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_events_failed")
		return
	}
	findings := analyzer.AnalyzeConnectivity(items, events)
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
		"count":    len(findings),
		"note":     "Service selector↔Pod, Ingress backend/host/TLS, PVC Pending을 저장된 인벤토리·이벤트로 점검한 결과입니다.",
	})
}

type k8sActionPayload struct {
	ClusterID      string         `json:"cluster_id"`
	Namespace      string         `json:"namespace"`
	ResourceKind   string         `json:"resource_kind"`
	ResourceName   string         `json:"resource_name"`
	Action         string         `json:"action"`
	Parameters     map[string]any `json:"parameters"`
	DryRunDiff     string         `json:"dry_run_diff"`
	IdempotencyKey string         `json:"idempotency_key"`
}

func (s *Server) handleK8sActions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		actions, err := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{
			ClusterID: q.Get("cluster_id"),
			Status:    q.Get("status"),
			Limit:     intParam(q.Get("limit"), 100),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_actions_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
	case http.MethodPost:
		var p k8sActionPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(p.ClusterID) == "" || strings.TrimSpace(p.ResourceKind) == "" || strings.TrimSpace(p.ResourceName) == "" || strings.TrimSpace(p.Action) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "cluster_id, resource_kind, resource_name and action are required", "invalid_request_error", "missing_fields")
			return
		}
		idempotencyKey := strings.TrimSpace(firstNonEmpty(p.IdempotencyKey, r.Header.Get("Idempotency-Key")))
		if idempotencyKey != "" {
			existing, err := s.db.GetK8sActionRequestByIdempotencyKey(r.Context(), idempotencyKey)
			if err == nil {
				writeJSON(w, http.StatusOK, map[string]any{"action": existing, "idempotent_replay": true})
				return
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_idempotency_lookup_failed")
				return
			}
		}
		if _, err := s.db.GetK8sCluster(r.Context(), p.ClusterID); errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+p.ClusterID, "invalid_request_error", "cluster_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
			return
		}
		decision := k8saction.Classify(p.Action)
		// Read-only impact assessment from the stored inventory (ACT-01~07 안전장치).
		all, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: p.ClusterID, Limit: 2000})
		var target store.K8sInventoryItem
		if t, err := s.db.GetK8sInventoryItem(r.Context(), p.ClusterID, p.ResourceKind, p.Namespace, p.ResourceName); err == nil {
			target = t
		}
		impact := k8saction.AssessImpact(p.Action, p.Parameters, target, all)
		status := "pending"
		if decision.RequiresApproval || len(impact.Blockers) > 0 {
			status = "approval_required"
		}
		diff := strings.TrimSpace(p.DryRunDiff)
		if diff == "" {
			diff = "영향도: " + impact.Summary
			if len(impact.Blockers) > 0 {
				diff += "\n승인 필요 사유: " + strings.Join(impact.Blockers, " · ")
			}
			if decision.DryRunRequired {
				diff += "\n(실제 서버사이드 실행기는 아직 연결되지 않아 휴먼 검토용으로 기록됩니다.)"
			}
		}
		req := store.K8sActionRequest{
			ID:                    newID("k8sact"),
			ClusterID:             strings.TrimSpace(p.ClusterID),
			Namespace:             strings.TrimSpace(p.Namespace),
			ResourceKind:          strings.TrimSpace(p.ResourceKind),
			ResourceName:          strings.TrimSpace(p.ResourceName),
			Action:                strings.TrimSpace(p.Action),
			Parameters:            p.Parameters,
			RiskLevel:             decision.RiskLevel,
			Status:                status,
			RequestedBy:           adminID(r),
			DryRunDiff:            diff,
			Result:                decision.Reason,
			IdempotencyKey:        firstNonEmpty(idempotencyKey, newID("idem")),
			TargetUID:             target.UID,
			TargetResourceVersion: k8sActionTargetResourceVersion(target),
			CommandHash:           k8sActionCommandHash(strings.TrimSpace(p.ClusterID), strings.TrimSpace(p.Namespace), strings.TrimSpace(p.ResourceKind), strings.TrimSpace(p.ResourceName), strings.TrimSpace(p.Action), p.Parameters),
		}
		if err := s.db.InsertK8sActionRequest(r.Context(), req); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.action.request", "", auditJSON(req))
		writeJSON(w, http.StatusCreated, map[string]any{"action": req, "decision": decision, "impact": impact})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sActionByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/actions/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "action id and command required", "invalid_request_error", "bad_action_path")
		return
	}
	id, command := parts[0], parts[1]
	var payload struct {
		Result string `json:"result"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	status := ""
	switch command {
	case "approve":
		status = "approved"
	case "reject":
		status = "rejected"
	case "execute":
		s.executeK8sAction(w, r, id)
		return
	default:
		writeOpenAIError(w, http.StatusBadRequest, "unsupported action command", "invalid_request_error", "unsupported_action_command")
		return
	}
	if err := s.db.UpdateK8sActionStatus(r.Context(), id, status, adminID(r), payload.Result); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "action request not found: "+id, "invalid_request_error", "action_not_found")
		return
	} else if errors.Is(err, store.ErrInvalidTransition) {
		writeOpenAIError(w, http.StatusConflict, "action cannot transition from current state", "invalid_request_error", "action_bad_state")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_update_failed")
		return
	}
	s.auditAdmin(r, "k8s.action."+command, "", auditJSON(map[string]string{"id": id, "status": status}))
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": status})
}

type k8sActionRunResult struct {
	ID              string
	Status          string
	Message         string
	HTTPStatus      int
	Err             error
	ErrorType       string
	ErrorCode       string
	ExecutionFailed bool
}

func k8sActionRunErr(httpStatus int, msg, errType, errCode string, err error) k8sActionRunResult {
	return k8sActionRunResult{HTTPStatus: httpStatus, Message: msg, ErrorType: errType, ErrorCode: errCode, Err: err}
}

func (s *Server) runApprovedK8sAction(ctx context.Context, actor string, act store.K8sActionRequest) k8sActionRunResult {
	if act.Status != "approved" {
		return k8sActionRunErr(http.StatusConflict, "action must be approved before execution (current: "+act.Status+")", "invalid_request_error", "action_not_approved", store.ErrInvalidTransition)
	}
	cluster, err := s.db.GetK8sCluster(ctx, act.ClusterID)
	if err != nil {
		return k8sActionRunErr(http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed", err)
	}
	client, err := s.k8sClientForCluster(ctx, cluster)
	if err != nil {
		return k8sActionRunErr(http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed", err)
	}
	exec, ok := client.(kube.Executor)
	if !ok {
		return k8sActionRunErr(http.StatusNotImplemented, "이 클러스터 클라이언트는 실행을 지원하지 않습니다.", "invalid_request_error", "executor_unsupported", errors.New("executor unsupported"))
	}
	if !k8sActionExecutable(act.Action) {
		return k8sActionRunErr(http.StatusBadRequest, "실행 가능한 액션이 아닙니다: "+act.Action+" (drain 등은 수동 처리)", "invalid_request_error", "action_not_executable", errors.New("action not executable"))
	}
	if err := s.db.UpdateK8sActionStatus(ctx, act.ID, "running", actor, "실행 중"); errors.Is(err, store.ErrInvalidTransition) {
		return k8sActionRunErr(http.StatusConflict, "action is already running or closed", "invalid_request_error", "action_bad_state", err)
	} else if errors.Is(err, store.ErrNotFound) {
		return k8sActionRunErr(http.StatusNotFound, "action request not found: "+act.ID, "invalid_request_error", "action_not_found", err)
	} else if err != nil {
		return k8sActionRunErr(http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_running_failed", err)
	}

	var execErr error
	switch strings.ToLower(act.Action) {
	case "scale":
		replicas := intFromParams(act.Parameters, "replicas", -1)
		if replicas < 0 {
			execErr = errors.New("scale 액션에 replicas 파라미터가 필요합니다")
		} else {
			execErr = exec.Scale(ctx, act.ResourceKind, act.Namespace, act.ResourceName, replicas)
		}
	case "rollout_restart":
		execErr = exec.RolloutRestart(ctx, act.ResourceKind, act.Namespace, act.ResourceName)
	case "cordon":
		execErr = exec.SetCordon(ctx, act.ResourceName, true)
	case "uncordon":
		execErr = exec.SetCordon(ctx, act.ResourceName, false)
	case "delete_pod":
		execErr = exec.DeletePod(ctx, act.Namespace, act.ResourceName)
	default:
		execErr = errors.New("실행 가능한 액션이 아닙니다: " + act.Action)
	}

	resultStatus, resultMsg := "executed", "실행 완료"
	if execErr != nil {
		resultStatus, resultMsg = "failed", "실행 실패: "+execErr.Error()
	}
	if err := s.db.UpdateK8sActionStatus(ctx, act.ID, resultStatus, actor, resultMsg); errors.Is(err, store.ErrInvalidTransition) {
		return k8sActionRunErr(http.StatusConflict, "action finalization was already applied", "invalid_request_error", "action_bad_state", err)
	} else if err != nil {
		return k8sActionRunErr(http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_finalize_failed", err)
	}
	if execErr != nil {
		return k8sActionRunResult{ID: act.ID, Status: resultStatus, Message: resultMsg, HTTPStatus: http.StatusBadGateway, Err: execErr, ExecutionFailed: true}
	}
	// Change-aware burst: collect this cluster at high frequency briefly so the change verifies fast.
	s.registerCollectBurst(ctx, act.ClusterID, act.Namespace, "action", "action:"+act.Action+" "+act.ResourceKind+"/"+act.ResourceName)
	return k8sActionRunResult{ID: act.ID, Status: resultStatus, Message: resultMsg, HTTPStatus: http.StatusOK}
}

// executeK8sAction runs an approved action against the live cluster (live executor). Only
// status=="approved" actions and an allowlisted set of operations are permitted; the result is
// recorded back on the request and audited.
func (s *Server) executeK8sAction(w http.ResponseWriter, r *http.Request, id string) {
	act, err := s.db.GetK8sActionRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "action request not found: "+id, "invalid_request_error", "action_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_failed")
		return
	}
	result := s.runApprovedK8sAction(r.Context(), adminID(r), act)
	if result.Err != nil && !result.ExecutionFailed {
		writeOpenAIError(w, result.HTTPStatus, result.Message, result.ErrorType, result.ErrorCode)
		return
	}
	s.auditAdmin(r, "k8s.action.execute", "", auditJSON(map[string]any{"id": id, "action": act.Action, "status": result.Status}))
	if result.ExecutionFailed {
		writeJSON(w, result.HTTPStatus, map[string]any{"id": id, "status": result.Status, "error": result.Message})
		return
	}
	writeJSON(w, result.HTTPStatus, map[string]any{"id": id, "status": result.Status, "result": result.Message})
}

func k8sActionExecutable(actionName string) bool {
	switch strings.ToLower(strings.TrimSpace(actionName)) {
	case "scale", "rollout_restart", "cordon", "uncordon", "delete_pod":
		return true
	default:
		return false
	}
}

func intFromParams(params map[string]any, key string, fallback int) int {
	if params == nil {
		return fallback
	}
	switch v := params[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

func k8sActionTargetResourceVersion(target store.K8sInventoryItem) string {
	for _, source := range []map[string]any{target.Spec, target.StatusObject} {
		if source == nil {
			continue
		}
		if v := strings.TrimSpace(k8sActionString(source["resourceVersion"])); v != "" {
			return v
		}
		if meta, ok := source["metadata"].(map[string]any); ok {
			if v := strings.TrimSpace(k8sActionString(meta["resourceVersion"])); v != "" {
				return v
			}
		}
	}
	return strings.TrimSpace(firstNonEmpty(target.ObservedAt, target.UpdatedAt))
}

func k8sActionCommandHash(clusterID, namespace, kind, name, actionName string, params map[string]any) string {
	payload := map[string]any{
		"cluster_id":    clusterID,
		"namespace":     namespace,
		"resource_kind": kind,
		"resource_name": name,
		"action":        actionName,
		"parameters":    k8sActionNonNilMap(params),
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func k8sActionNonNilMap(params map[string]any) map[string]any {
	if params == nil {
		return map[string]any{}
	}
	return params
}

func k8sActionString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	default:
		if t == nil {
			return ""
		}
		return strings.TrimSpace(strings.Trim(fmt.Sprint(t), `"`))
	}
}

func intParam(raw string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func floatParam(raw string, fallback float64) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return fallback
	}
	return f
}

func firstQuery(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
