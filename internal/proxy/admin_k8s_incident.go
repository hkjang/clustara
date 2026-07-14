package proxy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sIncidents lists incidents, or (POST /scan) evaluates current high/critical RCA and
// opens/refreshes incidents. GET/POST /admin/k8s/incidents
func (s *Server) handleK8sIncidents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		incs, err := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{
			ClusterID: q.Get("cluster_id"), Status: q.Get("status"), Limit: intParam(q.Get("limit"), 100),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_incidents_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"incidents": incs, "count": len(incs)})
	case http.MethodPost:
		s.scanK8sIncidents(w, r)
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// scanK8sIncidents builds incidents from current high/critical RCA candidates and upserts them.
// POST /admin/k8s/incidents  (or /incidents/scan)
func (s *Server) scanK8sIncidents(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	opened, updated, evaluated, err := s.scanK8sIncidentsForCluster(r.Context(), clusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	s.auditAdmin(r, "k8s.incident.scan", "", auditJSON(map[string]any{"cluster_id": clusterID, "opened": opened, "updated": updated}))
	writeJSON(w, http.StatusOK, map[string]any{"opened": opened, "updated": updated, "evaluated": evaluated})
}

func (s *Server) scanK8sIncidentsForCluster(ctx context.Context, clusterID string) (opened, updated, evaluated int, err error) {
	items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
	if err != nil {
		return 0, 0, 0, err
	}
	events, _ := s.db.ListK8sEvents(ctx, clusterID, 1000)
	revisions, _ := s.db.ListK8sRevisions(ctx, store.K8sRevisionFilter{ClusterID: clusterID, Limit: 2000})
	rca := analyzer.EnrichWithConfigChanges(analyzer.AnalyzeRCA(items, events), revisions, time.Now().UTC(), 24*time.Hour)
	ownerByPod := k8sPodOwnerIndex(items)
	rca = filterBatchPodFindings(rca, ownerByPod)
	drafts := analyzer.BuildIncidents(items, rca, events)
	metrics, _ := s.db.ListK8sMetricSamplesFiltered(ctx, store.K8sMetricSampleFilter{ClusterID: clusterID, Since: time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano), Limit: 100000})
	metricDrafts := analyzer.BuildMetricRiskIncidents(items, metrics, events, time.Now().UTC())
	metricDrafts = filterBatchPodIncidentDrafts(metricDrafts, ownerByPod)
	drafts = append(drafts, metricDrafts...)

	// Restart storms (POD-RULE-06): a service-wide restart wave opens one workload incident.
	stormPods := []analyzer.RestartStormPod{}
	for _, it := range items {
		if it.Kind != "Pod" {
			continue
		}
		pv := podView(it, events, false)
		stormPods = append(stormPods, analyzer.RestartStormPod{
			Namespace: pv.Namespace, Name: pv.Name, OwnerKind: pv.OwnerKind, OwnerName: pv.OwnerName,
			RestartCount: pv.RestartCount, RecentRestartCount: pv.RecentRestartCount, RestartRecencyKnown: true,
			Unhealthy: pv.HealthBand == "critical",
		})
	}
	storms := analyzer.DetectRestartStorms(stormPods, analyzer.RestartStormOptions{})
	drafts = append(drafts, analyzer.BuildRestartStormIncidents(storms, clusterID)...)

	for _, d := range drafts {
		_, isNew, err := s.db.UpsertK8sIncidentByKey(ctx, store.K8sIncident{
			DedupKey: d.Key, ClusterID: d.ClusterID, Namespace: d.Namespace, Kind: d.Kind, Name: d.Name,
			Condition: d.Condition, Severity: d.Severity, Title: d.Title, Evidence: d.Evidence,
		}, newID)
		if err != nil {
			continue
		}
		if isNew {
			opened++
		} else {
			updated++
		}
	}
	activePredictive := map[string]bool{}
	for _, d := range metricDrafts {
		activePredictive[d.Key] = true
	}
	_, _ = s.db.ResolveOpenK8sIncidentsByKeyPrefix(ctx, clusterID, "predictive:", activePredictive)
	// Migration cleanup: older scans could open service-style RestartStorm incidents for
	// finite Job attempts. Resolve those now that batch outcomes are owned by Job/CronJob rules.
	if existing, listErr := s.db.ListK8sIncidents(ctx, store.K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 500}); listErr == nil {
		for _, incident := range existing {
			if incident.Condition == "RestartStorm" && (strings.EqualFold(incident.Kind, "Job") || strings.EqualFold(incident.Kind, "CronJob")) {
				_ = s.db.ResolveK8sIncident(ctx, incident.ID)
			}
		}
	}
	return opened, updated, len(drafts), nil
}

// handleK8sIncidentByID returns an incident with related actions, or resolves it.
// GET /admin/k8s/incidents/{id}  ·  POST /admin/k8s/incidents/{id}/resolve
func (s *Server) handleK8sIncidentByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/incidents/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" || id == "scan" {
		writeOpenAIError(w, http.StatusBadRequest, "incident id required", "invalid_request_error", "missing_incident_id")
		return
	}
	if len(parts) > 1 && parts[1] == "resolve" {
		if r.Method != http.MethodPost {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		if err := s.db.ResolveK8sIncident(r.Context(), id); errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "open incident not found: "+id, "invalid_request_error", "incident_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_incident_resolve_failed")
			return
		}
		s.auditAdmin(r, "k8s.incident.resolve", "", auditJSON(map[string]string{"id": id}))
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "resolved"})
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	inc, err := s.db.GetK8sIncident(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "incident not found: "+id, "invalid_request_error", "incident_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_incident_failed")
		return
	}
	// Related action requests for the same resource (the workspace's 조치 탭).
	related := []store.K8sActionRequest{}
	if acts, aerr := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: inc.ClusterID, Limit: 200}); aerr == nil {
		for _, a := range acts {
			if a.ResourceName == inc.Name && strings.EqualFold(a.ResourceKind, inc.Kind) && (inc.Namespace == "" || a.Namespace == inc.Namespace) {
				related = append(related, a)
			}
		}
	}
	relatedEvents := []store.K8sEvent{}
	if events, eerr := s.db.ListK8sEvents(r.Context(), inc.ClusterID, 500); eerr == nil {
		for _, e := range events {
			if k8sEventMatchesIncident(inc, e) {
				relatedEvents = append(relatedEvents, e)
				if len(relatedEvents) >= 20 {
					break
				}
			}
		}
	}
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{
		ClusterID: inc.ClusterID, Kind: inc.Kind, Namespace: inc.Namespace, Name: inc.Name, Limit: 8,
	})
	relatedFindings := []store.K8sSecurityFinding{}
	if findings, ferr := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{ClusterID: inc.ClusterID, Status: "open", Limit: 500}); ferr == nil {
		for _, f := range findings {
			if k8sFindingMatchesIncident(inc, f) {
				relatedFindings = append(relatedFindings, f)
				if len(relatedFindings) >= 20 {
					break
				}
			}
		}
	}
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: inc.ClusterID, Limit: 5000})
	owners, _ := s.db.ListK8sNamespaceOwnership(r.Context(), inc.ClusterID, "")
	graph := analyzer.BuildResourceGraph(items, owners, analyzer.ResourceGraphFocus{
		ClusterID: inc.ClusterID, Kind: inc.Kind, Namespace: inc.Namespace, Name: inc.Name, Radius: 2,
	})
	confidence := analyzer.ScoreIncidentConfidence(analyzer.ConfidenceInput{
		Severity: inc.Severity, OpenedAt: inc.OpenedAt,
		Events: relatedEvents, Revisions: revisions, Findings: relatedFindings,
		EvidenceCount: len(inc.Evidence), ImpactCount: graph.Impact.NodeCount, Now: time.Now().UTC(),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"incident": inc, "actions": related, "events": relatedEvents, "revisions": revisions,
		"findings": relatedFindings, "graph": graph, "impact": graph.Impact, "confidence": confidence,
		"response_plan": predictiveIncidentResponsePlan(inc),
	})
}

func predictiveIncidentResponsePlan(inc store.K8sIncident) map[string]any {
	predictive := strings.HasPrefix(inc.DedupKey, "predictive:")
	checks := []string{"최근 메트릭과 Kubernetes 상태·Warning 이벤트의 시각을 대조", "최근 배포·설정·노드 변경과 위험 상승 시점을 비교", "영향도 그래프에서 상위 서비스와 인접 Pod·Node 범위 확인"}
	preparations := []string{"담당자와 관찰 주기를 지정하고 워룸 Incident를 유지", "승인형 완화 조치의 실행 조건과 롤백 기준을 사전 확인"}
	recovery := []string{"위험 신호가 연속 3회 정상 범위인지 확인", "Ready·재시작·Warning과 사용자 영향이 함께 회복됐는지 검증"}
	switch inc.Condition {
	case "PodMemorySaturation", "PredictedMemoryExhaustion":
		checks = append(checks, "working set 증가율, memory limit, OOMKilled와 캐시·누수 패턴 확인")
		preparations = append(preparations, "안전한 scale-out 또는 memory limit 조정 변경안을 미리 검증")
	case "PodCPUSaturation", "PredictedCPUExhaustion":
		checks = append(checks, "CPU throttling, 요청 지연, HPA 목표·최대 replica 확인")
		preparations = append(preparations, "HPA/replica 확장 또는 CPU limit 조정의 용량·비용 영향 확인")
	case "NodeResourceRisk", "PredictedCapacityExhaustion":
		checks = append(checks, "Node Pressure, allocatable 대비 사용량, 상위 소비 Pod와 PDB 확인")
		preparations = append(preparations, "대체 노드 용량과 cordon/drain 승인 경로 및 PDB 차단 여부 확인")
	case "PodGPURisk":
		checks = append(checks, "DCGM 온도·XID·ECC·VRAM과 동일 노드의 GPU Pod 경합 확인")
		preparations = append(preparations, "대체 GPU 노드와 체크포인트·재스케줄 가능 여부 확인")
	}
	stage := "detected"
	if predictive {
		stage = "preventive_observation"
	}
	return map[string]any{"stage": stage, "checks": checks, "preparations": preparations, "recovery_criteria": recovery, "auto_resolve": predictive}
}

func k8sEventMatchesIncident(inc store.K8sIncident, e store.K8sEvent) bool {
	if e.ClusterID != inc.ClusterID || e.Namespace != inc.Namespace {
		return false
	}
	if strings.EqualFold(e.InvolvedKind, inc.Kind) && e.InvolvedName == inc.Name {
		return true
	}
	if strings.EqualFold(e.InvolvedKind, "Pod") && inc.Kind != "Pod" {
		return strings.HasPrefix(e.InvolvedName, inc.Name+"-")
	}
	return false
}

func k8sFindingMatchesIncident(inc store.K8sIncident, f store.K8sSecurityFinding) bool {
	return f.ClusterID == inc.ClusterID &&
		f.Namespace == inc.Namespace &&
		strings.EqualFold(f.ResourceKind, inc.Kind) &&
		f.ResourceName == inc.Name
}
