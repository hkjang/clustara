package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

// K8s API Discovery + OpenAPI v3 Schema Registry (CLU-DISC-01/02/04/05/13).
//
// POST collects the cluster's aggregated discovery (resource catalog) + /openapi/v3 root (schema
// document index) and replaces the per-cluster registry. GET serves the cached registry + summary.

// handleK8sClusterDiscover collects + caches discovery for one cluster (called from the cluster path).
func (s *Server) handleK8sClusterDiscover(w http.ResponseWriter, r *http.Request, cluster store.K8sCluster) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	disc, ok := client.(kube.Discoverer)
	if !ok {
		writeOpenAIError(w, http.StatusNotImplemented, "이 클러스터 클라이언트는 discovery를 지원하지 않습니다.", "invalid_request_error", "discovery_unsupported")
		return
	}

	resources, docs, derr := s.collectClusterDiscovery(r, disc, cluster.ID)
	snap := store.K8sDiscoverySnapshot{ID: newID("k8sdisc"), ClusterID: cluster.ID, ResourceCount: len(resources), DocumentCount: len(docs), OK: derr == nil}
	if derr != nil {
		snap.Error = derr.Error()
	}
	_ = s.db.RecordK8sDiscoverySnapshot(r.Context(), snap)
	if derr != nil {
		writeOpenAIError(w, http.StatusBadGateway, "discovery 수집 실패: "+derr.Error(), "server_error", "discovery_failed")
		return
	}
	s.auditAdmin(r, "k8s.discovery.collect", cluster.ID, auditJSON(map[string]any{"resources": len(resources), "documents": len(docs)}))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "resources": len(resources), "documents": len(docs),
		"summary": analyzer.SummarizeDiscovery(toAPIResourceInfos(resources), toDocRefs(docs)),
	})
}

// collectClusterDiscovery fetches + parses + persists the resource catalog and OpenAPI index.
func (s *Server) collectClusterDiscovery(r *http.Request, disc kube.Discoverer, clusterID string) ([]store.K8sAPIResource, []store.K8sOpenAPIDocument, error) {
	apisBody, err := disc.RawGet(r.Context(), "/apis", kube.AggregatedDiscoveryAccept)
	if err != nil {
		return nil, nil, err
	}
	coreBody, err := disc.RawGet(r.Context(), "/api", kube.AggregatedDiscoveryAccept)
	if err != nil {
		return nil, nil, err
	}
	apiRes, err := analyzer.ParseAggregatedDiscovery(apisBody)
	if err != nil {
		return nil, nil, err
	}
	coreRes, _ := analyzer.ParseAggregatedDiscovery(coreBody)
	all := append(coreRes, apiRes...)

	resources := make([]store.K8sAPIResource, 0, len(all))
	for _, a := range all {
		resources = append(resources, store.K8sAPIResource{
			ClusterID: clusterID, GroupName: a.Group, Version: a.Version, Resource: a.Resource, Kind: a.Kind,
			Namespaced: a.Namespaced, Listable: a.Listable, Verbs: strings.Join(a.Verbs, ","),
			ShortNames: strings.Join(a.ShortNames, ","), Categories: strings.Join(a.Categories, ","),
			IsCRD: strings.Contains(a.Group, "."),
		})
	}
	if err := s.db.ReplaceK8sAPIResources(r.Context(), clusterID, resources); err != nil {
		return nil, nil, err
	}

	// OpenAPI v3 root index (best-effort: a missing /openapi/v3 shouldn't fail the whole discovery).
	docs := []store.K8sOpenAPIDocument{}
	if rootBody, oerr := disc.RawGet(r.Context(), "/openapi/v3", ""); oerr == nil {
		if refs, perr := analyzer.ParseOpenAPIV3Root(rootBody); perr == nil {
			for _, d := range refs {
				docs = append(docs, store.K8sOpenAPIDocument{
					ClusterID: clusterID, GroupVersion: d.GroupVersion, ServerRelativeURL: d.ServerRelativeURL, SchemaHash: d.Hash,
				})
			}
		}
	}
	_ = s.db.ReplaceK8sOpenAPIDocuments(r.Context(), clusterID, docs)
	return resources, docs, nil
}

// handleK8sDiscovery serves the cached discovery registry for a cluster.
// GET /admin/k8s/discovery?cluster_id=
func (s *Server) handleK8sDiscovery(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required", "invalid_request_error", "missing_cluster_id")
		return
	}
	resources, _ := s.db.ListK8sAPIResources(r.Context(), clusterID)
	docs, _ := s.db.ListK8sOpenAPIDocuments(r.Context(), clusterID)
	infos := toAPIResourceInfos(resources)
	targets := analyzer.SuggestInventoryTargets(infos)
	toolCandidates := analyzer.GenerateMCPToolCandidates(infos)
	snap, hasSnap, _ := s.db.LatestK8sDiscoverySnapshot(r.Context(), clusterID)
	now := time.Now().UTC()
	ageSecs := int64(-1)
	if hasSnap {
		if ts, ok := parseK8sHomeTime(snap.CollectedAt); ok {
			ageSecs = int64(now.Sub(ts).Seconds())
		}
	}
	// Activation state (CLU-NEXT-15/16): which targets/tools the operator has enabled.
	activeTargets := map[string]bool{}
	activeTools := map[string]bool{}
	if acts, aerr := s.db.ListK8sDiscoveryActivations(r.Context(), clusterID, ""); aerr == nil {
		for _, a := range acts {
			if a.Kind == "mcp_tool" {
				activeTools[a.Key] = a.Enabled
			} else {
				activeTargets[a.Key] = a.Enabled
			}
		}
	}
	targetViews := make([]map[string]any, 0, len(targets))
	for _, t := range targets {
		key := t.GroupVersion + "/" + t.Resource
		targetViews = append(targetViews, map[string]any{"target": t, "key": key, "activated": activeTargets[key]})
	}
	toolViews := make([]map[string]any, 0, len(toolCandidates))
	for _, c := range toolCandidates {
		toolViews = append(toolViews, map[string]any{"tool": c, "key": c.ToolName, "activated": activeTools[c.ToolName]})
	}

	resp := map[string]any{
		"resources":          resources,
		"documents":          docs,
		"summary":            analyzer.SummarizeDiscovery(infos, toDocRefs(docs)),
		"targets":            targets,
		"target_views":       targetViews,
		"tool_candidates":    toolCandidates,
		"tool_views":         toolViews,
		"targets_summary":    analyzer.SummarizeDiscoveryTargets(targets, toolCandidates),
		"deprecated":         analyzer.DetectDeprecatedAPIs(infos),
		"note":               "클러스터가 실제 제공하는 API resource 카탈로그·OpenAPI v3 스키마 인덱스와, 이를 기반으로 한 동적 수집 대상·read-only MCP 도구 후보입니다. 클러스터 상세에서 'API 탐색'으로 갱신하세요.",
		"collected_age_secs": ageSecs,
	}
	if hasSnap {
		resp["snapshot"] = snap
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleK8sDiscoveryActivate toggles activation of a discovered inventory target or MCP tool
// candidate (CLU-NEXT-15/16). The activated set is the operator-curated allow-list.
// POST /admin/k8s/discovery/activate {cluster_id, kind, key, enabled}
func (s *Server) handleK8sDiscoveryActivate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		ClusterID string `json:"cluster_id"`
		Kind      string `json:"kind"` // target | mcp_tool
		Key       string `json:"key"`
		Enabled   bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if strings.TrimSpace(in.ClusterID) == "" || strings.TrimSpace(in.Key) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id and key are required", "invalid_request_error", "missing_fields")
		return
	}
	kind := in.Kind
	if kind != "mcp_tool" {
		kind = "target"
	}
	if err := s.db.SetK8sDiscoveryActivation(r.Context(), store.K8sDiscoveryActivation{
		ClusterID: in.ClusterID, Kind: kind, Key: in.Key, Enabled: in.Enabled, UpdatedBy: adminID(r),
	}); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "activation_failed")
		return
	}
	s.auditAdmin(r, "k8s.discovery.activate", in.ClusterID, auditJSON(map[string]any{"kind": kind, "key": in.Key, "enabled": in.Enabled}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "kind": kind, "key": in.Key, "enabled": in.Enabled,
		"note": "활성화 상태가 저장되었습니다. 실제 수집(collector)·MCP 게이트웨이 등록 enforcement는 다음 배선 단계입니다."})
}

// handleK8sDiscoveryCompare diffs two clusters' API catalogs (CLU-DISC-12 — upgrade/cross-cluster).
// GET /admin/k8s/discovery/compare?from=<cluster>&to=<cluster>
func (s *Server) handleK8sDiscoveryCompare(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	from := strings.TrimSpace(r.URL.Query().Get("from"))
	to := strings.TrimSpace(r.URL.Query().Get("to"))
	if from == "" || to == "" {
		writeOpenAIError(w, http.StatusBadRequest, "from and to cluster_id are required", "invalid_request_error", "missing_clusters")
		return
	}
	fromRes, _ := s.db.ListK8sAPIResources(r.Context(), from)
	toRes, _ := s.db.ListK8sAPIResources(r.Context(), to)
	diff := analyzer.DiffAPICatalogs(toAPIResourceInfos(fromRes), toAPIResourceInfos(toRes))
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "diff": diff,
		"note": "두 클러스터(또는 업그레이드 전후 스냅샷)의 API 카탈로그 차이입니다. removed는 사라진 resource/GV, changed는 verb 집합 변경입니다.",
	})
}

// toAPIResourceInfos / toDocRefs map stored rows back to analyzer types for summarization.
func toAPIResourceInfos(rows []store.K8sAPIResource) []analyzer.APIResourceInfo {
	out := make([]analyzer.APIResourceInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, analyzer.APIResourceInfo{
			Group: r.GroupName, Version: r.Version, Resource: r.Resource, Kind: r.Kind,
			Namespaced: r.Namespaced, Listable: r.Listable, Verbs: splitCSV(r.Verbs),
			ShortNames: splitCSV(r.ShortNames), Categories: splitCSV(r.Categories),
		})
	}
	return out
}

func toDocRefs(rows []store.K8sOpenAPIDocument) []analyzer.OpenAPIDocRef {
	out := make([]analyzer.OpenAPIDocRef, 0, len(rows))
	for _, d := range rows {
		out = append(out, analyzer.OpenAPIDocRef{GroupVersion: d.GroupVersion, ServerRelativeURL: d.ServerRelativeURL, Hash: d.SchemaHash})
	}
	return out
}
