package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

type catalogRuntimeRef struct {
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

func (s *Server) handleCatalogScorecards(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	entities, err := s.db.ListCatalogEntities(r.Context(), store.CatalogEntityFilter{
		Kind:        strings.TrimSpace(r.URL.Query().Get("kind")),
		OwnerTeamID: strings.TrimSpace(r.URL.Query().Get("owner_team_id")),
		Limit:       intParam(r.URL.Query().Get("limit"), 1000),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_scorecard_failed")
		return
	}
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 500})
	findings, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{ClusterID: clusterID, Status: "open", Limit: 500})
	projects, _ := s.db.ListEnterpriseProjects(r.Context(), store.EnterpriseProjectFilter{})
	projectByID := map[string]store.EnterpriseProject{}
	for _, p := range projects {
		projectByID[p.ID] = p
	}
	rows := make([]map[string]any, 0, len(entities))
	summary := map[string]int{"gold": 0, "silver": 0, "bronze": 0, "at_risk": 0}
	for _, entity := range entities {
		rt, ok := parseCatalogRuntimeRef(entity.RuntimeRef)
		if clusterID != "" && (!ok || rt.ClusterID != clusterID) {
			continue
		}
		row := buildCatalogScorecard(entity, projectByID[entity.ProjectID], rt, ok, incidents, findings)
		if m, _ := row["maturity"].(string); m != "" {
			summary[strings.ToLower(strings.ReplaceAll(m, " ", "_"))]++
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "catalog_scorecard", "*", map[string]any{
		"scorecards": rows,
		"summary":    summary,
		"count":      len(rows),
	}))
}

func (s *Server) handleCatalogEntityRuntime(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/catalog/entities/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "runtime" {
		writeOpenAIError(w, http.StatusNotFound, "catalog runtime route not found", "invalid_request_error", "not_found")
		return
	}
	entityID := strings.TrimSpace(parts[0])
	entities, err := s.db.ListCatalogEntities(r.Context(), store.CatalogEntityFilter{Limit: 2000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_runtime_failed")
		return
	}
	var entity store.CatalogEntity
	found := false
	for _, e := range entities {
		if e.ID == entityID {
			entity = e
			found = true
			break
		}
	}
	if !found {
		writeOpenAIError(w, http.StatusNotFound, "catalog entity not found", "invalid_request_error", "not_found")
		return
	}
	rt, hasRuntime := parseCatalogRuntimeRef(entity.RuntimeRef)
	inventory := []store.K8sInventoryItem{}
	incidents := []store.K8sIncident{}
	findings := []store.K8sSecurityFinding{}
	actions := []store.K8sActionRequest{}
	if hasRuntime {
		items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: rt.ClusterID, Namespace: rt.Namespace, Limit: 1000})
		for _, it := range items {
			if catalogRuntimeItemMatches(rt, it) {
				inventory = append(inventory, it)
			}
		}
		incRows, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: rt.ClusterID, Status: "open", Limit: 500})
		for _, inc := range incRows {
			if catalogIncidentMatches(rt, inc) {
				incidents = append(incidents, inc)
			}
		}
		findingRows, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{ClusterID: rt.ClusterID, Status: "open", Limit: 500})
		for _, f := range findingRows {
			if catalogFindingMatches(rt, f) {
				findings = append(findings, f)
			}
		}
		actionRows, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: rt.ClusterID, Limit: 500})
		for _, a := range actionRows {
			if a.Namespace == rt.Namespace && strings.EqualFold(a.ResourceKind, rt.Kind) && a.ResourceName == rt.Name {
				actions = append(actions, a)
			}
		}
	}
	selfService, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{
		Kind:      "catalog_self_service_action",
		ScopeType: "catalog_entity",
		ScopeID:   entity.ID,
		Limit:     100,
	})
	projects, _ := s.db.ListEnterpriseProjects(r.Context(), store.EnterpriseProjectFilter{})
	var project store.EnterpriseProject
	for _, p := range projects {
		if p.ID == entity.ProjectID {
			project = p
			break
		}
	}
	score := buildCatalogScorecard(entity, project, rt, hasRuntime, incidents, findings)
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "catalog_entity", entity.ID, map[string]any{
		"entity":               entity,
		"project":              project,
		"runtime":              rt,
		"runtime_valid":        hasRuntime,
		"scorecard":            score,
		"inventory":            inventory,
		"open_incidents":       incidents,
		"security_findings":    findings,
		"k8s_actions":          actions,
		"self_service_actions": selfService,
		"summary": map[string]any{
			"inventory":            len(inventory),
			"open_incidents":       len(incidents),
			"security_findings":    len(findings),
			"k8s_actions":          len(actions),
			"self_service_actions": len(selfService),
		},
	}))
}

func (s *Server) handleCatalogRuntimeCandidates(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Namespace: namespace, Limit: intParam(r.URL.Query().Get("limit"), 2000)})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_runtime_candidates_failed")
		return
	}
	entities, _ := s.db.ListCatalogEntities(r.Context(), store.CatalogEntityFilter{Limit: 2000})
	owners, _ := s.db.ListK8sNamespaceOwnership(r.Context(), clusterID, "")
	projects, _ := s.db.ListEnterpriseProjects(r.Context(), store.EnterpriseProjectFilter{})
	ownerByNS := map[string]store.K8sNamespaceOwnership{}
	for _, owner := range owners {
		ownerByNS[owner.ClusterID+"/"+owner.Namespace] = owner
	}
	covered := map[string]bool{}
	for _, entity := range entities {
		rt, ok := parseCatalogRuntimeRef(entity.RuntimeRef)
		if !ok {
			continue
		}
		covered[rt.ClusterID+"/"+rt.Namespace+"/"+rt.Kind+"/"+rt.Name] = true
	}
	kinds := map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Service": true, "Ingress": true, "Job": true, "CronJob": true}
	candidates := []map[string]any{}
	for _, it := range items {
		if !kinds[it.Kind] || it.Namespace == "" {
			continue
		}
		ref := it.ClusterID + "/" + it.Namespace + "/" + it.Kind + "/" + it.Name
		if covered[ref] {
			continue
		}
		owner := ownerByNS[it.ClusterID+"/"+it.Namespace]
		suggestedKind := "Service"
		if it.Kind == "Job" || it.Kind == "CronJob" {
			suggestedKind = "Job"
		}
		suggestedName := catalogSuggestedName(it, owner)
		confidence := 60
		reasons := []string{"runtime_ref is not linked to catalog"}
		if owner.Team != "" {
			confidence += 15
			reasons = append(reasons, "namespace ownership has team")
		}
		if owner.ServiceName != "" {
			confidence += 15
			reasons = append(reasons, "namespace ownership has service name")
		}
		if it.Kind == "Deployment" || it.Kind == "StatefulSet" {
			confidence += 5
			reasons = append(reasons, "workload controller")
		}
		suggestedTeamID, suggestedTeamName := s.catalogSuggestedTeam(r, owner.Team)
		suggestedProject := catalogSuggestedProject(projects, suggestedTeamID, it.Namespace)
		if suggestedProject.ID != "" {
			confidence += 5
			reasons = append(reasons, "project matched by team/environment")
		}
		if confidence > 95 {
			confidence = 95
		}
		candidates = append(candidates, map[string]any{
			"cluster_id":            it.ClusterID,
			"namespace":             it.Namespace,
			"kind":                  it.Kind,
			"name":                  it.Name,
			"runtime_ref":           ref,
			"status":                it.Status,
			"risk_level":            it.RiskLevel,
			"health_score":          it.HealthScore,
			"owner":                 owner,
			"suggested_kind":        suggestedKind,
			"suggested_name":        suggestedName,
			"suggested_team":        suggestedTeamName,
			"suggested_team_id":     suggestedTeamID,
			"suggested_project_id":  suggestedProject.ID,
			"suggested_project":     suggestedProject.Name,
			"suggested_environment": suggestedProject.Environment,
			"suggested_owner":       owner.Owner,
			"suggested_criticality": firstNonEmptyStr(owner.Criticality, it.RiskLevel),
			"suggested_tags":        []string{strings.ToLower(it.Kind), it.Namespace},
			"confidence":            confidence,
			"reasons":               reasons,
		})
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "catalog_runtime_candidate", "*", map[string]any{
		"candidates": candidates,
		"count":      len(candidates),
	}))
}

func (s *Server) handleCatalogCoverage(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: intParam(r.URL.Query().Get("limit"), 10000)})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_coverage_failed")
		return
	}
	entities, _ := s.db.ListCatalogEntities(r.Context(), store.CatalogEntityFilter{Limit: 5000})
	coveredByRef := map[string]store.CatalogEntity{}
	for _, entity := range entities {
		rt, ok := parseCatalogRuntimeRef(entity.RuntimeRef)
		if !ok {
			continue
		}
		if clusterID != "" && rt.ClusterID != clusterID {
			continue
		}
		coveredByRef[rt.ClusterID+"/"+rt.Namespace+"/"+rt.Kind+"/"+rt.Name] = entity
	}
	owners, _ := s.db.ListK8sNamespaceOwnership(r.Context(), clusterID, "")
	ownerByNS := map[string]store.K8sNamespaceOwnership{}
	for _, owner := range owners {
		ownerByNS[owner.ClusterID+"/"+owner.Namespace] = owner
	}
	type coverageBucket struct {
		ClusterID   string `json:"cluster_id"`
		Namespace   string `json:"namespace"`
		Kind        string `json:"kind"`
		Team        string `json:"team"`
		Total       int    `json:"total"`
		Linked      int    `json:"linked"`
		Unlinked    int    `json:"unlinked"`
		HighRisk    int    `json:"high_risk"`
		CoveragePct int    `json:"coverage_pct"`
	}
	bucketByKey := map[string]*coverageBucket{}
	total, linked, highRisk := 0, 0, 0
	for _, it := range items {
		if !catalogRuntimeCandidateKind(it.Kind) || it.Namespace == "" {
			continue
		}
		ref := it.ClusterID + "/" + it.Namespace + "/" + it.Kind + "/" + it.Name
		owner := ownerByNS[it.ClusterID+"/"+it.Namespace]
		key := it.ClusterID + "/" + it.Namespace + "/" + it.Kind
		bucket := bucketByKey[key]
		if bucket == nil {
			bucket = &coverageBucket{ClusterID: it.ClusterID, Namespace: it.Namespace, Kind: it.Kind, Team: owner.Team}
			bucketByKey[key] = bucket
		}
		total++
		bucket.Total++
		if _, ok := coveredByRef[ref]; ok {
			linked++
			bucket.Linked++
		} else {
			bucket.Unlinked++
		}
		if strings.EqualFold(it.RiskLevel, "high") || strings.EqualFold(it.RiskLevel, "critical") {
			highRisk++
			bucket.HighRisk++
		}
	}
	buckets := []coverageBucket{}
	for _, bucket := range bucketByKey {
		if bucket.Total > 0 {
			bucket.CoveragePct = int(float64(bucket.Linked) / float64(bucket.Total) * 100)
		}
		buckets = append(buckets, *bucket)
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].CoveragePct == buckets[j].CoveragePct {
			return buckets[i].Unlinked > buckets[j].Unlinked
		}
		return buckets[i].CoveragePct < buckets[j].CoveragePct
	})
	coveragePct := 0
	if total > 0 {
		coveragePct = int(float64(linked) / float64(total) * 100)
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "catalog_coverage", "*", map[string]any{
		"summary": map[string]any{
			"total_runtime":    total,
			"linked_runtime":   linked,
			"unlinked_runtime": total - linked,
			"high_risk":        highRisk,
			"coverage_pct":     coveragePct,
		},
		"buckets": buckets,
		"count":   len(buckets),
	}))
}

func (s *Server) handleCatalogGaps(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	includeExceptions := strings.EqualFold(r.URL.Query().Get("include_exceptions"), "1") || strings.EqualFold(r.URL.Query().Get("include_exceptions"), "true")
	limit := intParam(r.URL.Query().Get("limit"), 200)
	entities, err := s.db.ListCatalogEntities(r.Context(), store.CatalogEntityFilter{Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_gaps_failed")
		return
	}
	projects, _ := s.db.ListEnterpriseProjects(r.Context(), store.EnterpriseProjectFilter{})
	projectByID := map[string]store.EnterpriseProject{}
	for _, p := range projects {
		projectByID[p.ID] = p
	}
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 500})
	findings, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{ClusterID: clusterID, Status: "open", Limit: 500})
	exceptionRows, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: "catalog_gap_exception", Limit: 1000})
	exceptions := activeCatalogGapExceptions(exceptionRows, time.Now().UTC())
	suppressed := []map[string]any{}
	gaps := []map[string]any{}
	addGap := func(severity, gapType, target, message, recommendation string, entity store.CatalogEntity, runtime catalogRuntimeRef) {
		gapKey := catalogGapKey(gapType, firstNonEmptyStr(entity.ID, target))
		gap := map[string]any{
			"gap_key":        gapKey,
			"severity":       severity,
			"type":           gapType,
			"target":         target,
			"message":        message,
			"recommendation": recommendation,
			"entity_id":      entity.ID,
			"entity_name":    entity.Name,
			"owner_team_id":  entity.OwnerTeamID,
			"project_id":     entity.ProjectID,
			"runtime_ref":    entity.RuntimeRef,
			"runtime":        runtime,
		}
		if ex, ok := exceptions[gapKey]; ok {
			gap["exception"] = ex
			suppressed = append(suppressed, gap)
			if !includeExceptions {
				return
			}
		}
		gaps = append(gaps, gap)
	}
	covered := map[string]bool{}
	for _, entity := range entities {
		rt, hasRuntime := parseCatalogRuntimeRef(entity.RuntimeRef)
		if clusterID != "" && hasRuntime && rt.ClusterID != clusterID {
			continue
		}
		if hasRuntime {
			covered[rt.ClusterID+"/"+rt.Namespace+"/"+rt.Kind+"/"+rt.Name] = true
		}
		if entity.OwnerTeamID == "" {
			addGap("high", "missing_owner", entity.Name, "서비스 owner_team_id가 비어 있습니다", "팀 소유권을 지정하세요", entity, rt)
		}
		if entity.ProjectID == "" {
			addGap("high", "missing_project", entity.Name, "서비스 project_id가 비어 있습니다", "프로젝트와 cost center 범위를 연결하세요", entity, rt)
		}
		if !hasRuntime {
			addGap("high", "missing_runtime", entity.Name, "runtime_ref가 없거나 형식이 올바르지 않습니다", "cluster/namespace/kind/name 형식으로 runtime_ref를 연결하세요", entity, rt)
		}
		project := projectByID[entity.ProjectID]
		if project.Environment == "prod" && entity.Criticality == "" && project.Criticality == "" {
			addGap("medium", "missing_criticality", entity.Name, "prod 서비스 criticality가 비어 있습니다", "criticality를 지정하세요", entity, rt)
		}
		if entity.RepoURL == "" {
			addGap("medium", "missing_repo", entity.Name, "repo_url이 비어 있습니다", "서비스 Git repository를 연결하세요", entity, rt)
		}
		if entity.DocsURL == "" {
			addGap("medium", "missing_docs", entity.Name, "docs_url이 비어 있습니다", "runbook 또는 운영 문서를 연결하세요", entity, rt)
		}
		score := buildCatalogScorecard(entity, project, rt, hasRuntime, incidents, findings)
		if s, _ := score["score"].(int); s > 0 && s < 55 {
			addGap("high", "low_score", entity.Name, "서비스 운영 score가 낮습니다", "scorecard 권고를 먼저 처리하세요", entity, rt)
		}
	}
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	for _, it := range items {
		if !catalogRuntimeCandidateKind(it.Kind) || it.Namespace == "" {
			continue
		}
		ref := it.ClusterID + "/" + it.Namespace + "/" + it.Kind + "/" + it.Name
		if covered[ref] {
			continue
		}
		severity := "medium"
		if strings.EqualFold(it.RiskLevel, "high") || strings.EqualFold(it.RiskLevel, "critical") {
			severity = "high"
		}
		gapKey := catalogGapKey("unlinked_runtime", ref)
		gap := map[string]any{
			"gap_key":        gapKey,
			"severity":       severity,
			"type":           "unlinked_runtime",
			"target":         ref,
			"message":        "Kubernetes runtime이 service catalog에 연결되어 있지 않습니다",
			"recommendation": "Runtime 연결 후보에서 catalog entity로 등록하세요",
			"cluster_id":     it.ClusterID,
			"namespace":      it.Namespace,
			"kind":           it.Kind,
			"name":           it.Name,
			"risk_level":     it.RiskLevel,
			"health_score":   it.HealthScore,
			"runtime_ref":    ref,
		}
		if ex, ok := exceptions[gapKey]; ok {
			gap["exception"] = ex
			suppressed = append(suppressed, gap)
			if !includeExceptions {
				continue
			}
		}
		gaps = append(gaps, gap)
	}
	sort.Slice(gaps, func(i, j int) bool {
		if catalogGapRank(toString(gaps[i]["severity"])) == catalogGapRank(toString(gaps[j]["severity"])) {
			return toString(gaps[i]["type"]) < toString(gaps[j]["type"])
		}
		return catalogGapRank(toString(gaps[i]["severity"])) > catalogGapRank(toString(gaps[j]["severity"]))
	})
	if len(gaps) > limit {
		gaps = gaps[:limit]
	}
	summary := map[string]int{"high": 0, "medium": 0, "low": 0}
	types := map[string]int{}
	for _, gap := range gaps {
		sev := toString(gap["severity"])
		if sev == "" {
			sev = "low"
		}
		summary[sev]++
		types[toString(gap["type"])]++
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "catalog_gap", "*", map[string]any{
		"gaps":             gaps,
		"suppressed":       suppressed,
		"suppressed_count": len(suppressed),
		"summary":          summary,
		"types":            types,
		"count":            len(gaps),
	}))
}

func (s *Server) handleCatalogGapExceptions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "catalog_gap_exception")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "catalog_gap_exception", "*", map[string]any{
			"exceptions": rows,
			"count":      len(rows),
		}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "catalog_gap_exception", "active", "catalog.gap_exception.upsert")
		if !ok {
			return
		}
		if rec.ScopeType == "" {
			rec.ScopeType = "catalog_gap"
		}
		if rec.ScopeID == "" {
			rec.ScopeID = toString(rec.Payload["gap_key"])
		}
		if rec.Name == "" {
			rec.Name = "Catalog gap exception"
		}
		if rec.Payload == nil {
			rec.Payload = map[string]any{}
		}
		if rec.Payload["gap_key"] == nil {
			rec.Payload["gap_key"] = rec.ScopeID
		}
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_gap_exception_save_failed")
			return
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "catalog_gap_exception", rec.ID, map[string]any{"exception": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) catalogSuggestedTeam(r *http.Request, team string) (string, string) {
	team = strings.TrimSpace(team)
	if team == "" {
		return "", ""
	}
	row, found, err := s.db.AuthTeamByIDOrName(r.Context(), team)
	if err == nil && found {
		return row.ID, firstNonEmptyStr(row.Name, row.ID)
	}
	return "", team
}

func catalogGapKey(gapType, target string) string {
	return strings.ToLower(strings.TrimSpace(gapType)) + "|" + strings.TrimSpace(target)
}

func activeCatalogGapExceptions(rows []store.EnterpriseRecord, now time.Time) map[string]store.EnterpriseRecord {
	out := map[string]store.EnterpriseRecord{}
	for _, rec := range rows {
		status := strings.ToLower(strings.TrimSpace(rec.Status))
		if status != "" && status != "active" && status != "approved" {
			continue
		}
		expires := strings.TrimSpace(toString(rec.Payload["expires_at"]))
		if expires != "" {
			if ts, err := time.Parse(time.RFC3339Nano, expires); err == nil && !ts.After(now) {
				continue
			}
		}
		key := strings.TrimSpace(toString(rec.Payload["gap_key"]))
		if key == "" {
			key = strings.TrimSpace(rec.ScopeID)
		}
		if key != "" {
			out[key] = rec
		}
	}
	return out
}

func catalogGapExceptionStats(rows []store.EnterpriseRecord, now time.Time) map[string]int {
	stats := map[string]int{"total": len(rows), "active": 0, "expired": 0, "expiring_soon": 0, "inactive": 0}
	for _, rec := range rows {
		status := strings.ToLower(strings.TrimSpace(rec.Status))
		if status != "" && status != "active" && status != "approved" {
			if status == "expired" {
				stats["expired"]++
			} else {
				stats["inactive"]++
			}
			continue
		}
		expires := strings.TrimSpace(toString(rec.Payload["expires_at"]))
		if expires != "" {
			if ts, err := time.Parse(time.RFC3339Nano, expires); err == nil {
				if !ts.After(now) {
					stats["expired"]++
					continue
				}
				if ts.Sub(now) <= 14*24*time.Hour {
					stats["expiring_soon"]++
				}
			}
		}
		stats["active"]++
	}
	return stats
}

func catalogGapRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return 3
	case "medium", "warn":
		return 2
	default:
		return 1
	}
}

func catalogRuntimeCandidateKind(kind string) bool {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Service", "Ingress", "Job", "CronJob":
		return true
	default:
		return false
	}
}

func catalogSuggestedProject(projects []store.EnterpriseProject, teamID, namespace string) store.EnterpriseProject {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	var fallback store.EnterpriseProject
	for _, project := range projects {
		if teamID != "" && project.OwnerTeamID != teamID {
			continue
		}
		if fallback.ID == "" {
			fallback = project
		}
		env := strings.ToLower(strings.TrimSpace(project.Environment))
		if env != "" && (namespace == env || strings.Contains(namespace, env)) {
			return project
		}
	}
	return fallback
}

func catalogSuggestedName(it store.K8sInventoryItem, owner store.K8sNamespaceOwnership) string {
	if it.Labels != nil {
		for _, key := range []string{"app.kubernetes.io/name", "app", "service", "app.kubernetes.io/instance"} {
			if value := strings.TrimSpace(it.Labels[key]); value != "" {
				return value
			}
		}
	}
	return firstNonEmptyStr(owner.ServiceName, it.Name)
}

func (s *Server) handleCatalogSelfServiceActions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "catalog_self_service_action")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "catalog_self_service_action", "*", map[string]any{
			"actions": rows,
			"count":   len(rows),
		}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "catalog_self_service_action", "draft", "catalog.self_service_action.upsert")
		if !ok {
			return
		}
		if rec.ScopeType == "" {
			rec.ScopeType = "catalog_entity"
		}
		if rec.Status == "" {
			rec.Status = "draft"
		}
		if rec.Payload == nil {
			rec.Payload = map[string]any{}
		}
		if rec.Payload["risk_level"] == nil {
			rec.Payload["risk_level"] = "medium"
		}
		if rec.Payload["approval_required"] == nil {
			rec.Payload["approval_required"] = rec.Payload["risk_level"] != "low"
		}
		if rec.Name == "" {
			rec.Name = "Self-service action"
		}
		if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "catalog_self_service_action_save_failed")
			return
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "catalog_self_service_action", rec.ID, map[string]any{"action": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func parseCatalogRuntimeRef(ref string) (catalogRuntimeRef, bool) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(ref), "/"), "/")
	if len(parts) < 4 {
		return catalogRuntimeRef{}, false
	}
	return catalogRuntimeRef{
		ClusterID: strings.TrimSpace(parts[0]),
		Namespace: strings.TrimSpace(parts[1]),
		Kind:      strings.TrimSpace(parts[2]),
		Name:      strings.TrimSpace(strings.Join(parts[3:], "/")),
	}, true
}

func buildCatalogScorecard(entity store.CatalogEntity, project store.EnterpriseProject, rt catalogRuntimeRef, hasRuntime bool, incidents []store.K8sIncident, findings []store.K8sSecurityFinding) map[string]any {
	score := 100
	recommendations := []string{}
	categories := map[string]int{
		"ownership":   100,
		"runtime":     100,
		"reliability": 100,
		"security":    100,
		"docs":        100,
	}
	if entity.OwnerTeamID == "" {
		score -= 20
		categories["ownership"] = 40
		recommendations = append(recommendations, "owner_team_id를 지정하세요")
	}
	if entity.ProjectID == "" {
		score -= 8
		categories["ownership"] -= 15
		recommendations = append(recommendations, "프로젝트와 비용센터 범위를 연결하세요")
	}
	if project.Environment == "prod" && entity.Criticality == "" && project.Criticality == "" {
		score -= 8
		recommendations = append(recommendations, "prod 서비스는 criticality를 지정하세요")
	}
	if !hasRuntime {
		score -= 20
		categories["runtime"] = 35
		recommendations = append(recommendations, "runtime_ref를 cluster/namespace/kind/name 형식으로 연결하세요")
	}
	if entity.RepoURL == "" {
		score -= 7
		categories["docs"] -= 15
		recommendations = append(recommendations, "repo_url을 연결하세요")
	}
	if entity.DocsURL == "" {
		score -= 7
		categories["docs"] -= 20
		recommendations = append(recommendations, "docs_url 또는 runbook 링크를 연결하세요")
	}
	incidentCount := matchingCatalogIncidentCount(rt, hasRuntime, incidents)
	if incidentCount > 0 {
		delta := minInt(30, 10+incidentCount*5)
		score -= delta
		categories["reliability"] = maxInt(20, 100-delta*2)
		recommendations = append(recommendations, "오픈 problem/incident를 확인하고 runbook 초안을 생성하세요")
	}
	findingCount, criticalFindings := matchingCatalogFindingCount(rt, hasRuntime, findings)
	if findingCount > 0 {
		delta := minInt(30, 8+findingCount*4+criticalFindings*6)
		score -= delta
		categories["security"] = maxInt(15, 100-delta*2)
		recommendations = append(recommendations, "보안 finding과 정책 예외 만료 여부를 확인하세요")
	}
	score = maxInt(0, minInt(100, score))
	maturity := "Gold"
	switch {
	case score < 55:
		maturity = "At Risk"
	case score < 70:
		maturity = "Bronze"
	case score < 85:
		maturity = "Silver"
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "현재 기준으로 필수 운영 메타데이터가 충분합니다")
	}
	return map[string]any{
		"entity_id":              entity.ID,
		"entity_name":            entity.Name,
		"kind":                   entity.Kind,
		"project_id":             entity.ProjectID,
		"owner_team_id":          entity.OwnerTeamID,
		"runtime_ref":            entity.RuntimeRef,
		"runtime":                rt,
		"score":                  score,
		"maturity":               maturity,
		"categories":             categories,
		"open_incidents":         incidentCount,
		"open_security_findings": findingCount,
		"critical_findings":      criticalFindings,
		"recommendations":        recommendations,
	}
}

func matchingCatalogIncidentCount(rt catalogRuntimeRef, hasRuntime bool, incidents []store.K8sIncident) int {
	if !hasRuntime {
		return 0
	}
	count := 0
	for _, inc := range incidents {
		if inc.ClusterID != rt.ClusterID || inc.Namespace != rt.Namespace {
			continue
		}
		if strings.EqualFold(inc.Kind, rt.Kind) && inc.Name == rt.Name {
			count++
			continue
		}
		if strings.EqualFold(inc.Kind, "Pod") || strings.Contains(strings.ToLower(inc.Title), strings.ToLower(rt.Name)) || strings.Contains(strings.ToLower(inc.DedupKey), strings.ToLower(rt.Name)) {
			count++
		}
	}
	return count
}

func catalogIncidentMatches(rt catalogRuntimeRef, inc store.K8sIncident) bool {
	if inc.ClusterID != rt.ClusterID || inc.Namespace != rt.Namespace {
		return false
	}
	return (strings.EqualFold(inc.Kind, rt.Kind) && inc.Name == rt.Name) ||
		strings.Contains(strings.ToLower(inc.Title), strings.ToLower(rt.Name)) ||
		strings.Contains(strings.ToLower(inc.DedupKey), strings.ToLower(rt.Name)) ||
		strings.EqualFold(inc.Kind, "Pod")
}

func matchingCatalogFindingCount(rt catalogRuntimeRef, hasRuntime bool, findings []store.K8sSecurityFinding) (int, int) {
	if !hasRuntime {
		return 0, 0
	}
	count := 0
	critical := 0
	for _, f := range findings {
		if f.ClusterID != rt.ClusterID || f.Namespace != rt.Namespace {
			continue
		}
		if !strings.EqualFold(f.ResourceKind, rt.Kind) && f.ResourceName != rt.Name {
			continue
		}
		count++
		sev := strings.ToLower(f.Severity)
		if sev == "critical" || sev == "high" {
			critical++
		}
	}
	return count, critical
}

func catalogFindingMatches(rt catalogRuntimeRef, f store.K8sSecurityFinding) bool {
	if f.ClusterID != rt.ClusterID || f.Namespace != rt.Namespace {
		return false
	}
	return strings.EqualFold(f.ResourceKind, rt.Kind) || f.ResourceName == rt.Name
}

func catalogRuntimeItemMatches(rt catalogRuntimeRef, it store.K8sInventoryItem) bool {
	if it.ClusterID != rt.ClusterID || it.Namespace != rt.Namespace {
		return false
	}
	if strings.EqualFold(it.Kind, rt.Kind) && it.Name == rt.Name {
		return true
	}
	if strings.EqualFold(it.Kind, "Pod") && strings.Contains(strings.ToLower(it.Name), strings.ToLower(rt.Name)) {
		return true
	}
	return false
}
