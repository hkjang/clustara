package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

// platformAgentPlanInput is intentionally structured around the placement decisions that an
// operator must own. The prompt selects and tunes a catalog; it never grants the agent authority
// to choose an arbitrary cluster or to apply resources.
type platformAgentPlanInput struct {
	Prompt      string `json:"prompt"`
	ClusterID   string `json:"cluster_id"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Environment string `json:"environment"`
	CatalogCode string `json:"catalog_code"`
	Profile     string `json:"profile"`
	Image       string `json:"image"`
}

type platformAgentStage struct {
	State  string `json:"state"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type platformAgentLifecycle struct {
	State      string                      `json:"state"`
	Label      string                      `json:"label"`
	Detail     string                      `json:"detail"`
	Decision   string                      `json:"decision"`
	Stages     []platformAgentStage        `json:"stages"`
	LastApply  *store.K8sStackApplyHistory `json:"last_apply,omitempty"`
	NextAction string                      `json:"next_action"`
}

// platformAgentLifecycleFromEvidence derives the Agent's current position from existing durable
// evidence. It deliberately does not create a second workflow ledger beside Service/Stack history.
func platformAgentLifecycleFromEvidence(instance store.K8sServiceInstance, stack store.K8sApplicationStack, history []store.K8sStackApplyHistory, healthStatus string) platformAgentLifecycle {
	decision := "allow"
	var policy map[string]any
	if json.Unmarshal([]byte(instance.PolicyResultJSON), &policy) == nil {
		decision = firstNonEmpty(strings.TrimSpace(fmt.Sprint(policy["decision"])), decision)
	}
	state, label, detail, next := "validating", "정책 검증", "저장된 Manifest의 정책 검증 결과를 확인합니다.", "Stack 검증 결과를 확인하세요."
	if decision == "approval_required" || instance.Status == "pending_approval" {
		state, label, detail, next = "approval_required", "승인 필요", "정책상 실제 Apply 전에 운영 승인이 필요합니다.", "Application Stack에서 승인 후 Apply하세요."
	}
	var last *store.K8sStackApplyHistory
	for idx := range history {
		if history[idx].Operation == "apply" {
			last = &history[idx]
			break
		}
	}
	if last != nil {
		switch last.Status {
		case "approval_required":
			state, label, detail, next = "approval_required", "승인 필요", "최근 Apply가 승인 게이트에서 대기 중입니다.", "승인 권한으로 Apply를 확인하세요."
		case "denied", "failed", "partial":
			state, label, detail, next = "execution_failed", "적용 확인 필요", "최근 Apply 결과가 "+last.Status+" 상태입니다.", "리소스별 실패 증적과 정책 위반을 확인하세요."
		case "success":
			if last.DryRun {
				state, label, detail, next = "validating", "Dry-run 통과", "최근 Server-Side Apply Dry-run을 통과했습니다.", "승인 후 실제 Apply를 실행하세요."
			} else {
				state, label, detail, next = "observing", "배포 관찰", "실제 Apply 후 Kubernetes 인벤토리와 Health 증적을 관찰하고 있습니다.", "상태 동기화·검증을 실행하세요."
			}
		}
	}
	if stack.Status == "applied" && (healthStatus == "ready" || healthStatus == "healthy") {
		state, label, detail, next = "succeeded", "운영 정상", "Apply와 서비스 Health 검증이 모두 완료되었습니다.", "지속 모니터링과 드리프트를 확인하세요."
	}
	return platformAgentLifecycle{State: state, Label: label, Detail: detail, Decision: decision, Stages: platformAgentEvidenceStages(state), LastApply: last, NextAction: next}
}

func platformAgentEvidenceStages(current string) []platformAgentStage {
	defs := []struct{ state, label string }{{"requested", "요청"}, {"planning", "계획"}, {"draft_ready", "초안"}, {"validating", "검증"}, {"approval_required", "승인"}, {"applying", "적용"}, {"observing", "관찰"}, {"succeeded", "완료"}}
	position := map[string]int{"validating": 3, "approval_required": 4, "applying": 5, "observing": 6, "succeeded": 7, "execution_failed": 5}[current]
	out := make([]platformAgentStage, 0, len(defs))
	for idx, def := range defs {
		status := "pending"
		if idx < position {
			status = "completed"
		}
		if idx == position {
			status = "current"
		}
		if current == "execution_failed" && idx == position {
			status = "blocked"
		}
		out = append(out, platformAgentStage{State: def.state, Label: def.label, Status: status})
	}
	return out
}

// handlePlatformAgentDeploymentReadiness performs a live-capability preflight without calling
// Kubernetes Apply. It closes the gap between a policy-valid draft and an actually deployable
// Stack while preserving the explicit approval/apply boundary.
func (s *Server) handlePlatformAgentDeploymentReadiness(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	stack, err := s.db.GetK8sStack(r.Context(), instance.StackID)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "service Application Stack not found", "invalid_request_error", "stack_not_found")
		return
	}
	docs, err := decodeManifestDocs(stack.Manifest)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "stored manifest parse error: "+err.Error(), "invalid_request_error", "manifest_parse_failed")
		return
	}
	policies, err := s.db.ListK8sPolicies(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_policies_failed")
		return
	}
	plan := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
	blockers, warnings := []string{}, []string{}
	if plan.Denied {
		blockers = append(blockers, "현재 정책이 Application Stack Apply를 차단합니다.")
	}
	cluster, clusterErr := s.db.GetK8sCluster(r.Context(), instance.ClusterID)
	clientReady, applySupported := false, false
	if clusterErr != nil {
		blockers = append(blockers, "대상 클러스터 설정을 찾을 수 없습니다.")
	} else if client, clientErr := s.k8sClientForCluster(r.Context(), cluster); clientErr != nil {
		blockers = append(blockers, "Kubernetes 연결 준비 실패: "+clientErr.Error())
	} else {
		clientReady = true
		_, applySupported = client.(kube.StackApplier)
		if !applySupported {
			blockers = append(blockers, "대상 클러스터 클라이언트가 Server-Side Apply를 지원하지 않습니다.")
		}
	}
	if plan.RequiresApproval {
		warnings = append(warnings, "정책상 운영자 승인이 필요합니다: "+strings.Join(plan.ApprovalReasons, " · "))
	}
	history, _ := s.db.ListK8sStackApplyHistory(r.Context(), stack.ID, 20)
	lifecycle := platformAgentLifecycleFromEvidence(instance, stack, history, "")
	state := "ready"
	if len(blockers) > 0 {
		state = "blocked"
	} else if plan.RequiresApproval || instance.Environment == "production" {
		state = "approval_required"
	}
	result := map[string]any{
		"state": state, "ready": state != "blocked", "approval_required": state == "approval_required",
		"instance_id": instance.ID, "stack_id": stack.ID, "cluster_id": instance.ClusterID,
		"namespace": instance.Namespace, "revision_no": stack.RevisionNo, "resource_count": len(resolveStackTargets(docs, stack.Namespace)),
		"client_ready": clientReady, "server_side_apply_supported": applySupported,
		"plan": plan, "blockers": blockers, "warnings": warnings, "lifecycle": lifecycle,
		"next":   map[string]string{"stack": "#/k8s-stacks?id=" + stack.ID, "approval": "#/k8s-actions", "observe": "#/services/all?id=" + instance.ID},
		"safety": "준비도 점검은 Kubernetes 리소스를 변경하지 않습니다. 실제 Apply는 Application Stack 화면에서 별도로 실행해야 합니다.",
	}
	s.auditAdmin(r, "k8s.agent.deployment_readiness", instance.ID, auditJSON(map[string]any{"state": state, "stack_id": stack.ID, "resources": len(docs)}))
	writeJSON(w, http.StatusOK, result)
}

// handlePlatformAgentPlan converts a natural-language service request into an explainable,
// policy-reviewed service catalog draft. It is read-only: persistence happens only when the user
// explicitly submits the returned service_input to the existing service instance endpoint, and
// cluster mutation remains behind the existing Stack validation/approval/apply workflow.
func (s *Server) handlePlatformAgentPlan(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized", "permission_error", "authentication_required")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in platformAgentPlanInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	in.Prompt, in.ClusterID, in.Namespace, in.Name = strings.TrimSpace(in.Prompt), strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Name)
	if in.Prompt == "" || in.ClusterID == "" || in.Name == "" {
		writeOpenAIError(w, http.StatusBadRequest, "prompt, cluster_id and name are required", "invalid_request_error", "missing_fields")
		return
	}
	if in.Namespace == "" {
		in.Namespace = "default"
	}
	if in.Environment == "" {
		in.Environment = platformAgentEnvironment(in.Prompt)
	}
	if in.Environment == "" {
		in.Environment = "development"
	}
	if err := s.ensureBuiltinServiceCatalogs(r); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_catalog_seed_failed")
		return
	}

	catalogs, err := s.db.ListK8sServiceCatalogs(r.Context(), false)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_catalog_list_failed")
		return
	}
	code := firstNonEmpty(strings.TrimSpace(in.CatalogCode), platformAgentCatalogCode(in.Prompt))
	var catalog store.K8sServiceCatalog
	for _, candidate := range catalogs {
		if strings.EqualFold(candidate.Code, code) {
			catalog = candidate
			break
		}
	}
	if catalog.ID == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"state": "blocked", "prompt": in.Prompt,
			"blockers":           []string{"요청한 서비스 유형을 현재 카탈로그에서 찾지 못했습니다."},
			"supported_catalogs": platformAgentCatalogOptions(catalogs),
			"stages":             platformAgentStages("blocked", "지원 카탈로그를 선택하거나 템플릿 관리에서 먼저 등록하세요."),
			"safety":             "AI Platform Agent는 지원 카탈로그 밖의 임의 YAML을 자동 배포하지 않습니다.",
		})
		return
	}

	versions, _ := s.db.ListK8sServiceVersions(r.Context(), catalog.ID)
	profiles, _ := s.db.ListK8sServiceProfiles(r.Context(), catalog.ID)
	versionID := ""
	for _, version := range versions {
		if version.Recommended && version.Status == "available" {
			versionID = version.ID
			break
		}
	}
	if versionID == "" && len(versions) > 0 {
		versionID = versions[0].ID
	}
	profileName := firstNonEmpty(strings.TrimSpace(in.Profile), platformAgentProfile(in.Prompt), "small")
	profileID := ""
	for _, profile := range profiles {
		if strings.EqualFold(profile.Name, profileName) {
			profileID = profile.ID
			break
		}
	}
	serviceInput := serviceInstanceInput{
		CatalogID: catalog.ID, VersionID: versionID, ProfileID: profileID, ClusterID: in.ClusterID,
		Namespace: in.Namespace, Name: in.Name, Environment: in.Environment,
		Values: map[string]any{},
	}
	if in.Image != "" {
		serviceInput.Values["image"] = in.Image
	}
	applyPlatformAgentPromptValues(in.Prompt, serviceInput.Values)
	cat, version, manifest, values, validationErrors, prepErr := s.prepareServiceInstance(r, serviceInput)
	if prepErr != nil {
		validationErrors = append(validationErrors, prepErr.Error())
	}
	serviceInput.Values = values
	if serviceInput.Values == nil {
		serviceInput.Values = map[string]any{}
	}

	resourcePlan := map[string]any{}
	resources := []map[string]string{}
	warnings := platformAgentWarnings(in.Prompt, in.Environment, values)
	if manifest != "" {
		if docs, decodeErr := decodeManifestDocs(manifest); decodeErr == nil {
			policies, _ := s.db.ListK8sPolicies(r.Context())
			analysis := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
			resourcePlan = map[string]any{"analysis": analysis, "resource_count": len(docs)}
			for _, doc := range docs {
				apiVersion, kind, namespace, name := manifestDocIdentity(doc)
				resources = append(resources, map[string]string{"api_version": apiVersion, "kind": kind, "namespace": namespace, "name": name})
			}
			if analysis.Denied {
				for _, violation := range analysis.PolicyViolations {
					validationErrors = append(validationErrors, firstNonEmpty(violation.Detail, violation.Name, violation.RuleType))
				}
			}
		} else {
			validationErrors = append(validationErrors, "생성 manifest 해석 실패: "+decodeErr.Error())
		}
	}
	state := "draft_ready"
	if len(validationErrors) > 0 {
		state = "blocked"
	}
	stages := platformAgentStages(state, "서비스 등록 후 Stack 검증·승인·적용·관찰로 이어집니다.")
	response := map[string]any{
		"state": state, "prompt": in.Prompt, "catalog": cat, "version": version,
		"profile": profileName, "service_input": serviceInput, "manifest": manifest,
		"resources": resources, "resource_plan": resourcePlan, "warnings": warnings,
		"blockers": validationErrors, "stages": stages,
		"cost":   map[string]any{"status": "requires_pricing", "basis": map[string]any{"cpu": values["cpu"], "memory": values["memory"], "storage": values["storage"], "replicas": values["replicas"]}},
		"safety": "이 응답은 계획과 manifest preview만 생성합니다. 서비스 등록은 Stack 초안을 저장할 뿐이며 실제 Kubernetes Apply는 기존 검증·승인 흐름에서만 수행됩니다.",
		"next":   map[string]string{"register": "POST /admin/k8s/services/instances", "validate": "POST /admin/k8s/stacks/validate", "apply": "POST /admin/k8s/stacks/{id}/apply"},
	}
	s.auditAdmin(r, "k8s.agent.platform_plan", "", auditJSON(map[string]any{"state": state, "catalog": catalog.Code, "cluster_id": in.ClusterID, "namespace": in.Namespace, "name": in.Name, "resource_count": len(resources)}))
	writeJSON(w, http.StatusOK, response)
}

func platformAgentCatalogCode(prompt string) string {
	p := strings.ToLower(prompt)
	aliases := []struct {
		code  string
		terms []string
	}{
		{"postgresql", []string{"postgresql", "postgres", "포스트그레스", "포스트그레"}},
		{"redis", []string{"redis", "레디스", "cache", "캐시"}},
		{"spring-boot", []string{"spring boot", "spring-boot", "스프링 부트", "스프링부트"}},
		{"jupyterhub", []string{"jupyterhub", "jupyter hub", "주피터허브"}},
		{"jupyterlab", []string{"jupyterlab", "jupyter lab", "주피터랩", "notebook"}},
		{"tomcat", []string{"tomcat", "톰캣", "was"}},
	}
	for _, alias := range aliases {
		for _, term := range alias.terms {
			if strings.Contains(p, term) {
				return alias.code
			}
		}
	}
	return ""
}

func platformAgentProfile(prompt string) string {
	p := strings.ToLower(prompt)
	for _, name := range []string{"large", "medium", "small"} {
		if strings.Contains(p, name) {
			return name
		}
	}
	if strings.Contains(p, "대형") || strings.Contains(p, "고성능") {
		return "large"
	}
	if strings.Contains(p, "중형") {
		return "medium"
	}
	return ""
}

func platformAgentEnvironment(prompt string) string {
	p := strings.ToLower(prompt)
	if strings.Contains(p, "production") || strings.Contains(p, "prod") || strings.Contains(p, "운영") {
		return "production"
	}
	if strings.Contains(p, "staging") || strings.Contains(p, "stage") || strings.Contains(p, "스테이징") {
		return "staging"
	}
	return ""
}

func applyPlatformAgentPromptValues(prompt string, values map[string]any) {
	p := strings.ToLower(prompt)
	if strings.Contains(p, "ha") || strings.Contains(p, "고가용") {
		values["replicas"] = 3
	}
	if strings.Contains(p, "gpu") {
		values["gpu"] = "1"
	}
}

func platformAgentWarnings(prompt, environment string, values map[string]any) []string {
	warnings := []string{"Secret 원문은 계획에 포함하지 않습니다. 기존 Kubernetes Secret 또는 외부 Secret manager 참조를 사용하세요."}
	if strings.EqualFold(environment, "production") {
		warnings = append(warnings, "운영 환경은 이미지 digest 고정과 추가 승인이 필요합니다.")
	}
	if strings.Contains(strings.ToLower(prompt), "ingress") {
		warnings = append(warnings, "기본 카탈로그는 Ingress를 자동 생성하지 않습니다. 도메인·TLS·노출 정책을 확인한 후 별도 변경 요청으로 추가하세요.")
	}
	if fmt.Sprint(values["gpu"]) != "<nil>" && strings.TrimSpace(fmt.Sprint(values["gpu"])) != "" {
		warnings = append(warnings, "GPU 요청은 현재 기본 카탈로그 template 지원 여부를 검토해야 합니다.")
	}
	return warnings
}

func platformAgentStages(state, detail string) []platformAgentStage {
	status := func(target string) string {
		order := map[string]int{"requested": 0, "planning": 1, "draft_ready": 2, "validating": 3, "approval_required": 4, "applying": 5, "observing": 6, "succeeded": 7}
		if state == "blocked" {
			if target == "requested" || target == "planning" {
				return "completed"
			}
			if target == "draft_ready" {
				return "blocked"
			}
			return "pending"
		}
		if order[target] < order[state] {
			return "completed"
		}
		if target == state {
			return "current"
		}
		return "pending"
	}
	labels := []struct{ state, label string }{{"requested", "요청 접수"}, {"planning", "계획 생성"}, {"draft_ready", "초안 검토"}, {"validating", "Stack 검증"}, {"approval_required", "승인"}, {"applying", "적용"}, {"observing", "상태 관찰"}, {"succeeded", "완료"}}
	stages := make([]platformAgentStage, 0, len(labels))
	for _, item := range labels {
		stages = append(stages, platformAgentStage{State: item.state, Label: item.label, Status: status(item.state), Detail: detail})
	}
	return stages
}

func platformAgentCatalogOptions(catalogs []store.K8sServiceCatalog) []map[string]string {
	rows := make([]map[string]string, 0, len(catalogs))
	for _, catalog := range catalogs {
		rows = append(rows, map[string]string{"code": catalog.Code, "name": catalog.Name, "category": catalog.Category})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["code"] < rows[j]["code"] })
	return rows
}
