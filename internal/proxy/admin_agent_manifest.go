package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleAgentManifestDrafts bridges the read-only Ops Agent with Manifest Change Studio.
// The agent may draft or register a YAML create/update request, but it never validates, approves,
// or applies the change. Those steps stay in the existing Manifest Change Studio state machine.
// POST /admin/agent/manifest-drafts
func (s *Server) handleAgentManifestDrafts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in agentManifestDraftInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if err := s.fillAgentManifestDraftContext(r, &in); err != nil {
		writeManifestChangeCreateError(w, err)
		return
	}
	draft, err := s.buildAgentManifestDraft(r, in)
	if err != nil {
		writeManifestChangeCreateError(w, err)
		return
	}

	var created *store.K8sManifestChangeRequest
	var createResult manifestChangeCreateResult
	if in.CreateRequest {
		reqInput := manifestChangeCreateInput{
			ClusterID:      draft.ClusterID,
			Namespace:      draft.Namespace,
			Kind:           draft.Kind,
			APIVersion:     draft.APIVersion,
			Name:           draft.Name,
			Operation:      draft.Operation,
			AfterYAML:      draft.YAML,
			Reason:         firstNonEmpty(strings.TrimSpace(in.Reason), "Ops Agent draft: "+strings.TrimSpace(in.Prompt)),
			IdempotencyKey: firstNonEmpty(strings.TrimSpace(in.IdempotencyKey), agentManifestDraftIdempotency(in, draft)),
		}
		result, err := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), reqInput)
		if err != nil {
			writeManifestChangeCreateError(w, err)
			return
		}
		createResult = result
		created = &result.Request
		draft.Review["request_created"] = result.Request.ID
		draft.Review["request_status"] = result.Request.Status
	}

	if strings.TrimSpace(in.SessionID) != "" {
		s.recordAgentManifestDraftMessages(r, in, draft, created)
	}
	auditDetail := map[string]any{
		"session_id":     in.SessionID,
		"operation":      draft.Operation,
		"cluster_id":     draft.ClusterID,
		"kind":           draft.Kind,
		"namespace":      draft.Namespace,
		"name":           draft.Name,
		"create_request": in.CreateRequest,
	}
	if created != nil {
		auditDetail["request_id"] = created.ID
	}
	s.auditAdmin(r, "k8s.agent.manifest_draft", "", auditJSON(auditDetail))

	status := http.StatusOK
	if created != nil && !createResult.IdempotentReplay {
		status = http.StatusCreated
	}
	resp := map[string]any{
		"draft":      draft,
		"safety":     "Ops Agent는 YAML 초안과 Manifest Change 요청까지만 만들며, 검증·승인·적용은 Manifest Change Studio의 원장 상태머신에서만 진행됩니다.",
		"next_steps": agentManifestDraftNextSteps(draft, created),
		"studio_href": k8sManifestStudioHref(draft.ClusterID, draft.Kind, draft.Namespace, draft.Name,
			func() string {
				if created != nil {
					return created.ID
				}
				return ""
			}()),
	}
	if created != nil {
		resp["request"] = created
		resp["manifest_change"] = manifestChangeCreateResponse(createResult)
	}
	writeJSON(w, status, resp)
}

type agentManifestDraftInput struct {
	SessionID      string `json:"session_id"`
	ClusterID      string `json:"cluster_id"`
	Namespace      string `json:"namespace"`
	Kind           string `json:"kind"`
	APIVersion     string `json:"api_version"`
	Name           string `json:"name"`
	Operation      string `json:"operation"`
	Prompt         string `json:"prompt"`
	ManifestYAML   string `json:"manifest_yaml"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key"`
	CreateRequest  bool   `json:"create_request"`
}

type agentManifestDraft struct {
	Operation  string                       `json:"operation"`
	ClusterID  string                       `json:"cluster_id"`
	Namespace  string                       `json:"namespace"`
	Kind       string                       `json:"kind"`
	APIVersion string                       `json:"api_version"`
	Name       string                       `json:"name"`
	YAML       string                       `json:"yaml"`
	Prompt     string                       `json:"prompt"`
	Review     map[string]any               `json:"review"`
	Checklist  []string                     `json:"checklist"`
	Warnings   []string                     `json:"warnings"`
	Blockers   []string                     `json:"blockers"`
	Diffs      []store.K8sManifestFieldDiff `json:"diffs"`
}

func (s *Server) fillAgentManifestDraftContext(r *http.Request, in *agentManifestDraftInput) error {
	if strings.TrimSpace(in.SessionID) == "" {
		return nil
	}
	sess, err := s.db.GetK8sAgentSession(r.Context(), strings.TrimSpace(in.SessionID))
	if errors.Is(err, store.ErrNotFound) {
		return manifestChangeCreateHTTPError(http.StatusNotFound, "agent session not found", "session_not_found")
	}
	if err != nil {
		return err
	}
	var raw map[string]any
	_ = json.Unmarshal([]byte(sess.Context), &raw)
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(asStr(raw[k])); v != "" {
				return v
			}
		}
		return ""
	}
	if in.ClusterID == "" {
		in.ClusterID = pick("cluster_id", "ClusterID", "clusterId")
	}
	if in.Namespace == "" {
		in.Namespace = pick("namespace", "Namespace")
	}
	if in.Kind == "" {
		in.Kind = pick("kind", "Kind")
	}
	if in.Name == "" {
		in.Name = firstNonEmpty(pick("name", "Name"), pick("pod", "Pod"))
	}
	return nil
}

func (s *Server) buildAgentManifestDraft(r *http.Request, in agentManifestDraftInput) (agentManifestDraft, error) {
	op, err := normalizeManifestChangeOperation(in.Operation)
	if err != nil {
		return agentManifestDraft{}, manifestChangeCreateHTTPError(http.StatusBadRequest, err.Error(), "invalid_manifest_operation")
	}
	clusterID := strings.TrimSpace(in.ClusterID)
	kind := canonicalManifestKind(firstNonEmpty(in.Kind, agentManifestKindFromPrompt(in.Prompt)))
	name := strings.TrimSpace(firstNonEmpty(in.Name, agentManifestDefaultName(kind)))
	namespace := strings.TrimSpace(in.Namespace)
	if namespace == "" && !manifestKindClusterScoped(kind) {
		namespace = "default"
	}
	apiVersion := strings.TrimSpace(firstNonEmpty(in.APIVersion, agentManifestDefaultAPIVersion(kind)))
	if clusterID == "" {
		return agentManifestDraft{}, manifestChangeCreateHTTPError(http.StatusBadRequest, "cluster_id is required", "missing_cluster_id")
	}
	if kind == "" || name == "" {
		return agentManifestDraft{}, manifestChangeCreateHTTPError(http.StatusBadRequest, "kind and name are required", "missing_target")
	}

	yml := strings.TrimSpace(in.ManifestYAML)
	warnings := []string{}
	blockers := []string{}
	if yml == "" {
		if op == "create" {
			yml = agentManifestTemplate(kind, apiVersion, namespace, name)
			warnings = append(warnings, "표준 템플릿으로 생성했습니다. image, selector, port, env, resource 값은 실제 서비스 기준으로 검토하세요.")
		} else {
			item, err := s.db.GetK8sInventoryItem(r.Context(), clusterID, kind, namespace, name)
			if errors.Is(err, store.ErrNotFound) {
				return agentManifestDraft{}, manifestChangeCreateHTTPError(http.StatusNotFound, "live resource not found; 변경 초안은 live YAML 또는 manifest_yaml이 필요합니다", "resource_not_found")
			}
			if err != nil {
				return agentManifestDraft{}, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_inventory_failed")
			}
			yml = mustManifestYAML(sanitizeManifestDocForLedger(assembleManifest(item)))
			warnings = append(warnings, "Live YAML을 초안으로 불러왔습니다. 필요한 필드를 편집한 뒤 요청을 생성하세요.")
		}
	}

	doc, err := parseSingleManifestDoc(yml)
	if err != nil {
		return agentManifestDraft{}, manifestChangeCreateHTTPError(http.StatusBadRequest, "manifest_yaml parse error: "+err.Error(), "manifest_parse_failed")
	}
	docAPIVersion, docKind, docNamespace, docName := manifestDocIdentity(doc)
	if kind == "" {
		kind = docKind
	}
	if name == "" {
		name = docName
	}
	if namespace == "" {
		namespace = docNamespace
	}
	if namespace == "" && !manifestKindClusterScoped(kind) {
		namespace = "default"
	}
	if err := ensureManifestDocTarget(doc, kind, namespace, name); err != nil {
		return agentManifestDraft{}, manifestChangeCreateHTTPError(http.StatusBadRequest, err.Error(), "manifest_target_mismatch")
	}
	apiVersion = firstNonEmpty(apiVersion, docAPIVersion)
	yml = mustManifestYAML(sanitizeManifestDocForLedger(doc))

	diffs, impact, risk, requiresApproval := s.agentManifestDraftReview(r, op, clusterID, namespace, kind, apiVersion, name, doc, &warnings, &blockers)
	review := map[string]any{
		"risk_level":        risk,
		"requires_approval": requiresApproval,
		"impact":            impact,
		"diff_count":        len(diffs),
		"source":            "ops_agent",
	}
	if strings.TrimSpace(in.Prompt) != "" {
		review["prompt"] = strings.TrimSpace(in.Prompt)
	}
	return agentManifestDraft{
		Operation: op, ClusterID: clusterID, Namespace: namespace, Kind: kind, APIVersion: apiVersion,
		Name: name, YAML: yml, Prompt: strings.TrimSpace(in.Prompt), Review: review,
		Checklist: agentManifestChecklist(op, kind), Warnings: warnings, Blockers: blockers, Diffs: diffs,
	}, nil
}

func (s *Server) agentManifestDraftReview(r *http.Request, op, clusterID, namespace, kind, apiVersion, name string, afterDoc map[string]any, warnings, blockers *[]string) ([]store.K8sManifestFieldDiff, map[string]any, string, bool) {
	policies, _ := s.db.ListK8sPolicies(r.Context())
	plan := analyzer.AnalyzeStackManifest([]map[string]any{afterDoc}, toAnalyzerPolicies(policies))
	item := store.K8sInventoryItem{ClusterID: clusterID, Namespace: namespace, Kind: kind, APIVersion: apiVersion, Name: name}
	if op == "create" {
		if existing, err := s.db.GetK8sInventoryItem(r.Context(), clusterID, kind, namespace, name); err == nil {
			*blockers = append(*blockers, fmt.Sprintf("이미 inventory에 같은 대상이 있습니다: %s/%s/%s (uid=%s)", kind, namespace, name, existing.UID))
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			*warnings = append(*warnings, "기존 대상 확인 실패: "+err.Error())
		}
		storeAfterDoc := sanitizeManifestDocForLedger(afterDoc)
		diffs := diffManifestDocs(map[string]any{}, storeAfterDoc)
		impact, risk, requiresApproval := manifestCreateImpact(item, afterDoc, diffs, plan)
		if strings.EqualFold(kind, "Secret") && manifestContainsSecretPayload(afterDoc) {
			*blockers = append(*blockers, "Secret data/stringData 원문은 Agent/Manifest Studio로 저장하거나 적용하지 않습니다.")
			impact["secret_payload_guard"] = "blocked"
			risk = "blocked"
			requiresApproval = true
		}
		return diffs, impact, risk, requiresApproval
	}
	live, err := s.db.GetK8sInventoryItem(r.Context(), clusterID, kind, namespace, name)
	if errors.Is(err, store.ErrNotFound) {
		*blockers = append(*blockers, "변경 대상 live resource가 없습니다. 생성이면 operation=create를 사용하세요.")
		return diffManifestDocs(map[string]any{}, sanitizeManifestDocForLedger(afterDoc)), map[string]any{"operation": "update", "target": item}, "blocked", true
	}
	if err != nil {
		*warnings = append(*warnings, "live resource 확인 실패: "+err.Error())
		return diffManifestDocs(map[string]any{}, sanitizeManifestDocForLedger(afterDoc)), map[string]any{"operation": "update", "target": item}, "medium", true
	}
	beforeDoc := sanitizeManifestDocForLedger(assembleManifest(live))
	storeAfterDoc := sanitizeManifestDocForLedger(afterDoc)
	diffs := diffManifestDocs(beforeDoc, storeAfterDoc)
	impact, risk, requiresApproval := manifestChangeImpact(live, afterDoc, diffs, plan)
	if strings.EqualFold(kind, "Secret") && manifestContainsSecretPayload(afterDoc) {
		*blockers = append(*blockers, "Secret data/stringData 원문 변경은 Config Change Control 또는 외부 Secret 관리 체계로 처리하세요.")
		impact["secret_payload_guard"] = "blocked"
		risk = "blocked"
		requiresApproval = true
	}
	if len(diffs) == 0 {
		*warnings = append(*warnings, "현재 live YAML과 의미 있는 diff가 없습니다. 적용 요청 전 변경 내용을 확인하세요.")
	}
	return diffs, impact, risk, requiresApproval
}

func agentManifestKindFromPrompt(prompt string) string {
	p := strings.ToLower(prompt)
	switch {
	case strings.Contains(p, "configmap") || strings.Contains(p, "cm") || strings.Contains(p, "설정"):
		return "ConfigMap"
	case strings.Contains(p, "secret") || strings.Contains(p, "시크릿"):
		return "Secret"
	case strings.Contains(p, "serviceaccount") || strings.Contains(p, " sa "):
		return "ServiceAccount"
	case strings.Contains(p, "rolebinding"):
		return "RoleBinding"
	case strings.Contains(p, "role"):
		return "Role"
	case strings.Contains(p, "pvc") || strings.Contains(p, "persistentvolumeclaim"):
		return "PersistentVolumeClaim"
	case strings.Contains(p, "ingress"):
		return "Ingress"
	case strings.Contains(p, "networkpolicy") || strings.Contains(p, "netpol"):
		return "NetworkPolicy"
	case strings.Contains(p, "hpa"):
		return "HorizontalPodAutoscaler"
	case strings.Contains(p, "service") || strings.Contains(p, "svc"):
		return "Service"
	case strings.Contains(p, "namespace"):
		return "Namespace"
	case strings.Contains(p, "cronjob"):
		return "CronJob"
	case strings.Contains(p, "job"):
		return "Job"
	default:
		return "Deployment"
	}
}

func agentManifestDefaultAPIVersion(kind string) string {
	switch canonicalManifestKind(kind) {
	case "Deployment", "StatefulSet", "DaemonSet":
		return "apps/v1"
	case "Job", "CronJob":
		return "batch/v1"
	case "Ingress", "NetworkPolicy":
		return "networking.k8s.io/v1"
	case "HorizontalPodAutoscaler":
		return "autoscaling/v2"
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
		return "rbac.authorization.k8s.io/v1"
	default:
		return "v1"
	}
}

func agentManifestDefaultName(kind string) string {
	switch canonicalManifestKind(kind) {
	case "ConfigMap":
		return "sample-config"
	case "Secret":
		return "sample-secret"
	case "ServiceAccount":
		return "sample-sa"
	case "Service":
		return "sample-app"
	case "Role":
		return "sample-reader"
	case "RoleBinding":
		return "sample-reader-binding"
	case "PersistentVolumeClaim":
		return "sample-data"
	case "Ingress":
		return "sample-ingress"
	case "NetworkPolicy":
		return "default-deny"
	case "HorizontalPodAutoscaler":
		return "sample-app"
	case "Namespace":
		return "sample-namespace"
	case "Job":
		return "sample-job"
	case "CronJob":
		return "sample-cron"
	default:
		return "sample-app"
	}
}

func agentManifestTemplate(kind, apiVersion, namespace, name string) string {
	kind = canonicalManifestKind(kind)
	apiVersion = firstNonEmpty(apiVersion, agentManifestDefaultAPIVersion(kind))
	meta := []string{"metadata:", "  name: " + name}
	if !manifestKindClusterScoped(kind) && namespace != "" {
		meta = append(meta, "  namespace: "+namespace)
	}
	meta = append(meta, "  labels:", "    app.kubernetes.io/managed-by: clustara")
	m := strings.Join(meta, "\n")
	switch kind {
	case "Deployment":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: Deployment", m, "spec:", "  replicas: 1", "  selector:", "    matchLabels:", "      app: " + name, "  template:", "    metadata:", "      labels:", "        app: " + name, "    spec:", "      containers:", "      - name: app", "        image: nginx:stable", "        ports:", "        - containerPort: 80", "        resources:", "          requests:", "            cpu: 100m", "            memory: 128Mi", "          limits:", "            memory: 256Mi"}, "\n") + "\n"
	case "Service":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: Service", m, "spec:", "  type: ClusterIP", "  selector:", "    app: " + name, "  ports:", "  - name: http", "    port: 80", "    targetPort: 80"}, "\n") + "\n"
	case "ConfigMap":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: ConfigMap", m, "data:", "  APP_MODE: production"}, "\n") + "\n"
	case "Secret":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: Secret", m, "type: Opaque"}, "\n") + "\n"
	case "ServiceAccount":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: ServiceAccount", m, "automountServiceAccountToken: false"}, "\n") + "\n"
	case "Role":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: Role", m, "rules:", "- apiGroups: [\"\"]", "  resources: [\"pods\", \"pods/log\"]", "  verbs: [\"get\", \"list\", \"watch\"]"}, "\n") + "\n"
	case "RoleBinding":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: RoleBinding", m, "subjects:", "- kind: ServiceAccount", "  name: sample-sa", "  namespace: " + firstNonEmpty(namespace, "default"), "roleRef:", "  apiGroup: rbac.authorization.k8s.io", "  kind: Role", "  name: sample-reader"}, "\n") + "\n"
	case "PersistentVolumeClaim":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: PersistentVolumeClaim", m, "spec:", "  accessModes:", "  - ReadWriteOnce", "  resources:", "    requests:", "      storage: 1Gi"}, "\n") + "\n"
	case "Ingress":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: Ingress", m, "spec:", "  ingressClassName: nginx", "  rules:", "  - host: example.local", "    http:", "      paths:", "      - path: /", "        pathType: Prefix", "        backend:", "          service:", "            name: " + name, "            port:", "              number: 80"}, "\n") + "\n"
	case "NetworkPolicy":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: NetworkPolicy", m, "spec:", "  podSelector: {}", "  policyTypes:", "  - Ingress", "  - Egress"}, "\n") + "\n"
	case "HorizontalPodAutoscaler":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: HorizontalPodAutoscaler", m, "spec:", "  scaleTargetRef:", "    apiVersion: apps/v1", "    kind: Deployment", "    name: " + name, "  minReplicas: 1", "  maxReplicas: 3", "  metrics:", "  - type: Resource", "    resource:", "      name: cpu", "      target:", "        type: Utilization", "        averageUtilization: 70"}, "\n") + "\n"
	case "Namespace":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: Namespace", m}, "\n") + "\n"
	case "Job":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: Job", m, "spec:", "  template:", "    spec:", "      restartPolicy: Never", "      containers:", "      - name: job", "        image: busybox:1.36", "        command: [\"sh\", \"-c\", \"echo hello from clustara\"]", "  backoffLimit: 1"}, "\n") + "\n"
	case "CronJob":
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: CronJob", m, "spec:", "  schedule: \"*/15 * * * *\"", "  jobTemplate:", "    spec:", "      template:", "        spec:", "          restartPolicy: OnFailure", "          containers:", "          - name: job", "            image: busybox:1.36", "            command: [\"sh\", \"-c\", \"date\"]"}, "\n") + "\n"
	default:
		return strings.Join([]string{"apiVersion: " + apiVersion, "kind: " + kind, m, "spec: {}"}, "\n") + "\n"
	}
}

func agentManifestChecklist(operation, kind string) []string {
	checklist := []string{
		"생성/변경 사유, 장애번호 또는 변경번호가 충분한지 확인",
		"Diff, 위험도, 정책 위반, 승인 필요 사유를 Manifest Change Studio에서 검증",
		"적용 전 server dry-run과 admission warning 확인",
		"적용 직전 drift guard와 롤백 후보 확인",
	}
	switch canonicalManifestKind(kind) {
	case "Service":
		checklist = append(checklist, "Service selector와 port/targetPort가 실제 Pod label과 맞는지 확인")
	case "Ingress":
		checklist = append(checklist, "host, path, TLS, backend service가 운영 노출 정책과 맞는지 확인")
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
		checklist = append(checklist, "wildcard 권한, cluster-admin 유사 권한, subject 범위를 보안 담당자가 확인")
	case "NetworkPolicy":
		checklist = append(checklist, "기본 차단/허용 방향과 egress 범위가 서비스 통신에 미치는 영향 확인")
	case "Secret":
		checklist = append(checklist, "Secret 원문은 저장하지 않으므로 외부 Secret 관리 체계를 사용")
	}
	if operation == "create" {
		checklist = append(checklist, "같은 cluster/kind/namespace/name 대상이 이미 존재하지 않는지 확인")
	}
	return checklist
}

func agentManifestDraftNextSteps(d agentManifestDraft, created *store.K8sManifestChangeRequest) []string {
	if created == nil {
		return []string{"초안 YAML을 검토합니다.", "필요하면 Manifest Change 요청으로 저장합니다.", "저장 후 검증, 승인, 적용, 사후 검증 순서로 처리합니다."}
	}
	return []string{"Manifest Change Studio에서 요청 상세를 엽니다.", "검증(validate)을 실행합니다.", "승인 필요 시 승인함에서 승인합니다.", "Server-Side Apply 적용 후 사후 검증을 확인합니다."}
}

func agentManifestDraftIdempotency(in agentManifestDraftInput, d agentManifestDraft) string {
	base := strings.Join([]string{strings.TrimSpace(in.SessionID), d.Operation, d.ClusterID, d.Namespace, d.Kind, d.Name, d.YAML}, "\x00")
	sum := manifestHash(base)
	if len(sum) > 32 {
		sum = sum[:32]
	}
	return "agent-manifest:" + sum
}

func k8sManifestStudioHref(clusterID, kind, namespace, name, focusID string) string {
	q := []string{}
	add := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			q = append(q, k+"="+urlQueryEscape(v))
		}
	}
	add("cluster_id", clusterID)
	add("kind", kind)
	add("namespace", namespace)
	add("name", name)
	add("focus_id", focusID)
	if len(q) == 0 {
		return "#/k8s-manifest-changes"
	}
	return "#/k8s-manifest-changes?" + strings.Join(q, "&")
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

func (s *Server) recordAgentManifestDraftMessages(r *http.Request, in agentManifestDraftInput, d agentManifestDraft, created *store.K8sManifestChangeRequest) {
	sessionID := strings.TrimSpace(in.SessionID)
	if sessionID == "" {
		return
	}
	userContent := strings.TrimSpace(in.Prompt)
	if userContent == "" {
		userContent = "Manifest " + d.Operation + " draft requested for " + d.Namespace + "/" + d.Kind + "/" + d.Name
	}
	agentContent := fmt.Sprintf("YAML %s 초안을 준비했습니다: %s/%s/%s · risk=%s · blockers=%d · warnings=%d",
		d.Operation, d.Namespace, d.Kind, d.Name, asStr(d.Review["risk_level"]), len(d.Blockers), len(d.Warnings))
	if created != nil {
		agentContent += " · manifest_change=" + created.ID
	}
	ev, _ := json.Marshal(map[string]any{"review": d.Review, "checklist": d.Checklist, "blockers": d.Blockers, "warnings": d.Warnings})
	_ = s.db.AppendK8sAgentMessage(r.Context(), store.K8sAgentMessage{ID: newID("k8samsg"), SessionID: sessionID, Role: "user", Content: userContent, Intent: analyzer.IntentStack, CreatedAt: nowK8sAgentTime()})
	_ = s.db.AppendK8sAgentMessage(r.Context(), store.K8sAgentMessage{ID: newID("k8samsg"), SessionID: sessionID, Role: "agent", Content: agentContent, Intent: analyzer.IntentStack, Evidence: string(ev), LLMAvailable: false, CreatedAt: nowK8sAgentTime()})
}
