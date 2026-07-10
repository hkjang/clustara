package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

// handleK8sManifestEditor returns the resource picker metadata for Manifest Change Studio.
// GET /admin/k8s/manifests/editor?cluster_id=&kind=&namespace=
func (s *Server) handleK8sManifestEditor(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	clusters, _ := s.db.ListK8sClusters(r.Context())
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{
		ClusterID: strings.TrimSpace(q.Get("cluster_id")),
		Kind:      strings.TrimSpace(q.Get("kind")),
		Namespace: strings.TrimSpace(q.Get("namespace")),
		Limit:     manifestEditorLimit(q.Get("limit")),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_editor_failed")
		return
	}
	type resourceRow struct {
		ClusterID  string `json:"cluster_id"`
		Kind       string `json:"kind"`
		APIVersion string `json:"api_version"`
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		RiskLevel  string `json:"risk_level"`
		UpdatedAt  string `json:"updated_at"`
	}
	rows := make([]resourceRow, 0, len(items))
	kindSet := map[string]bool{}
	for _, k := range manifestEditorPreferredKinds() {
		kindSet[k] = true
	}
	for _, it := range items {
		kindSet[it.Kind] = true
		rows = append(rows, resourceRow{
			ClusterID: it.ClusterID, Kind: it.Kind, APIVersion: it.APIVersion, Namespace: it.Namespace,
			Name: it.Name, Status: it.Status, RiskLevel: it.RiskLevel, UpdatedAt: it.UpdatedAt,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		pi, pj := manifestEditorKindPriority(rows[i].Kind), manifestEditorKindPriority(rows[j].Kind)
		if pi != pj {
			return pi < pj
		}
		if rows[i].ClusterID != rows[j].ClusterID {
			return rows[i].ClusterID < rows[j].ClusterID
		}
		if rows[i].Namespace != rows[j].Namespace {
			return rows[i].Namespace < rows[j].Namespace
		}
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].Name < rows[j].Name
	})
	kinds := make([]string, 0, len(kindSet))
	for k := range kindSet {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	writeJSON(w, http.StatusOK, map[string]any{
		"clusters": clusters, "resources": rows, "resource_kinds": kinds,
		"note": "Manifest Change Studio는 live manifest를 편집 요청으로 저장한 뒤 검증, 승인, Server-Side Apply, 사후 검증 흐름으로 처리합니다.",
	})
}

func manifestEditorLimit(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 10000
	}
	return intParam(raw, 10000)
}

func manifestEditorPreferredKinds() []string {
	return []string{
		"Deployment", "StatefulSet", "DaemonSet", "Service", "Ingress", "ConfigMap", "Secret",
		"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding",
		"PersistentVolumeClaim", "NetworkPolicy", "HorizontalPodAutoscaler", "Pod", "Node",
	}
}

func manifestEditorKindPriority(kind string) int {
	for i, k := range manifestEditorPreferredKinds() {
		if strings.EqualFold(k, kind) {
			return i
		}
	}
	return 1000
}

// handleK8sManifestLive is the Manifest Studio alias of the read-only Manifest Viewer.
// GET /admin/k8s/manifests/live?cluster_id=&kind=&namespace=&name=
func (s *Server) handleK8sManifestLive(w http.ResponseWriter, r *http.Request) {
	s.handleK8sManifest(w, r)
}

// handleK8sManifestChanges lists or creates auditable YAML change requests.
// GET/POST /admin/k8s/manifest-changes
func (s *Server) handleK8sManifestChanges(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		rows, err := s.db.ListK8sManifestChangeRequests(r.Context(), store.K8sManifestChangeFilter{
			ClusterID: q.Get("cluster_id"), Status: q.Get("status"), Kind: q.Get("kind"),
			Namespace: q.Get("namespace"), Limit: intParam(q.Get("limit"), 100),
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_changes_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": rows, "count": len(rows)})
	case http.MethodPost:
		s.createK8sManifestChange(w, r)
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) createK8sManifestChange(w http.ResponseWriter, r *http.Request) {
	var in manifestChangeCreateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	in.IdempotencyKey = firstNonEmpty(in.IdempotencyKey, r.Header.Get("Idempotency-Key"))
	result, err := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), in)
	if err != nil {
		writeManifestChangeCreateError(w, err)
		return
	}
	event := "k8s.manifest_change.request"
	if result.Operation == "create" {
		event = "k8s.manifest_change.create_request"
	}
	if result.IdempotentReplay {
		event += ".replay"
	}
	s.auditAdmin(r, event, "", auditJSON(map[string]any{
		"id": result.Request.ID, "cluster_id": result.Request.ClusterID, "kind": result.Request.Kind,
		"namespace": result.Request.Namespace, "name": result.Request.Name, "risk": result.Request.RiskLevel,
		"operation": result.Operation,
	}))
	status := http.StatusCreated
	if result.IdempotentReplay {
		status = http.StatusOK
	}
	writeJSON(w, status, manifestChangeCreateResponse(result))
}

type manifestChangeCreateInput struct {
	ClusterID      string `json:"cluster_id"`
	Namespace      string `json:"namespace"`
	Kind           string `json:"kind"`
	APIVersion     string `json:"api_version"`
	Name           string `json:"name"`
	Operation      string `json:"operation"`
	AfterYAML      string `json:"after_yaml"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key"`
}

type manifestChangeCreateResult struct {
	Request          store.K8sManifestChangeRequest
	Impact           map[string]any
	Diffs            []store.K8sManifestFieldDiff
	Operation        string
	IdempotentReplay bool
	Note             string
}

type manifestChangeCreateError struct {
	status  int
	message string
	code    string
}

func (e manifestChangeCreateError) Error() string { return e.message }

func manifestChangeCreateHTTPError(status int, message, code string) manifestChangeCreateError {
	return manifestChangeCreateError{status: status, message: message, code: code}
}

func writeManifestChangeCreateError(w http.ResponseWriter, err error) {
	var ce manifestChangeCreateError
	if errors.As(err, &ce) {
		errType := "invalid_request_error"
		if ce.status >= 500 {
			errType = "server_error"
		}
		writeOpenAIError(w, ce.status, ce.message, errType, ce.code)
		return
	}
	writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
}

func manifestChangeCreateResponse(result manifestChangeCreateResult) map[string]any {
	return map[string]any{
		"request":           result.Request,
		"impact":            result.Impact,
		"diffs":             result.Diffs,
		"operation":         result.Operation,
		"idempotent_replay": result.IdempotentReplay,
		"note":              result.Note,
	}
}

func (s *Server) prepareK8sManifestChangeRequest(ctx context.Context, actor string, in manifestChangeCreateInput) (manifestChangeCreateResult, error) {
	clusterID := strings.TrimSpace(in.ClusterID)
	operation, err := normalizeManifestChangeOperation(in.Operation)
	if err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusBadRequest, err.Error(), "invalid_manifest_operation")
	}
	kind := canonicalManifestKind(strings.TrimSpace(in.Kind))
	namespace := strings.TrimSpace(in.Namespace)
	name := strings.TrimSpace(in.Name)
	afterRaw := strings.TrimSpace(in.AfterYAML)
	if clusterID == "" || afterRaw == "" {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusBadRequest, "cluster_id and after_yaml are required", "missing_fields")
	}
	afterDoc, err := parseSingleManifestDoc(afterRaw)
	if err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusBadRequest, "after_yaml parse error: "+err.Error(), "manifest_parse_failed")
	}
	docAPIVersion, docKind, docNamespace, docName := manifestDocIdentity(afterDoc)
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
	if err := ensureManifestDocTarget(afterDoc, kind, namespace, name); err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusBadRequest, err.Error(), "manifest_target_mismatch")
	}
	apiVersion := firstNonEmpty(strings.TrimSpace(in.APIVersion), docAPIVersion)
	if clusterID == "" || kind == "" || name == "" || apiVersion == "" {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusBadRequest, "cluster_id, apiVersion, kind, name and after_yaml are required", "missing_fields")
	}
	idempotencyKey := strings.TrimSpace(in.IdempotencyKey)
	if idempotencyKey != "" {
		existing, err := s.db.GetK8sManifestChangeRequestByIdempotencyKey(ctx, idempotencyKey)
		if err == nil {
			return manifestChangeCreateResult{
				Request:          existing,
				Impact:           existing.Impact,
				Diffs:            existing.Diffs,
				Operation:        manifestChangeOperation(existing),
				IdempotentReplay: true,
				Note:             "동일 idempotency key의 기존 요청을 반환했습니다.",
			}, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_manifest_change_idempotency_lookup_failed")
		}
	}
	if operation == "create" {
		return s.prepareK8sManifestCreateRequest(ctx, actor, clusterID, namespace, kind, apiVersion, name, afterDoc, strings.TrimSpace(in.Reason), idempotencyKey)
	}
	item, err := s.db.GetK8sInventoryItem(ctx, clusterID, kind, namespace, name)
	if errors.Is(err, store.ErrNotFound) {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusNotFound, "live resource not found; 신규 리소스 생성은 operation=create로 요청하세요", "resource_not_found")
	}
	if err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_inventory_failed")
	}
	if err := validateManifestTarget(afterDoc, item); err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusBadRequest, err.Error(), "manifest_target_mismatch")
	}
	beforeDoc := sanitizeManifestDocForLedger(assembleManifest(item))
	beforeYAML := mustManifestYAML(beforeDoc)
	storeAfterDoc := sanitizeManifestDocForLedger(afterDoc)
	afterYAML := mustManifestYAML(storeAfterDoc)
	diffs := diffManifestDocs(beforeDoc, storeAfterDoc)
	policies, _ := s.db.ListK8sPolicies(ctx)
	plan := analyzer.AnalyzeStackManifest([]map[string]any{afterDoc}, toAnalyzerPolicies(policies))
	impact, risk, requiresApproval := manifestChangeImpact(item, afterDoc, diffs, plan)
	if strings.EqualFold(kind, "Secret") && manifestContainsSecretPayload(afterDoc) {
		requiresApproval = true
		risk = "critical"
		impact["secret_payload_guard"] = manifestSecretPayloadGuidance("update")
	}
	req := store.K8sManifestChangeRequest{
		ID: newID("k8smchg"), ClusterID: clusterID, Namespace: namespace, Kind: item.Kind, APIVersion: firstNonEmpty(apiVersion, item.APIVersion),
		Name: item.Name, Status: "draft", RiskLevel: risk, RequiresApproval: requiresApproval, Reason: strings.TrimSpace(in.Reason),
		BeforeYAML: beforeYAML, AfterYAML: afterYAML, BeforeHash: manifestHash(beforeYAML), AfterHash: manifestHash(afterYAML),
		Diffs: diffs, Impact: impact, CreatedBy: actor, IdempotencyKey: idempotencyKey,
		TargetUID: item.UID, TargetResourceVersion: k8sActionTargetResourceVersion(item),
		Result: "변경 요청 생성됨. validate를 실행해 schema/policy/server dry-run을 확인하세요.",
	}
	if err := s.db.CreateK8sManifestChangeRequest(ctx, req); err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_manifest_change_save_failed")
	}
	return manifestChangeCreateResult{
		Request: req, Impact: impact, Diffs: diffs, Operation: "update",
		Note: "요청이 draft로 저장되었습니다. validate 후 위험도에 따라 승인 또는 바로 적용할 수 있습니다.",
	}, nil
}

func (s *Server) prepareK8sManifestCreateRequest(ctx context.Context, actor, clusterID, namespace, kind, apiVersion, name string, afterDoc map[string]any, reason, idempotencyKey string) (manifestChangeCreateResult, error) {
	if _, err := s.db.GetK8sCluster(ctx, clusterID); errors.Is(err, store.ErrNotFound) {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusNotFound, "cluster not found: "+clusterID, "k8s_cluster_not_found")
	} else if err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_cluster_failed")
	}
	if existing, err := s.db.GetK8sInventoryItem(ctx, clusterID, kind, namespace, name); err == nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusConflict, fmt.Sprintf("resource already exists: %s/%s/%s (uid=%s)", kind, namespace, name, existing.UID), "manifest_create_target_exists")
	} else if !errors.Is(err, store.ErrNotFound) {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_inventory_failed")
	}
	storeAfterDoc := sanitizeManifestDocForLedger(afterDoc)
	afterYAML := mustManifestYAML(storeAfterDoc)
	diffs := diffManifestDocs(map[string]any{}, storeAfterDoc)
	policies, _ := s.db.ListK8sPolicies(ctx)
	plan := analyzer.AnalyzeStackManifest([]map[string]any{afterDoc}, toAnalyzerPolicies(policies))
	item := store.K8sInventoryItem{ClusterID: clusterID, Namespace: namespace, Kind: kind, APIVersion: apiVersion, Name: name}
	impact, risk, requiresApproval := manifestCreateImpact(item, afterDoc, diffs, plan)
	if strings.EqualFold(kind, "Secret") && manifestContainsSecretPayload(afterDoc) {
		requiresApproval = true
		risk = "critical"
		impact["secret_payload_guard"] = manifestSecretPayloadGuidance("create")
	}
	req := store.K8sManifestChangeRequest{
		ID: newID("k8smchg"), ClusterID: clusterID, Namespace: namespace, Kind: kind, APIVersion: apiVersion,
		Name: name, Status: "draft", RiskLevel: risk, RequiresApproval: requiresApproval, Reason: reason,
		BeforeYAML: "", AfterYAML: afterYAML, BeforeHash: manifestHash(""), AfterHash: manifestHash(afterYAML),
		Diffs: diffs, Impact: impact, CreatedBy: actor, IdempotencyKey: idempotencyKey,
		Result: "생성 요청 생성됨. validate를 실행해 schema/policy/server dry-run을 확인하세요.",
	}
	if err := s.db.CreateK8sManifestChangeRequest(ctx, req); err != nil {
		return manifestChangeCreateResult{}, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_manifest_create_save_failed")
	}
	return manifestChangeCreateResult{
		Request: req, Impact: impact, Diffs: diffs, Operation: "create",
		Note: "신규 리소스 생성 요청이 draft로 저장되었습니다. validate 후 승인/적용하세요.",
	}, nil
}

// handleK8sManifestChangeByID returns detail or dispatches validate/impact/approve/reject/apply/verify/export.
// GET /admin/k8s/manifest-changes/{id}
// POST /admin/k8s/manifest-changes/{id}/validate|impact|approve|reject|apply|verify|rollback
func (s *Server) handleK8sManifestChangeByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/manifest-changes/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "manifest change id required", "invalid_request_error", "missing_manifest_change_id")
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.writeK8sManifestChangeDetail(w, r, id)
		return
	}
	switch parts[1] {
	case "brief":
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.writeK8sManifestChangeBrief(w, r, id)
	case "evidence":
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.writeK8sManifestChangeEvidence(w, r, id)
	case "git-patch":
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.writeK8sManifestChangePatch(w, r, id)
	default:
		if r.Method != http.MethodPost {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		switch parts[1] {
		case "validate", "impact":
			s.validateK8sManifestChange(w, r, id)
		case "approve", "reject":
			s.decideK8sManifestChange(w, r, id, parts[1])
		case "apply":
			s.applyK8sManifestChange(w, r, id)
		case "verify":
			s.verifyK8sManifestChange(w, r, id)
		case "rollback":
			s.rollbackK8sManifestChange(w, r, id)
		default:
			writeOpenAIError(w, http.StatusNotFound, "unknown manifest change command", "invalid_request_error", "unknown_manifest_change_command")
		}
	}
}

func (s *Server) writeK8sManifestChangeDetail(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": req})
}

func (s *Server) writeK8sManifestChangeBrief(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	driftGuard := s.manifestChangeDriftGuard(r.Context(), req)
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id":  req.ID,
		"brief":       manifestChangeBrief(req, driftGuard),
		"drift_guard": driftGuard,
	})
}

func (s *Server) validateK8sManifestChange(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	docs, err := decodeManifestDocs(req.AfterYAML)
	if err != nil || len(docs) != 1 {
		writeOpenAIError(w, http.StatusBadRequest, "stored manifest parse error", "invalid_request_error", "manifest_parse_failed")
		return
	}
	policies, _ := s.db.ListK8sPolicies(r.Context())
	plan := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
	validation := map[string]any{
		"schema": map[string]any{"status": "basic_passed", "checked": []string{"apiVersion", "kind", "metadata.name"}},
		"policy": map[string]any{"denied": plan.Denied, "violations": plan.PolicyViolations, "approval_reasons": plan.ApprovalReasons},
	}
	status := "validated"
	result := "schema/policy passed"
	requiresApproval := req.RequiresApproval || plan.RequiresApproval
	risk := manifestRiskMax(req.RiskLevel, "low")
	if strings.EqualFold(req.Kind, "Secret") && manifestContainsSecretPayload(docs[0]) {
		validation["secret_payload_guard"] = map[string]any{
			"status":   "blocked",
			"reason":   "Secret data/stringData payload is not stored or applied by Manifest Change Studio",
			"guidance": manifestSecretPayloadGuidance(manifestChangeOperation(req)),
		}
		status = "failed"
		risk = "blocked"
		requiresApproval = true
		result = "Secret payload changes are blocked; use Config Change Control or an external Secret manager"
	}
	if plan.RequiresApproval && riskRank(risk) < riskRank("medium") {
		risk = "medium"
	}
	if status == "failed" {
		// Guarded before live dry-run so masked Secret bodies can never be sent back to the API server.
	} else if plan.Denied {
		status = "failed"
		risk = "blocked"
		result = "policy denied"
	} else {
		cluster, cErr := s.db.GetK8sCluster(r.Context(), req.ClusterID)
		if cErr != nil {
			validation["dry_run"] = map[string]any{"status": "skipped", "error": cErr.Error()}
		} else if client, cErr := s.k8sClientForCluster(r.Context(), cluster); cErr != nil {
			validation["dry_run"] = map[string]any{"status": "skipped", "error": cErr.Error()}
		} else if applier, ok := client.(kube.StackApplier); !ok {
			validation["dry_run"] = map[string]any{"status": "unsupported", "error": "cluster client does not support apply"}
		} else {
			yml := []byte(req.AfterYAML)
			if aErr := applier.Apply(r.Context(), req.APIVersion, req.Kind, req.Namespace, req.Name, yml, true); aErr != nil {
				validation["dry_run"] = map[string]any{"status": "failed", "error": aErr.Error()}
				status = "failed"
				risk = "blocked"
				result = "server dry-run failed: " + aErr.Error()
			} else {
				validation["dry_run"] = map[string]any{"status": "passed", "mode": "dryRun=All"}
			}
		}
	}
	if status == "validated" && requiresApproval {
		status = "approval_required"
		result = "검증 통과, 승인 필요"
	}
	if err := s.db.UpdateK8sManifestChangeAnalysis(r.Context(), id, status, risk, requiresApproval, req.Impact, validation, result); errors.Is(err, store.ErrInvalidTransition) {
		writeOpenAIError(w, http.StatusConflict, "manifest change cannot transition from current state", "invalid_request_error", "manifest_change_bad_state")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_validate_failed")
		return
	}
	s.auditAdmin(r, "k8s.manifest_change.validate", id, auditJSON(map[string]any{"status": status, "risk": risk}))
	updated, _ := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"request": updated, "validation": validation, "plan": plan})
}

func manifestSecretPayloadGuidance(operation string) map[string]any {
	return map[string]any{
		"operation":    operation,
		"why_blocked":  "Secret data/stringData 원문은 변경 원장, 감사 증적, 응답에 남길 수 없어 Manifest Change Studio에서 처리하지 않습니다.",
		"allowed_here": []string{"metadata.name/namespace", "type", "labels", "annotations"},
		"next_actions": []string{
			"기존 Secret 변경은 Config Change Control에서 값 원문 없이 영향도와 승인 기록을 생성하세요.",
			"실제 값 주입은 ExternalSecret, SealedSecret 또는 조직 Secret Manager를 사용하세요.",
			"레지스트리 인증은 정책 센터의 Pull Secret 생성기를 사용하고 생성 결과를 안전한 경로로 적용하세요.",
		},
	}
}

func (s *Server) decideK8sManifestChange(w http.ResponseWriter, r *http.Request, id, command string) {
	var in struct {
		Result string `json:"result"`
		Note   string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	status := "approved"
	if command == "reject" {
		status = "rejected"
	}
	msg := strings.TrimSpace(firstNonEmpty(in.Result, in.Note))
	if err := s.db.UpdateK8sManifestChangeStatus(r.Context(), id, status, adminID(r), msg); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	} else if errors.Is(err, store.ErrInvalidTransition) {
		writeOpenAIError(w, http.StatusConflict, "manifest change cannot transition from current state", "invalid_request_error", "manifest_change_bad_state")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_decision_failed")
		return
	}
	s.auditAdmin(r, "k8s.manifest_change."+command, id, auditJSON(map[string]any{"status": status}))
	req, _ := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"request": req})
}

func (s *Server) applyK8sManifestChange(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		ForceDrift bool   `json:"force_drift"`
		Force      bool   `json:"force"`
		Note       string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	if req.RequiresApproval && req.Status != "approved" {
		writeOpenAIError(w, http.StatusPreconditionRequired, "approval required before apply (current: "+req.Status+")", "invalid_request_error", "manifest_change_approval_required")
		return
	}
	if !req.RequiresApproval && req.Status != "validated" && req.Status != "approved" {
		writeOpenAIError(w, http.StatusConflict, "manifest change must be validated or approved before apply (current: "+req.Status+")", "invalid_request_error", "manifest_change_not_ready")
		return
	}
	driftGuard := s.manifestChangeDriftGuard(r.Context(), req)
	forceDrift := in.ForceDrift || in.Force
	if manifestChangeDriftBlocks(driftGuard, forceDrift) {
		errMsg := "live manifest changed after this request was created"
		nextActions := []string{"새 live YAML을 다시 불러와 변경 요청을 재생성하세요.", "의도한 덮어쓰기라면 force_drift=true로 재시도할 수 있습니다. UID 변경이나 삭제는 force로도 차단됩니다."}
		if manifestChangeOperation(req) == "create" {
			errMsg = "create target already exists"
			nextActions = []string{"이미 생성된 리소스를 확인하세요.", "기존 리소스를 수정하려면 변경 모드에서 live YAML을 불러와 새 요청을 만드세요."}
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"request_id":   id,
			"status":       "blocked",
			"error":        errMsg,
			"drift_guard":  driftGuard,
			"next_actions": nextActions,
		})
		return
	}
	if forceDrift && strings.EqualFold(asStr(driftGuard["status"]), "drift") {
		driftGuard["status"] = "overridden"
		driftGuard["override_note"] = strings.TrimSpace(in.Note)
		driftGuard["overridden_by"] = adminID(r)
	}
	if err := s.db.UpdateK8sManifestChangeStatus(r.Context(), id, "running", adminID(r), "SSA apply running"); err != nil {
		if errors.Is(err, store.ErrInvalidTransition) {
			writeOpenAIError(w, http.StatusConflict, "manifest change cannot transition to running", "invalid_request_error", "manifest_change_bad_state")
			return
		}
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_running_failed")
		return
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), req.ClusterID)
	if err != nil {
		s.finishManifestApplyFailure(r, id, map[string]any{"error": err.Error()})
		writeOpenAIError(w, http.StatusBadRequest, "cluster not found: "+err.Error(), "invalid_request_error", "k8s_cluster_failed")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		s.finishManifestApplyFailure(r, id, map[string]any{"error": err.Error()})
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	applier, ok := client.(kube.StackApplier)
	if !ok {
		s.finishManifestApplyFailure(r, id, map[string]any{"error": "applier unsupported"})
		writeOpenAIError(w, http.StatusNotImplemented, "이 클러스터 클라이언트는 apply를 지원하지 않습니다.", "invalid_request_error", "applier_unsupported")
		return
	}
	applyYAML := []byte(req.AfterYAML)
	if aErr := applier.Apply(r.Context(), req.APIVersion, req.Kind, req.Namespace, req.Name, applyYAML, false); aErr != nil {
		result := map[string]any{"status": "failed", "error": aErr.Error(), "field_manager": "clustara", "drift_guard": driftGuard}
		_ = s.db.UpdateK8sManifestChangeApplyResult(r.Context(), id, "failed", adminID(r), result, aErr.Error())
		writeJSON(w, http.StatusBadGateway, map[string]any{"request_id": id, "status": "failed", "apply_result": result})
		return
	}
	result := map[string]any{"status": "applied", "field_manager": "clustara", "applied_at": time.Now().UTC().Format(time.RFC3339Nano), "drift_guard": driftGuard}
	if err := s.db.UpdateK8sManifestChangeApplyResult(r.Context(), id, "applied", adminID(r), result, "SSA apply succeeded"); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_finalize_failed")
		return
	}
	s.registerCollectBurst(r.Context(), req.ClusterID, req.Namespace, "manifest_change", "manifest_change:"+req.Kind+"/"+req.Name)
	s.auditAdmin(r, "k8s.manifest_change.apply", id, auditJSON(map[string]any{"status": "applied", "kind": req.Kind, "name": req.Name}))
	updated, _ := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"request": updated, "apply_result": result})
}

func (s *Server) finishManifestApplyFailure(r *http.Request, id string, result map[string]any) {
	if result["status"] == nil {
		result["status"] = "failed"
	}
	_ = s.db.UpdateK8sManifestChangeApplyResult(r.Context(), id, "failed", adminID(r), result, fmt.Sprint(result["error"]))
}

func (s *Server) verifyK8sManifestChange(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	if req.Status != "applied" && req.Status != "verify_failed" {
		writeOpenAIError(w, http.StatusConflict, "manifest change must be applied before verification (current: "+req.Status+")", "invalid_request_error", "manifest_change_not_applied")
		return
	}
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: req.ClusterID, Limit: 5000})
	events, _ := s.db.ListK8sEvents(r.Context(), req.ClusterID, 500)
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: req.ClusterID, Status: "open", Limit: 200})
	appliedAt := parseConfigChangeTime(firstNonEmpty(req.AppliedAt, req.UpdatedAt, req.CreatedAt))
	found := false
	refreshed := false
	unhealthy := false
	resourceState := "unknown"
	reasonCodes := []string{}
	verificationSource := "inventory"
	liveReadError := ""
	for _, it := range items {
		if strings.EqualFold(it.Kind, req.Kind) && manifestNamespaceEqual(it.Namespace, req.Namespace) && it.Name == req.Name {
			found = true
			if !appliedAt.IsZero() && !parseConfigChangeTime(firstNonEmpty(it.ObservedAt, it.UpdatedAt)).Before(appliedAt) {
				refreshed = true
			}
			unhealthy, resourceState, reasonCodes = configChangeHealth(it)
			break
		}
	}
	// Prefer a direct API-server observation when the cluster client supports it. Inventory remains
	// the compatibility fallback for agents and test clients that only implement collection/apply.
	if cluster, getErr := s.db.GetK8sCluster(r.Context(), req.ClusterID); getErr == nil {
		if client, clientErr := s.k8sClientForCluster(r.Context(), cluster); clientErr == nil {
			if getter, ok := client.(kube.ResourceGetter); ok {
				if live, liveErr := getter.GetResource(r.Context(), req.APIVersion, req.Kind, req.Namespace, req.Name); liveErr == nil {
					item := manifestInventoryFromLive(req, live)
					found, refreshed, verificationSource = true, true, "api_server"
					unhealthy, resourceState, reasonCodes = configChangeHealth(item)
				} else {
					liveReadError = liveErr.Error()
				}
			}
		}
	}
	warnings := 0
	for _, ev := range events {
		if !appliedAt.IsZero() && parseConfigChangeTime(firstNonEmpty(ev.LastSeen, ev.CreatedAt)).Before(appliedAt) {
			continue
		}
		if strings.EqualFold(ev.Type, "Warning") && manifestNamespaceEqual(ev.Namespace, req.Namespace) &&
			((strings.EqualFold(ev.InvolvedKind, req.Kind) && ev.InvolvedName == req.Name) ||
				(strings.EqualFold(req.Kind, "Job") && strings.EqualFold(ev.InvolvedKind, "Pod") && strings.HasPrefix(ev.InvolvedName, req.Name+"-"))) {
			warnings++
		}
	}
	openIncidents := 0
	for _, inc := range incidents {
		if inc.ClusterID == req.ClusterID && manifestNamespaceEqual(inc.Namespace, req.Namespace) && strings.EqualFold(inc.Kind, req.Kind) && inc.Name == req.Name {
			openIncidents++
		}
	}
	// Decide the verification outcome.
	//
	// `found`/`unhealthy` are only trustworthy once the inventory collector has re-observed
	// the resource after apply (`refreshed`); before that they still reflect pre-apply state,
	// so a freshly created/changed resource would otherwise be misjudged. `warnings` (already
	// filtered to events at/after apply) and open `openIncidents` are post-apply signals and
	// apply regardless of the refresh timing.
	//
	// The apply step itself already confirmed the API server accepted the change. A collector timing
	// gap is recorded separately as observation_pending; warnings are also preserved as
	// verified_with_warning instead of being reported as execution failure.
	verifyStatus := "verified"
	resultStatus := "passed"
	switch {
	case refreshed && (!found || unhealthy):
		verifyStatus = "verify_failed"
		resultStatus = "execution_failed"
	case openIncidents > 0:
		verifyStatus = "verify_failed"
		resultStatus = "incident_detected"
	case !refreshed:
		resultStatus = "observation_pending"
		reasonCodes = append(reasonCodes, "inventory_not_refreshed")
	case warnings > 0:
		resultStatus = "verified_with_warning"
		reasonCodes = append(reasonCodes, "warning_events_present")
	}
	result := map[string]any{
		"status": resultStatus, "resource_found": found, "refreshed_after_apply": refreshed,
		"unhealthy": unhealthy, "warning_events": warnings, "open_incidents": openIncidents,
		"resource_state": resourceState, "reason_codes": reasonCodes, "verification_source": verificationSource,
	}
	if liveReadError != "" {
		result["live_read_error"] = liveReadError
	}
	if err := s.db.UpdateK8sManifestChangeVerifyResult(r.Context(), id, verifyStatus, adminID(r), result, "verification: "+resultStatus); err != nil {
		if errors.Is(err, store.ErrInvalidTransition) {
			writeOpenAIError(w, http.StatusConflict, "manifest change cannot transition from current state", "invalid_request_error", "manifest_change_bad_state")
			return
		}
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_verify_failed")
		return
	}
	s.auditAdmin(r, "k8s.manifest_change.verify", id, auditJSON(result))
	updated, _ := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"request": updated, "verification": result})
}

func manifestNamespaceEqual(a, b string) bool {
	normalize := func(ns string) string {
		if strings.TrimSpace(ns) == "" {
			return "default"
		}
		return strings.TrimSpace(ns)
	}
	return normalize(a) == normalize(b)
}

func manifestInventoryFromLive(req store.K8sManifestChangeRequest, live map[string]any) store.K8sInventoryItem {
	metadata := manifestAnyMap(live["metadata"])
	return store.K8sInventoryItem{
		ClusterID: req.ClusterID, Kind: firstNonEmpty(asStr(live["kind"]), req.Kind),
		APIVersion: firstNonEmpty(asStr(live["apiVersion"]), req.APIVersion),
		Namespace:  firstNonEmpty(asStr(metadata["namespace"]), req.Namespace), Name: firstNonEmpty(asStr(metadata["name"]), req.Name),
		Spec: manifestAnyMap(live["spec"]), StatusObject: manifestAnyMap(live["status"]), Status: manifestLiveStatus(req.Kind, manifestAnyMap(live["status"])),
	}
}

func manifestAnyMap(v any) map[string]any {
	if out, ok := v.(map[string]any); ok {
		return out
	}
	return map[string]any{}
}

func manifestLiveStatus(kind string, status map[string]any) string {
	if !strings.EqualFold(kind, "Job") {
		return firstNonEmpty(asStr(status["phase"]), "Observed")
	}
	for _, raw := range anySlice(status["conditions"]) {
		condition, _ := raw.(map[string]any)
		if strings.EqualFold(asStr(condition["status"]), "True") {
			if strings.EqualFold(asStr(condition["type"]), "Failed") {
				return "Failed"
			}
			if strings.EqualFold(asStr(condition["type"]), "Complete") {
				return "Succeeded"
			}
		}
	}
	if anyInt(status["active"]) > 0 {
		return "Running"
	}
	return "Pending"
}

func (s *Server) rollbackK8sManifestChange(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	rollbackReq := store.K8sManifestChangeRequest{
		ID: newID("k8smchg"), ClusterID: req.ClusterID, Namespace: req.Namespace, Kind: req.Kind, APIVersion: req.APIVersion,
		Name: req.Name, Status: "draft", RiskLevel: req.RiskLevel, RequiresApproval: true,
		Reason: "rollback request from " + req.ID, BeforeYAML: req.AfterYAML, AfterYAML: req.BeforeYAML,
		BeforeHash: req.AfterHash, AfterHash: req.BeforeHash, Diffs: diffYAMLText(req.AfterYAML, req.BeforeYAML),
		Impact:    map[string]any{"rollback_from": req.ID, "rollback_candidate": "before_yaml"},
		CreatedBy: adminID(r), TargetUID: req.TargetUID, TargetResourceVersion: req.TargetResourceVersion,
		Result: "Rollback 후보 요청 생성됨. validate 후 승인/적용하세요.",
	}
	if err := s.db.CreateK8sManifestChangeRequest(r.Context(), rollbackReq); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_rollback_save_failed")
		return
	}
	_ = s.db.UpdateK8sManifestChangeStatus(r.Context(), id, "rollback_requested", adminID(r), "rollback request: "+rollbackReq.ID)
	s.auditAdmin(r, "k8s.manifest_change.rollback", id, auditJSON(map[string]any{"rollback_request": rollbackReq.ID}))
	writeJSON(w, http.StatusCreated, map[string]any{"request": rollbackReq, "source": req.ID})
}

func (s *Server) writeK8sManifestChangeEvidence(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	md := manifestChangeEvidenceMarkdown(req)
	sum := sha256.Sum256([]byte(md))
	writeJSON(w, http.StatusOK, map[string]any{"request_id": req.ID, "bundle_hash": hex.EncodeToString(sum[:]), "markdown": md})
}

func (s *Server) writeK8sManifestChangePatch(w http.ResponseWriter, r *http.Request, id string) {
	req, err := s.db.GetK8sManifestChangeRequest(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "manifest change not found: "+id, "invalid_request_error", "manifest_change_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_change_failed")
		return
	}
	patch := manifestChangePseudoPatch(req)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(patch))
}

func parseSingleManifestDoc(raw string) (map[string]any, error) {
	docs, err := decodeManifestDocs(raw)
	if err != nil {
		return nil, err
	}
	if len(docs) != 1 {
		return nil, fmt.Errorf("exactly one Kubernetes resource document is required")
	}
	if strings.TrimSpace(asStr(docs[0]["apiVersion"])) == "" || strings.TrimSpace(asStr(docs[0]["kind"])) == "" {
		return nil, fmt.Errorf("apiVersion and kind are required")
	}
	meta, _ := docs[0]["metadata"].(map[string]any)
	if strings.TrimSpace(asStr(meta["name"])) == "" {
		return nil, fmt.Errorf("metadata.name is required")
	}
	return docs[0], nil
}

func normalizeManifestChangeOperation(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "update", "edit", "change", "patch":
		return "update", nil
	case "create", "new":
		return "create", nil
	default:
		return "", fmt.Errorf("operation must be update or create")
	}
}

func manifestDocIdentity(doc map[string]any) (apiVersion, kind, namespace, name string) {
	apiVersion = strings.TrimSpace(asStr(doc["apiVersion"]))
	kind = canonicalManifestKind(strings.TrimSpace(asStr(doc["kind"])))
	meta, _ := doc["metadata"].(map[string]any)
	namespace = strings.TrimSpace(asStr(meta["namespace"]))
	name = strings.TrimSpace(asStr(meta["name"]))
	return apiVersion, kind, namespace, name
}

func ensureManifestDocTarget(doc map[string]any, kind, namespace, name string) error {
	apiVersion, docKind, docNamespace, docName := manifestDocIdentity(doc)
	if apiVersion == "" || docKind == "" || docName == "" {
		return fmt.Errorf("apiVersion, kind and metadata.name are required")
	}
	if namespace == "" && !manifestKindClusterScoped(kind) {
		namespace = "default"
	}
	if docNamespace == "" && !manifestKindClusterScoped(kind) {
		meta, _ := doc["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
			doc["metadata"] = meta
		}
		meta["namespace"] = namespace
		docNamespace = namespace
	}
	if !strings.EqualFold(docKind, kind) || docName != name || docNamespace != namespace {
		return fmt.Errorf("manifest target mismatch: expected %s/%s/%s, got %s/%s/%s", kind, namespace, name, docKind, docNamespace, docName)
	}
	return nil
}

func canonicalManifestKind(kind string) string {
	normalized := strings.ToLower(strings.TrimSpace(kind))
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.ReplaceAll(normalized, "_", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, ".", "")
	switch normalized {
	case "cm", "configmap", "configmaps":
		return "ConfigMap"
	case "secret", "secrets":
		return "Secret"
	case "sa", "serviceaccount", "serviceaccounts":
		return "ServiceAccount"
	case "svc", "service", "services":
		return "Service"
	case "pvc", "pvcs", "persistentvolumeclaim", "persistentvolumeclaims", "persistancevolumeclaim", "persistancevolumeclaims":
		return "PersistentVolumeClaim"
	case "ing", "ingress", "ingresses":
		return "Ingress"
	case "netpol", "networkpolicy", "networkpolicies":
		return "NetworkPolicy"
	case "hpa", "horizontalpodautoscaler", "horizontalpodautoscalers":
		return "HorizontalPodAutoscaler"
	case "deploy", "deployment", "deployments":
		return "Deployment"
	case "sts", "statefulset", "statefulsets":
		return "StatefulSet"
	case "ds", "daemonset", "daemonsets":
		return "DaemonSet"
	case "job", "jobs":
		return "Job"
	case "cronjob", "cronjobs":
		return "CronJob"
	case "role", "roles":
		return "Role"
	case "rb", "rolebinding", "rolebindings":
		return "RoleBinding"
	case "cr", "clusterrole", "clusterroles":
		return "ClusterRole"
	case "crb", "clusterrolebinding", "clusterrolebindings":
		return "ClusterRoleBinding"
	case "ns", "namespace", "namespaces":
		return "Namespace"
	case "pod", "pods":
		return "Pod"
	default:
		return strings.TrimSpace(kind)
	}
}

func manifestKindClusterScoped(kind string) bool {
	switch canonicalManifestKind(kind) {
	case "Namespace", "Node", "PersistentVolume", "ClusterRole", "ClusterRoleBinding", "StorageClass", "CustomResourceDefinition", "PriorityClass", "ClusterIssuer":
		return true
	default:
		return false
	}
}

func validateManifestTarget(doc map[string]any, item store.K8sInventoryItem) error {
	kind := canonicalManifestKind(strings.TrimSpace(asStr(doc["kind"])))
	meta, _ := doc["metadata"].(map[string]any)
	name := strings.TrimSpace(asStr(meta["name"]))
	ns := strings.TrimSpace(asStr(meta["namespace"]))
	if ns == "" {
		ns = item.Namespace
	}
	if !strings.EqualFold(kind, item.Kind) || name != item.Name || ns != item.Namespace {
		return fmt.Errorf("manifest target mismatch: expected %s/%s/%s, got %s/%s/%s", item.Kind, item.Namespace, item.Name, kind, ns, name)
	}
	return nil
}

func mustManifestYAML(doc map[string]any) string {
	b, err := yaml.Marshal(doc)
	if err != nil {
		return ""
	}
	return string(b)
}

func sanitizeManifestDocForLedger(doc map[string]any) map[string]any {
	out := maskManifestValue(doc).(map[string]any)
	delete(out, "status")
	if meta, ok := out["metadata"].(map[string]any); ok {
		for _, k := range []string{"uid", "resourceVersion", "generation", "managedFields", "creationTimestamp", "deletionTimestamp", "selfLink"} {
			delete(meta, k)
		}
	}
	return out
}

func manifestContainsSecretPayload(doc map[string]any) bool {
	if !strings.EqualFold(asStr(doc["kind"]), "Secret") {
		return false
	}
	_, hasData := doc["data"]
	_, hasStringData := doc["stringData"]
	return hasData || hasStringData
}

func manifestHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Server) manifestChangeDriftGuard(ctx context.Context, req store.K8sManifestChangeRequest) map[string]any {
	guard := map[string]any{
		"status":                  "passed",
		"operation":               manifestChangeOperation(req),
		"expected_before_hash":    req.BeforeHash,
		"target_uid":              req.TargetUID,
		"target_resource_version": req.TargetResourceVersion,
		"checked_at":              time.Now().UTC().Format(time.RFC3339Nano),
		"hash_source":             "normalized_manifest",
	}
	current, err := s.db.GetK8sInventoryItem(ctx, req.ClusterID, req.Kind, req.Namespace, req.Name)
	if manifestChangeOperation(req) == "create" {
		if errors.Is(err, store.ErrNotFound) {
			guard["reason"] = "create_target_absent"
			guard["create_target_absent"] = true
			return guard
		}
		if err != nil {
			guard["status"] = "unknown"
			guard["reason"] = err.Error()
			return guard
		}
		currentYAML := mustManifestYAML(sanitizeManifestDocForLedger(assembleManifest(current)))
		guard["status"] = "blocked"
		guard["hard_block"] = true
		guard["reason"] = "create_target_already_exists"
		guard["current_uid"] = current.UID
		guard["current_resource_version"] = k8sActionTargetResourceVersion(current)
		guard["current_hash"] = manifestHash(currentYAML)
		guard["current_observed_at"] = current.ObservedAt
		guard["current_updated_at"] = current.UpdatedAt
		return guard
	}
	if errors.Is(err, store.ErrNotFound) {
		guard["status"] = "blocked"
		guard["hard_block"] = true
		guard["reason"] = "live_resource_missing"
		return guard
	}
	if err != nil {
		guard["status"] = "unknown"
		guard["reason"] = err.Error()
		return guard
	}
	currentVersion := k8sActionTargetResourceVersion(current)
	currentYAML := mustManifestYAML(sanitizeManifestDocForLedger(assembleManifest(current)))
	currentHash := manifestHash(currentYAML)
	guard["current_uid"] = current.UID
	guard["current_resource_version"] = currentVersion
	guard["current_hash"] = currentHash
	guard["current_observed_at"] = current.ObservedAt
	guard["current_updated_at"] = current.UpdatedAt
	if req.TargetUID != "" && current.UID != "" && req.TargetUID != current.UID {
		guard["status"] = "blocked"
		guard["hard_block"] = true
		guard["reason"] = "live_resource_uid_changed"
		return guard
	}
	if req.BeforeHash != "" && currentHash != "" && req.BeforeHash != currentHash {
		guard["status"] = "drift"
		guard["hard_block"] = false
		guard["reason"] = "live_manifest_changed_since_request"
		guard["current_diffs"] = diffYAMLText(req.BeforeYAML, currentYAML)
		return guard
	}
	guard["reason"] = "live_manifest_matches_request_baseline"
	return guard
}

func manifestChangeDriftBlocks(guard map[string]any, force bool) bool {
	status := strings.ToLower(strings.TrimSpace(asStr(guard["status"])))
	if hard, ok := guard["hard_block"].(bool); ok && hard {
		return true
	}
	switch status {
	case "blocked":
		return true
	case "drift":
		return !force
	default:
		return false
	}
}

func manifestChangeBrief(req store.K8sManifestChangeRequest, driftGuard map[string]any) map[string]any {
	riskCounts := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	topChanges := []store.K8sManifestFieldDiff{}
	for _, d := range req.Diffs {
		r := strings.ToLower(strings.TrimSpace(d.Risk))
		if _, ok := riskCounts[r]; !ok {
			r = "low"
		}
		riskCounts[r]++
		topChanges = append(topChanges, d)
	}
	sort.SliceStable(topChanges, func(i, j int) bool {
		if riskRank(topChanges[i].Risk) == riskRank(topChanges[j].Risk) {
			return topChanges[i].Path < topChanges[j].Path
		}
		return riskRank(topChanges[i].Risk) > riskRank(topChanges[j].Risk)
	})
	if len(topChanges) > 8 {
		topChanges = topChanges[:8]
	}
	dryRunStatus := "not_run"
	if v, ok := req.Validation["dry_run"].(map[string]any); ok {
		dryRunStatus = firstNonEmpty(asStr(v["status"]), dryRunStatus)
	}
	policyStatus := "not_run"
	if v, ok := req.Validation["policy"].(map[string]any); ok {
		if denied, _ := v["denied"].(bool); denied {
			policyStatus = "denied"
		} else {
			policyStatus = "checked"
		}
	}
	nextAction := manifestChangeNextAction(req, driftGuard)
	checklist := []string{
		"변경 사유와 장애/변경번호가 충분한지 확인",
		"High/Critical diff와 Service/RBAC/Secret/NetworkPolicy 영향 확인",
		"server dry-run 결과와 admission warning 확인",
		"적용 직전 drift guard 상태 확인",
		"롤백 후보(before YAML 또는 이전 revision) 확보",
	}
	if strings.EqualFold(asStr(driftGuard["status"]), "drift") {
		checklist = append(checklist, "요청 생성 이후 live manifest가 바뀌었습니다. 새 YAML로 재생성하거나 force_drift 사유를 남기세요.")
	}
	return map[string]any{
		"summary": map[string]any{
			"operation":         manifestChangeOperation(req),
			"target":            req.Namespace + "/" + req.Kind + "/" + req.Name,
			"status":            req.Status,
			"risk_level":        req.RiskLevel,
			"requires_approval": req.RequiresApproval,
			"reason":            req.Reason,
			"created_by":        req.CreatedBy,
			"approved_by":       req.ApprovedBy,
		},
		"decision": map[string]any{
			"next_action":   nextAction,
			"dry_run":       dryRunStatus,
			"policy":        policyStatus,
			"drift_status":  asStr(driftGuard["status"]),
			"force_allowed": strings.EqualFold(asStr(driftGuard["status"]), "drift"),
		},
		"risk_counts":        riskCounts,
		"top_changes":        topChanges,
		"approval_reasons":   manifestApprovalReasons(req.Impact),
		"operator_checklist": checklist,
		"evidence": map[string]any{
			"before_hash": req.BeforeHash,
			"after_hash":  req.AfterHash,
			"diff_count":  len(req.Diffs),
			"has_apply":   len(req.ApplyResult) > 0,
			"has_verify":  len(req.VerifyResult) > 0,
		},
	}
}

func manifestChangeNextAction(req store.K8sManifestChangeRequest, driftGuard map[string]any) string {
	if hard, ok := driftGuard["hard_block"].(bool); ok && hard {
		return "refresh_or_recreate"
	}
	if manifestChangeDriftBlocks(driftGuard, false) && (req.Status == "approved" || req.Status == "validated") {
		return "refresh_or_force_drift"
	}
	switch req.Status {
	case "draft":
		return "validate"
	case "validated":
		if req.RequiresApproval {
			return "approve"
		}
		return "apply"
	case "approval_required":
		return "approve_or_reject"
	case "approved":
		return "apply"
	case "applied", "verify_failed":
		return "verify"
	case "verified":
		return "done"
	case "failed":
		return "fix_and_recreate"
	case "rejected":
		return "closed"
	default:
		return "inspect"
	}
}

func manifestApprovalReasons(impact map[string]any) []string {
	if impact == nil {
		return nil
	}
	raw, ok := impact["approval_reasons"]
	if !ok {
		return nil
	}
	out := []string{}
	switch v := raw.(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, it := range v {
			if s := strings.TrimSpace(asStr(it)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func manifestChangeOperation(req store.K8sManifestChangeRequest) string {
	op := strings.ToLower(strings.TrimSpace(asStr(req.Impact["operation"])))
	switch op {
	case "create":
		return "create"
	default:
		return "update"
	}
}

func diffManifestDocs(before, after map[string]any) []store.K8sManifestFieldDiff {
	out := []store.K8sManifestFieldDiff{}
	collectManifestDiffs("", before, after, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func diffYAMLText(beforeYAML, afterYAML string) []store.K8sManifestFieldDiff {
	before, bErr := parseSingleManifestDoc(beforeYAML)
	after, aErr := parseSingleManifestDoc(afterYAML)
	if bErr != nil || aErr != nil {
		return []store.K8sManifestFieldDiff{{Path: "$", Type: "changed", Risk: "medium", OldValue: "previous manifest", NewValue: "rollback manifest"}}
	}
	return diffManifestDocs(before, after)
}

func collectManifestDiffs(path string, before, after any, out *[]store.K8sManifestFieldDiff) {
	bm, bok := before.(map[string]any)
	am, aok := after.(map[string]any)
	if bok && aok {
		keys := map[string]bool{}
		for k := range bm {
			keys[k] = true
		}
		for k := range am {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			child := k
			if path != "" {
				child = path + "." + k
			}
			_, hasB := bm[k]
			_, hasA := am[k]
			switch {
			case !hasB:
				*out = append(*out, store.K8sManifestFieldDiff{Path: child, Type: "added", NewValue: manifestDiffValue(am[k]), Risk: manifestDiffRisk(child)})
			case !hasA:
				*out = append(*out, store.K8sManifestFieldDiff{Path: child, Type: "removed", OldValue: manifestDiffValue(bm[k]), Risk: manifestDiffRisk(child)})
			default:
				collectManifestDiffs(child, bm[k], am[k], out)
			}
		}
		return
	}
	if !manifestValuesEqual(before, after) {
		*out = append(*out, store.K8sManifestFieldDiff{Path: firstNonEmpty(path, "$"), Type: "changed", OldValue: manifestDiffValue(before), NewValue: manifestDiffValue(after), Risk: manifestDiffRisk(path)})
	}
}

func manifestValuesEqual(a, b any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

func manifestDiffValue(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		if s == maskedValue {
			return maskedValue
		}
		if len(s) > 160 {
			return s[:160] + "..."
		}
		return s
	}
	b, _ := json.Marshal(v)
	if len(b) > 220 {
		return string(b[:220]) + "..."
	}
	return string(b)
}

func manifestDiffRisk(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "clusterrole"), strings.Contains(p, "privileged"), strings.Contains(p, "hostpath"),
		strings.Contains(p, "hostnetwork"), strings.Contains(p, "secret"), strings.Contains(p, "networkpolicy"):
		return "critical"
	case strings.Contains(p, "selector"), strings.Contains(p, "ingress"), strings.Contains(p, "tls"),
		strings.Contains(p, "replicas"), strings.Contains(p, "service.type"), strings.Contains(p, "pdb"):
		return "high"
	case strings.Contains(p, "env"), strings.Contains(p, "resources"), strings.Contains(p, "probe"), strings.Contains(p, "image"):
		return "medium"
	default:
		return "low"
	}
}

func manifestChangeImpact(item store.K8sInventoryItem, after map[string]any, diffs []store.K8sManifestFieldDiff, plan analyzer.StackPlan) (map[string]any, string, bool) {
	reasons := []string{}
	risk := "low"
	requiresApproval := plan.RequiresApproval
	for _, d := range diffs {
		risk = manifestRiskMax(risk, d.Risk)
		if d.Risk == "high" || d.Risk == "critical" {
			reasons = append(reasons, d.Path+"="+d.Risk)
			requiresApproval = true
		} else if d.Risk == "medium" {
			reasons = append(reasons, d.Path+"=medium")
			requiresApproval = true
		}
	}
	switch strings.ToLower(item.Kind) {
	case "secret", "clusterrole", "clusterrolebinding", "role", "rolebinding", "networkpolicy":
		risk = manifestRiskMax(risk, "critical")
		requiresApproval = true
	case "ingress", "service", "persistentvolumeclaim", "poddisruptionbudget":
		risk = manifestRiskMax(risk, "high")
		requiresApproval = true
	case "deployment", "statefulset", "daemonset", "job", "cronjob", "horizontalpodautoscaler":
		if riskRank(risk) < riskRank("medium") {
			risk = manifestRiskMax(risk, "medium")
		}
		requiresApproval = true
	}
	if len(plan.PolicyViolations) > 0 {
		reasons = append(reasons, "policy_violations")
	}
	if plan.Denied {
		risk = "blocked"
		requiresApproval = true
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "low-risk metadata/spec change")
	}
	targets := resolveStackTargets([]map[string]any{after}, item.Namespace)
	return map[string]any{
		"operation":      "update",
		"target":         map[string]any{"cluster_id": item.ClusterID, "kind": item.Kind, "namespace": item.Namespace, "name": item.Name, "uid": item.UID},
		"changed_fields": len(diffs), "approval_reasons": reasons, "stack_resources": targets,
		"policy_denied": plan.Denied, "policy_violations": plan.PolicyViolations,
	}, risk, requiresApproval
}

func manifestCreateImpact(item store.K8sInventoryItem, after map[string]any, diffs []store.K8sManifestFieldDiff, plan analyzer.StackPlan) (map[string]any, string, bool) {
	impact, risk, requiresApproval := manifestChangeImpact(item, after, diffs, plan)
	impact["operation"] = "create"
	impact["create_target"] = map[string]any{"cluster_id": item.ClusterID, "kind": item.Kind, "namespace": item.Namespace, "name": item.Name}
	reasons := manifestApprovalReasons(impact)
	filtered := make([]string, 0, len(reasons)+1)
	filtered = append(filtered, "create_resource")
	for _, r := range reasons {
		if r != "" && r != "low-risk metadata/spec change" && r != "create_resource" {
			filtered = append(filtered, r)
		}
	}
	impact["approval_reasons"] = filtered
	if riskRank(risk) < riskRank("medium") {
		risk = "medium"
	}
	// New Kubernetes objects are mutating changes even when the manifest itself is low-risk.
	// Keep them in the approval lane so ownership, namespace, and rollback intent are reviewed.
	requiresApproval = true
	return impact, risk, requiresApproval
}

func manifestRiskMax(a, b string) string {
	if riskRank(b) > riskRank(a) {
		return b
	}
	return a
}

func riskRank(r string) int {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "blocked":
		return 5
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func manifestChangeEvidenceMarkdown(req store.K8sManifestChangeRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Manifest Change Evidence\n\n")
	fmt.Fprintf(&b, "- Request: `%s`\n- Operation: `%s`\n- Target: `%s/%s/%s`\n- Status: `%s`\n- Risk: `%s`\n- Created by: `%s`\n- Reason: %s\n\n",
		req.ID, manifestChangeOperation(req), req.Namespace, req.Kind, req.Name, req.Status, req.RiskLevel, req.CreatedBy, req.Reason)
	fmt.Fprintf(&b, "## Hashes\n\n- Before: `%s`\n- After: `%s`\n\n", req.BeforeHash, req.AfterHash)
	fmt.Fprintf(&b, "## Field Diff\n\n")
	if len(req.Diffs) == 0 {
		b.WriteString("- No semantic diff recorded.\n\n")
	} else {
		for _, d := range req.Diffs {
			fmt.Fprintf(&b, "- `%s` %s (%s): `%s` -> `%s`\n", d.Path, d.Type, d.Risk, d.OldValue, d.NewValue)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Validation\n\n```json\n%s\n```\n\n", prettyJSON(req.Validation))
	fmt.Fprintf(&b, "## Apply Result\n\n```json\n%s\n```\n\n", prettyJSON(req.ApplyResult))
	fmt.Fprintf(&b, "## Verification\n\n```json\n%s\n```\n", prettyJSON(req.VerifyResult))
	return b.String()
}

func manifestChangePseudoPatch(req store.K8sManifestChangeRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# operation: %s\n", manifestChangeOperation(req))
	fmt.Fprintf(&b, "--- before/%s-%s-%s.yaml\n+++ after/%s-%s-%s.yaml\n", req.Namespace, req.Kind, req.Name, req.Namespace, req.Kind, req.Name)
	beforeLines := strings.Split(req.BeforeYAML, "\n")
	afterLines := strings.Split(req.AfterYAML, "\n")
	b.WriteString("@@ manifest @@\n")
	for _, line := range beforeLines {
		if strings.TrimSpace(line) != "" {
			fmt.Fprintf(&b, "-%s\n", line)
		}
	}
	for _, line := range afterLines {
		if strings.TrimSpace(line) != "" {
			fmt.Fprintf(&b, "+%s\n", line)
		}
	}
	return b.String()
}

func prettyJSON(v any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}
