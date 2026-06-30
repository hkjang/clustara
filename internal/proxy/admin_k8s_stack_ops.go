package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
	"clustara/internal/store"
)

// resourceTarget is one manifest document resolved to its apply coordinates.
type resourceTarget struct {
	APIVersion string         `json:"api_version"`
	Kind       string         `json:"kind"`
	Namespace  string         `json:"namespace"`
	Name       string         `json:"name"`
	doc        map[string]any `json:"-"`
}

// resolveStackTargets turns decoded manifest docs into apply targets, defaulting the namespace to
// the stack's namespace when a document omits one.
func resolveStackTargets(docs []map[string]any, defaultNamespace string) []resourceTarget {
	out := []resourceTarget{}
	for _, doc := range docs {
		kind := strings.TrimSpace(asStr(doc["kind"]))
		meta, _ := doc["metadata"].(map[string]any)
		name := strings.TrimSpace(asStr(meta["name"]))
		if kind == "" || name == "" {
			continue
		}
		ns := strings.TrimSpace(asStr(meta["namespace"]))
		if ns == "" {
			ns = defaultNamespace
		}
		out = append(out, resourceTarget{
			APIVersion: strings.TrimSpace(asStr(doc["apiVersion"])),
			Kind:       kind, Namespace: ns, Name: name, doc: doc,
		})
	}
	return out
}

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// handleK8sStackApply applies a saved stack to its cluster via Server-Side Apply, gated on the
// policy plan: a Deny policy blocks the apply; approval-gating changes require confirm=true.
// POST /admin/k8s/stacks/{id}/apply {dry_run, confirm}
func (s *Server) handleK8sStackApply(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		DryRun  bool `json:"dry_run"`
		Confirm bool `json:"confirm"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)

	st, err := s.db.GetK8sStack(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "stack not found", "invalid_request_error", "stack_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_failed")
		return
	}
	docs, perr := decodeManifestDocs(st.Manifest)
	if perr != nil {
		writeOpenAIError(w, http.StatusBadRequest, "stored manifest parse error: "+perr.Error(), "invalid_request_error", "manifest_parse_failed")
		return
	}
	policies, _ := s.db.ListK8sPolicies(r.Context())
	plan := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
	if plan.Denied {
		s.recordStackHistory(r, st, "apply", in.DryRun, "denied", 0, 0, plan.PolicyViolations)
		writeJSON(w, http.StatusConflict, map[string]any{"decision": "deny", "plan": plan,
			"note": "정책 Deny에 걸려 적용을 차단했습니다. 매니페스트를 수정하세요."})
		return
	}
	if plan.RequiresApproval && !in.Confirm {
		s.recordStackHistory(r, st, "apply", in.DryRun, "approval_required", 0, 0, nil)
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"decision": "approval_required", "plan": plan,
			"note": "승인 필요 변경이 포함되어 있습니다. confirm=true로 다시 요청하세요."})
		return
	}

	cluster, err := s.db.GetK8sCluster(r.Context(), st.ClusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "stack에 연결된 클러스터를 찾을 수 없습니다: "+err.Error(), "invalid_request_error", "k8s_cluster_failed")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	applier, ok := client.(kube.StackApplier)
	if !ok {
		writeOpenAIError(w, http.StatusNotImplemented, "이 클러스터 클라이언트는 apply를 지원하지 않습니다.", "invalid_request_error", "applier_unsupported")
		return
	}

	targets := resolveStackTargets(docs, st.Namespace)
	results := make([]map[string]any, 0, len(targets))
	applied, failed := 0, 0
	for _, t := range targets {
		yml, mErr := yaml.Marshal(t.doc)
		res := map[string]any{"kind": t.Kind, "namespace": t.Namespace, "name": t.Name}
		if mErr != nil {
			res["ok"], res["error"] = false, "manifest 직렬화 실패: "+mErr.Error()
			failed++
			results = append(results, res)
			continue
		}
		if aErr := applier.Apply(r.Context(), t.APIVersion, t.Kind, t.Namespace, t.Name, yml, in.DryRun); aErr != nil {
			res["ok"], res["error"] = false, aErr.Error()
			failed++
		} else {
			res["ok"] = true
			applied++
		}
		results = append(results, res)
	}

	status := "success"
	if failed > 0 && applied > 0 {
		status = "partial"
	} else if failed > 0 {
		status = "failed"
	}
	s.recordStackHistory(r, st, "apply", in.DryRun, status, applied, failed, results)
	if !in.DryRun && status == "success" {
		_ = s.db.SetK8sStackStatus(r.Context(), st.ID, "applied")
	}
	if !in.DryRun && applied > 0 {
		// Change-aware burst: collect the stack's cluster at high frequency to verify the apply.
		s.registerCollectBurst(r.Context(), st.ClusterID, st.Namespace, "stack_apply", "stack_apply:"+st.Name)
	}
	s.auditAdmin(r, "k8s.stack.apply", st.ID, auditJSON(map[string]any{"dry_run": in.DryRun, "status": status, "applied": applied, "failed": failed}))
	code := http.StatusOK
	if status == "failed" {
		code = http.StatusBadGateway
	}
	writeJSON(w, code, map[string]any{
		"stack_id": st.ID, "dry_run": in.DryRun, "status": status,
		"applied": applied, "failed": failed, "results": results,
	})
}

// handleK8sStackRollback restores a stack's manifest to a prior revision (roll-forward to old
// content, creating a new revision) after re-running the policy/impact check. The cluster is not
// mutated here — call /apply afterwards to deploy the restored manifest.
// POST /admin/k8s/stacks/{id}/rollback {revision_no}
func (s *Server) handleK8sStackRollback(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		RevisionNo int `json:"revision_no"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	st, err := s.db.GetK8sStack(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "stack not found", "invalid_request_error", "stack_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_failed")
		return
	}
	rev, err := s.db.GetK8sStackRevision(r.Context(), id, in.RevisionNo)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "revision not found", "invalid_request_error", "revision_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_rev_failed")
		return
	}
	docs, perr := decodeManifestDocs(rev.Manifest)
	if perr != nil {
		writeOpenAIError(w, http.StatusBadRequest, "revision manifest parse error: "+perr.Error(), "invalid_request_error", "manifest_parse_failed")
		return
	}
	// Re-check Config Impact / image risk against the restored manifest before accepting it.
	policies, _ := s.db.ListK8sPolicies(r.Context())
	plan := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
	if plan.Denied {
		writeJSON(w, http.StatusConflict, map[string]any{"decision": "deny", "plan": plan,
			"note": "롤백하려는 revision이 현재 정책 Deny에 걸립니다."})
		return
	}
	sum := sha256.Sum256([]byte(rev.Manifest))
	st.Manifest = rev.Manifest
	st.ManifestHash = hex.EncodeToString(sum[:])
	st.CreatedBy = adminID(r)
	saved, _, err := s.db.UpsertK8sStack(r.Context(), st, newID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_rollback_failed")
		return
	}
	s.recordStackHistory(r, saved, "rollback", false, "success", 0, 0, map[string]any{"restored_from_revision": in.RevisionNo, "new_revision": saved.RevisionNo})
	s.auditAdmin(r, "k8s.stack.rollback", saved.ID, auditJSON(map[string]any{"from_rev": in.RevisionNo, "new_rev": saved.RevisionNo}))
	writeJSON(w, http.StatusOK, map[string]any{
		"stack": saved, "plan": plan, "restored_from_revision": in.RevisionNo,
		"note": "이전 revision 매니페스트로 복원했습니다(새 revision 생성). 클러스터 반영은 /apply로 진행하세요.",
	})
}

// handleK8sStackPromote promotes a stack's current manifest to a target environment stack (e.g.
// dev→staging→prod), creating a new revision on the target and returning the resource-level diff.
// POST /admin/k8s/stacks/{id}/promote {target_stack_id | target_name, target_cluster_id, target_namespace}
func (s *Server) handleK8sStackPromote(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		TargetStackID   string `json:"target_stack_id"`
		TargetName      string `json:"target_name"`
		TargetClusterID string `json:"target_cluster_id"`
		TargetNamespace string `json:"target_namespace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	src, err := s.db.GetK8sStack(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "source stack not found", "invalid_request_error", "stack_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_failed")
		return
	}
	srcDocs, _ := decodeManifestDocs(src.Manifest)
	srcPlan := analyzer.AnalyzeStackManifest(srcDocs, nil)

	// Resolve the target stack (existing or new).
	var target store.K8sApplicationStack
	var prevTargetResources []analyzer.StackResource
	if strings.TrimSpace(in.TargetStackID) != "" {
		target, err = s.db.GetK8sStack(r.Context(), in.TargetStackID)
		if errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "target stack not found", "invalid_request_error", "target_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_failed")
			return
		}
		if tDocs, e := decodeManifestDocs(target.Manifest); e == nil {
			prevTargetResources = analyzer.AnalyzeStackManifest(tDocs, nil).Resources
		}
	} else {
		if strings.TrimSpace(in.TargetName) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "target_stack_id 또는 target_name이 필요합니다", "invalid_request_error", "missing_target")
			return
		}
		target = store.K8sApplicationStack{Name: strings.TrimSpace(in.TargetName)}
	}

	diff := diffStackResources(srcPlan.Resources, prevTargetResources)

	// Promote: copy the source manifest onto the target (new revision on target).
	sum := sha256.Sum256([]byte(src.Manifest))
	target.SourceType = "manifest"
	target.Manifest = src.Manifest
	target.ManifestHash = hex.EncodeToString(sum[:])
	if strings.TrimSpace(in.TargetClusterID) != "" {
		target.ClusterID = strings.TrimSpace(in.TargetClusterID)
	}
	if strings.TrimSpace(in.TargetNamespace) != "" {
		target.Namespace = strings.TrimSpace(in.TargetNamespace)
	}
	if target.SyncPolicy == "" {
		target.SyncPolicy = "manual"
	}
	target.CreatedBy = adminID(r)
	saved, isNew, err := s.db.UpsertK8sStack(r.Context(), target, newID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_promote_failed")
		return
	}
	s.recordStackHistoryTarget(r, src, "promote", saved.ID, "success", diff)
	s.auditAdmin(r, "k8s.stack.promote", src.ID, auditJSON(map[string]any{"target": saved.ID, "new": isNew, "rev": saved.RevisionNo}))
	writeJSON(w, http.StatusOK, map[string]any{
		"source_stack_id": src.ID, "target_stack": saved, "diff": diff, "target_is_new": isNew,
		"note": "소스 매니페스트를 대상 환경 스택으로 승격했습니다(새 revision). 대상 클러스터 반영은 대상 스택에서 /apply로 진행하세요.",
	})
}

// handleK8sStackHistory returns a stack's apply/promote/rollback history.
// GET /admin/k8s/stacks/{id}/history
func (s *Server) handleK8sStackHistory(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	rows, err := s.db.ListK8sStackApplyHistory(r.Context(), id, 100)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_history_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": rows})
}

func (s *Server) recordStackHistory(r *http.Request, st store.K8sApplicationStack, op string, dryRun bool, status string, applied, failed int, detail any) {
	detailJSON, _ := json.Marshal(detail)
	_ = s.db.InsertK8sStackApplyHistory(r.Context(), store.K8sStackApplyHistory{
		ID: newID("k8sstackhist"), StackID: st.ID, Operation: op, RevisionNo: st.RevisionNo,
		ClusterID: st.ClusterID, DryRun: dryRun, Status: status, Applied: applied, Failed: failed,
		Detail: string(detailJSON), Actor: adminID(r),
	})
}

func (s *Server) recordStackHistoryTarget(r *http.Request, st store.K8sApplicationStack, op, targetStackID, status string, detail any) {
	detailJSON, _ := json.Marshal(detail)
	_ = s.db.InsertK8sStackApplyHistory(r.Context(), store.K8sStackApplyHistory{
		ID: newID("k8sstackhist"), StackID: st.ID, Operation: op, RevisionNo: st.RevisionNo,
		ClusterID: st.ClusterID, TargetStackID: targetStackID, Status: status,
		Detail: string(detailJSON), Actor: adminID(r),
	})
}

// StackResourceDiff is the environment-promotion diff between two stacks' declared resources.
type StackResourceDiff struct {
	Added   []string `json:"added"`   // present in source, absent in target
	Removed []string `json:"removed"` // present in target, absent in source
	Common  []string `json:"common"`  // present in both
}

// diffStackResources computes the resource-identity diff for promotion (source vs target's previous
// declared resources). Identity is kind/namespace/name. Pure.
func diffStackResources(src, target []analyzer.StackResource) StackResourceDiff {
	srcSet := map[string]bool{}
	for _, r := range src {
		srcSet[stackResIdentity(r)] = true
	}
	targetSet := map[string]bool{}
	for _, r := range target {
		targetSet[stackResIdentity(r)] = true
	}
	diff := StackResourceDiff{Added: []string{}, Removed: []string{}, Common: []string{}}
	for k := range srcSet {
		if targetSet[k] {
			diff.Common = append(diff.Common, k)
		} else {
			diff.Added = append(diff.Added, k)
		}
	}
	for k := range targetSet {
		if !srcSet[k] {
			diff.Removed = append(diff.Removed, k)
		}
	}
	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)
	sort.Strings(diff.Common)
	return diff
}

func stackResIdentity(r analyzer.StackResource) string {
	return r.Kind + "/" + r.Namespace + "/" + r.Name
}
