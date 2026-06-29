package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// handleK8sStacks lists or creates/updates Application Stacks (persisted, versioned manifests).
// GET/POST /admin/k8s/stacks
func (s *Server) handleK8sStacks(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListK8sStacks(r.Context(), strings.TrimSpace(r.URL.Query().Get("cluster_id")))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stacks_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"stacks": rows})
	case http.MethodPost:
		var in struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			ClusterID  string `json:"cluster_id"`
			Namespace  string `json:"namespace"`
			Manifest   string `json:"manifest"`
			SyncPolicy string `json:"sync_policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.Manifest) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name and manifest are required", "invalid_request_error", "missing_fields")
			return
		}
		// Validate before persisting so a saved stack is always parseable.
		docs, perr := decodeManifestDocs(in.Manifest)
		if perr != nil {
			writeOpenAIError(w, http.StatusBadRequest, "manifest parse error: "+perr.Error(), "invalid_request_error", "manifest_parse_failed")
			return
		}
		policies, _ := s.db.ListK8sPolicies(r.Context())
		plan := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
		sum := sha256.Sum256([]byte(in.Manifest))
		st := store.K8sApplicationStack{
			ID: strings.TrimSpace(in.ID), Name: strings.TrimSpace(in.Name), ClusterID: strings.TrimSpace(in.ClusterID),
			Namespace: strings.TrimSpace(in.Namespace), SourceType: "manifest", Manifest: in.Manifest,
			ManifestHash: hex.EncodeToString(sum[:]), SyncPolicy: coalesceStr(strings.TrimSpace(in.SyncPolicy), "manual"),
			CreatedBy: adminID(r),
		}
		saved, isNew, err := s.db.UpsertK8sStack(r.Context(), st, newID)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.stack.upsert", "", auditJSON(map[string]any{"id": saved.ID, "rev": saved.RevisionNo, "new": isNew}))
		status := http.StatusOK
		if isNew {
			status = http.StatusCreated
		}
		writeJSON(w, status, map[string]any{"stack": saved, "plan": plan})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sStackByID returns a stack with its revisions, or deletes it.
// GET/DELETE /admin/k8s/stacks/{id}
func (s *Server) handleK8sStackByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/stacks/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" || id == "validate" {
		writeOpenAIError(w, http.StatusBadRequest, "stack id required", "invalid_request_error", "missing_stack_id")
		return
	}
	if len(parts) > 1 && parts[1] == "drift" {
		if r.Method != http.MethodGet {
			writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		s.handleK8sStackDrift(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		st, err := s.db.GetK8sStack(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "stack not found", "invalid_request_error", "stack_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_failed")
			return
		}
		revs, _ := s.db.ListK8sStackRevisions(r.Context(), id, 50)
		writeJSON(w, http.StatusOK, map[string]any{"stack": st, "revisions": revs})
	case http.MethodDelete:
		if err := s.db.DeleteK8sStack(r.Context(), id); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_stack_delete_failed")
			return
		}
		s.auditAdmin(r, "k8s.stack.delete", "", auditJSON(map[string]string{"id": id}))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sStackDrift compares a saved stack's declared resources against the live inventory.
// GET /admin/k8s/stacks/{id}/drift
func (s *Server) handleK8sStackDrift(w http.ResponseWriter, r *http.Request, id string) {
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
	plan := analyzer.AnalyzeStackManifest(docs, nil) // resources only; policies not needed for drift
	inventory, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: st.ClusterID, Limit: 5000})
	report := analyzer.DetectStackDrift(plan.Resources, st.Namespace, inventory)
	writeJSON(w, http.StatusOK, map[string]any{
		"stack_id": id, "cluster_id": st.ClusterID, "drift": report,
		"note": "선언된 리소스가 클러스터 인벤토리에 존재하는지(존재/누락) 비교합니다. 필드 단위 diff는 변경 타임라인/Diff를 참고하세요.",
	})
}

func coalesceStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// handleK8sStackValidate dry-runs a multi-document Kubernetes manifest: it enumerates the resources,
// runs the policy pack, and flags approval-gating changes — without applying anything to a cluster.
// The Application Stack (Portainer-style) deploy foundation. POST /admin/k8s/stacks/validate {manifest}
func (s *Server) handleK8sStackValidate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var p struct {
		Manifest string `json:"manifest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if strings.TrimSpace(p.Manifest) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "manifest is required", "invalid_request_error", "missing_manifest")
		return
	}
	docs, perr := decodeManifestDocs(p.Manifest)
	if perr != nil {
		writeOpenAIError(w, http.StatusBadRequest, "manifest parse error: "+perr.Error(), "invalid_request_error", "manifest_parse_failed")
		return
	}
	policies, err := s.db.ListK8sPolicies(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_policies_failed")
		return
	}
	plan := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
	decision := "allow"
	if plan.Denied {
		decision = "deny"
	} else if plan.RequiresApproval {
		decision = "approval_required"
	}
	s.auditAdmin(r, "k8s.stack.validate", "", auditJSON(map[string]any{"resources": len(plan.Resources), "decision": decision}))
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision, "plan": plan,
		"note": "dry-run 검증입니다 — 클러스터에 적용하지 않고 리소스·정책 위반·승인 필요 변경만 분석합니다.",
	})
}

// decodeManifestDocs splits a multi-document YAML/JSON manifest into decoded maps.
func decodeManifestDocs(manifest string) ([]map[string]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader([]byte(manifest)))
	docs := []map[string]any{}
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(doc) > 0 {
			docs = append(docs, doc)
		}
	}
	return docs, nil
}
