package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"clustara/internal/analyzer"
)

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
