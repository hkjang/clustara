package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Build Job Center — definitions + gated run requests (CLU-NEXT-03/05).
//
// Manages build definitions and creates build-run requests whose lifecycle is security-gated by the
// Dockerfile analysis (high finding → approval, critical/fail → blocked). Actual build execution is
// a separate infra-dependent phase; runs stay requested/approved/blocked here.

// handleK8sBuildDefinitions lists/creates build definitions.
// GET  /admin/k8s/build-definitions?cluster_id=
// POST /admin/k8s/build-definitions {id?, cluster_id, name, git_url, branch, context_path, dockerfile, output_image, provider}
func (s *Server) handleK8sBuildDefinitions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		defs, err := s.db.ListK8sBuildDefinitions(r.Context(), strings.TrimSpace(r.URL.Query().Get("cluster_id")))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "build_def_list_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"definitions": defs,
			"providers": []string{"kaniko", "buildkit", "tekton", "job"},
			"note":      "빌드 정의입니다. 빌드 실행(러너)은 라이브 인프라 의존으로 후속 단계이며, 여기서는 정의 관리와 보안 게이트된 실행 요청까지 제공합니다."})
	case http.MethodPost:
		var in struct {
			ID          string `json:"id"`
			ClusterID   string `json:"cluster_id"`
			Name        string `json:"name"`
			GitURL      string `json:"git_url"`
			Branch      string `json:"branch"`
			ContextPath string `json:"context_path"`
			Dockerfile  string `json:"dockerfile"`
			OutputImage string `json:"output_image"`
			Provider    string `json:"provider"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.GitURL) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name and git_url are required", "invalid_request_error", "missing_fields")
			return
		}
		d := store.K8sBuildDefinition{
			ID: firstNonEmpty(in.ID, newID("k8sbdef")), ClusterID: in.ClusterID, Name: in.Name, GitURL: in.GitURL,
			Branch: firstNonEmpty(in.Branch, "main"), ContextPath: in.ContextPath, Dockerfile: in.Dockerfile,
			OutputImage: in.OutputImage, Provider: firstNonEmpty(in.Provider, "kaniko"), CreatedBy: adminID(r),
		}
		if err := s.db.UpsertK8sBuildDefinition(r.Context(), d); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "build_def_failed")
			return
		}
		s.auditAdmin(r, "k8s.build.definition", d.ID, auditJSON(map[string]any{"name": d.Name, "provider": d.Provider}))
		writeJSON(w, http.StatusCreated, map[string]any{"definition": d})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sBuildRuns lists build runs, or (POST) requests a new run — security-gated by the
// definition's Dockerfile.
// GET  /admin/k8s/build-runs?definition_id=
// POST /admin/k8s/build-runs {definition_id}
func (s *Server) handleK8sBuildRuns(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		runs, err := s.db.ListK8sBuildRuns(r.Context(), strings.TrimSpace(r.URL.Query().Get("definition_id")), 200)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "build_run_list_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
	case http.MethodPost:
		var in struct {
			DefinitionID string `json:"definition_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		def, err := s.db.GetK8sBuildDefinition(r.Context(), strings.TrimSpace(in.DefinitionID))
		if errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "build definition not found", "invalid_request_error", "def_not_found")
			return
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "build_run_failed")
			return
		}
		// Security gate: run the Dockerfile analysis. A gate failure (high-severity finding) blocks
		// the run; otherwise it's requested (pending a runner).
		run := store.K8sBuildRun{
			ID: newID("k8sbrun"), DefinitionID: def.ID, ClusterID: def.ClusterID, Trigger: "manual",
			Status: "requested", GatePass: true, RequestedBy: adminID(r),
		}
		if strings.TrimSpace(def.Dockerfile) != "" {
			gate := analyzer.AnalyzeDockerfile(def.Dockerfile)
			gj, _ := json.Marshal(gate)
			run.GateResult = string(gj)
			run.GatePass = gate.Pass
			if !gate.Pass {
				run.Status = "blocked"
				run.FailureReason = "Dockerfile 보안 게이트 실패(high-severity)"
			}
		}
		if err := s.db.CreateK8sBuildRun(r.Context(), run); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "build_run_create_failed")
			return
		}
		s.auditAdmin(r, "k8s.build.run", run.ID, auditJSON(map[string]any{"definition": def.ID, "status": run.Status, "gate_pass": run.GatePass}))
		writeJSON(w, http.StatusCreated, map[string]any{"run": run,
			"note": "빌드 실행 요청이 등록되었습니다. Dockerfile 보안 게이트 실패 시 blocked로 차단됩니다. 실제 빌드 실행(러너)은 라이브 인프라 연결 후 진행됩니다."})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}
