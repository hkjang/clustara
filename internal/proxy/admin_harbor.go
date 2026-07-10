package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clustara/internal/harbor"
	"clustara/internal/store"
)

func (s *Server) handleHarborRegistries(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListHarborRegistries(r.Context(), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_registry_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"registries": rows, "count": len(rows), "generated_at": time.Now().UTC().Format(time.RFC3339Nano)})
	case http.MethodPost:
		var in struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			URL         string `json:"url"`
			InsecureTLS bool   `json:"insecure_tls"`
			CARef       string `json:"ca_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		url := harbor.NormalizeRegistryURL(in.URL)
		if strings.TrimSpace(in.Name) == "" || url == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name and url are required", "invalid_request_error", "missing_fields")
			return
		}
		row := store.HarborRegistry{
			ID: firstNonEmpty(strings.TrimSpace(in.ID), newID("hreg")), Name: strings.TrimSpace(in.Name), URL: url,
			InsecureTLS: in.InsecureTLS, CARef: strings.TrimSpace(in.CARef), Status: "registered", CreatedBy: adminID(r),
		}
		if err := s.db.UpsertHarborRegistry(r.Context(), row); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_registry_save_failed")
			return
		}
		s.auditAdmin(r, "harbor.registry.upsert", row.ID, auditJSON(map[string]any{"name": row.Name, "url": row.URL, "insecure_tls": row.InsecureTLS}))
		writeJSON(w, http.StatusCreated, map[string]any{"registry": row, "note": "Harbor registry metadata was saved. Robot tokens are never stored on this endpoint."})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleHarborRegistryByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/harbor/registries/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "registry id required", "invalid_request_error", "missing_registry_id")
		return
	}
	reg, err := s.db.GetHarborRegistry(r.Context(), parts[0])
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "harbor registry not found", "invalid_request_error", "not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_registry_failed")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"registry": reg})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPost {
		var in struct {
			Name        string `json:"name"`
			URL         string `json:"url"`
			InsecureTLS bool   `json:"insecure_tls"`
			CARef       string `json:"ca_ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		url := harbor.NormalizeRegistryURL(firstNonEmpty(in.URL, reg.URL))
		if strings.TrimSpace(in.Name) == "" || url == "" {
			writeOpenAIError(w, http.StatusBadRequest, "name and url are required", "invalid_request_error", "missing_fields")
			return
		}
		if url != reg.URL {
			reg.Status = "registered"
			reg.Version = ""
			reg.LastCheckedAt = ""
			reg.LastError = ""
		}
		reg.Name = strings.TrimSpace(in.Name)
		reg.URL = url
		reg.InsecureTLS = in.InsecureTLS
		reg.CARef = strings.TrimSpace(in.CARef)
		if err := s.db.UpsertHarborRegistry(r.Context(), reg); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_registry_save_failed")
			return
		}
		s.auditAdmin(r, "harbor.registry.update", reg.ID, auditJSON(map[string]any{"name": reg.Name, "url": reg.URL, "insecure_tls": reg.InsecureTLS}))
		writeJSON(w, http.StatusOK, map[string]any{"registry": reg})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		force := boolQuery(r.URL.Query().Get("force"))
		refs, err := s.db.CountHarborRegistryReferences(r.Context(), reg.ID)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_registry_reference_failed")
			return
		}
		if !force && refs["robots"]+refs["mappings"]+refs["launches"] > 0 {
			writeOpenAIError(w, http.StatusConflict, "registry has linked robots, mappings or launch history; retry with force=true to remove registry metadata and linked robots/mappings", "invalid_request_error", "harbor_registry_has_references")
			return
		}
		if err := s.db.DeleteHarborRegistry(r.Context(), reg.ID, force); err != nil {
			status := http.StatusInternalServerError
			code := "harbor_registry_delete_failed"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "not_found"
			}
			writeOpenAIError(w, status, err.Error(), "server_error", code)
			return
		}
		s.auditAdmin(r, "harbor.registry.delete", reg.ID, auditJSON(map[string]any{"force": force, "references": refs}))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": reg.ID, "force": force, "references": refs})
		return
	}
	if len(parts) == 2 && parts[1] == "test" && r.Method == http.MethodPost {
		client := &http.Client{Timeout: 8 * time.Second}
		result := harbor.CheckSystemInfo(r.Context(), client, reg.URL)
		status := "connected"
		if !result.OK {
			status = "error"
		}
		_ = s.db.UpdateHarborRegistryStatus(r.Context(), reg.ID, status, result.Version, result.CheckedAt, result.Error)
		s.auditAdmin(r, "harbor.registry.test", reg.ID, auditJSON(map[string]any{"ok": result.OK, "status_code": result.StatusCode, "error": result.Error}))
		writeJSON(w, http.StatusOK, map[string]any{"result": result, "status": status})
		return
	}
	writeOpenAIError(w, http.StatusNotFound, "unknown harbor registry operation", "invalid_request_error", "not_found")
}

func (s *Server) handleHarborRobotByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/harbor/robots/"), "/")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "robot id required", "invalid_request_error", "missing_robot_id")
		return
	}
	robot, err := s.db.GetHarborRobotAccount(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "robot account not found", "invalid_request_error", "not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_robot_failed")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"robot": robot})
	case http.MethodPost:
		var in struct {
			RegistryID   string `json:"registry_id"`
			ProjectName  string `json:"project_name"`
			Name         string `json:"name"`
			Token        string `json:"token"`
			CredentialID string `json:"credential_id"`
			ExpiresAt    string `json:"expires_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		robot.RegistryID = firstNonEmpty(in.RegistryID, robot.RegistryID)
		robot.ProjectName = firstNonEmpty(in.ProjectName, robot.ProjectName)
		robot.Name = firstNonEmpty(in.Name, robot.Name)
		robot.ExpiresAt = strings.TrimSpace(in.ExpiresAt)
		if _, err := s.db.GetHarborRegistry(r.Context(), robot.RegistryID); err != nil {
			status := http.StatusInternalServerError
			code := "harbor_registry_failed"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "harbor_registry_not_found"
			}
			writeOpenAIError(w, status, err.Error(), "server_error", code)
			return
		}
		token := strings.TrimSpace(in.Token)
		if token == "" && strings.TrimSpace(in.CredentialID) != "" {
			if cred, ok := s.resolveHarborCredential(w, r, in.CredentialID); ok {
				token = cred.Secret
				if strings.TrimSpace(robot.Name) == "" {
					robot.Name = cred.Username
				}
			} else {
				return
			}
		}
		if strings.TrimSpace(robot.RegistryID) == "" || strings.TrimSpace(robot.ProjectName) == "" || strings.TrimSpace(robot.Name) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "registry_id, project_name and name are required", "invalid_request_error", "missing_fields")
			return
		}
		if token != "" {
			robot.TokenHash = harbor.TokenHash(token)
			robot.HasTokenHash = true
			robot.Status = "registered"
			robot.LastVerifiedAt = ""
			robot.LastError = ""
		}
		if err := s.db.UpsertHarborRobotAccount(r.Context(), robot); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_robot_save_failed")
			return
		}
		robot.TokenHash = ""
		s.auditAdmin(r, "harbor.robot.update", robot.ID, auditJSON(map[string]any{"registry_id": robot.RegistryID, "project": robot.ProjectName, "name": robot.Name, "token_rotated": token != "", "credential_id": in.CredentialID}))
		writeJSON(w, http.StatusOK, map[string]any{"robot": robot, "token_policy": "token is encrypted in the user credential vault when credential_id is used; API responses never include it"})
	case http.MethodDelete:
		if err := s.db.DeleteHarborRobotAccount(r.Context(), robot.ID); err != nil {
			status := http.StatusInternalServerError
			code := "harbor_robot_delete_failed"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "not_found"
			}
			writeOpenAIError(w, status, err.Error(), "server_error", code)
			return
		}
		s.auditAdmin(r, "harbor.robot.delete", robot.ID, auditJSON(map[string]any{"registry_id": robot.RegistryID, "project": robot.ProjectName, "name": robot.Name}))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": robot.ID})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleHarborRobots(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListHarborRobotAccounts(r.Context(), strings.TrimSpace(r.URL.Query().Get("registry_id")), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_robot_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"robots": rows, "count": len(rows), "token_policy": "token may be supplied once or reused through a user-scoped external credential; API responses never include token or token hash"})
	case http.MethodPost:
		var in struct {
			ID           string `json:"id"`
			RegistryID   string `json:"registry_id"`
			ProjectName  string `json:"project_name"`
			Name         string `json:"name"`
			Token        string `json:"token"`
			CredentialID string `json:"credential_id"`
			ExpiresAt    string `json:"expires_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		token := strings.TrimSpace(in.Token)
		if token == "" && strings.TrimSpace(in.CredentialID) != "" {
			if cred, ok := s.resolveHarborCredential(w, r, in.CredentialID); ok {
				token = cred.Secret
				if strings.TrimSpace(in.Name) == "" {
					in.Name = cred.Username
				}
			} else {
				return
			}
		}
		if strings.TrimSpace(in.RegistryID) == "" || strings.TrimSpace(in.ProjectName) == "" || strings.TrimSpace(in.Name) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "registry_id, project_name and name are required", "invalid_request_error", "missing_fields")
			return
		}
		if _, err := s.db.GetHarborRegistry(r.Context(), strings.TrimSpace(in.RegistryID)); err != nil {
			status := http.StatusInternalServerError
			code := "harbor_registry_failed"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "harbor_registry_not_found"
			}
			writeOpenAIError(w, status, err.Error(), "server_error", code)
			return
		}
		tokenHash := ""
		if token != "" {
			tokenHash = harbor.TokenHash(token)
		}
		row := store.HarborRobotAccount{
			ID: firstNonEmpty(strings.TrimSpace(in.ID), newID("hrobot")), RegistryID: strings.TrimSpace(in.RegistryID),
			ProjectName: strings.TrimSpace(in.ProjectName), Name: strings.TrimSpace(in.Name), TokenHash: tokenHash,
			ExpiresAt: strings.TrimSpace(in.ExpiresAt), Status: "registered", CreatedBy: adminID(r),
		}
		if err := s.db.UpsertHarborRobotAccount(r.Context(), row); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_robot_save_failed")
			return
		}
		row.HasTokenHash = tokenHash != ""
		row.TokenHash = ""
		s.auditAdmin(r, "harbor.robot.upsert", row.ID, auditJSON(map[string]any{"registry_id": row.RegistryID, "project": row.ProjectName, "name": row.Name, "token_hash_stored": tokenHash != "", "credential_id": in.CredentialID}))
		writeJSON(w, http.StatusCreated, map[string]any{"robot": row, "note": "Robot token was hashed for drift/rotation evidence. Use external integration credentials to store the encrypted token per user."})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleHarborRobotVerify(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		RobotID      string `json:"robot_id"`
		Token        string `json:"token"`
		CredentialID string `json:"credential_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	robot, err := s.db.GetHarborRobotAccount(r.Context(), strings.TrimSpace(in.RobotID))
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "robot account not found", "invalid_request_error", "not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_robot_failed")
		return
	}
	reg, err := s.db.GetHarborRegistry(r.Context(), robot.RegistryID)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_registry_failed")
		return
	}
	token := strings.TrimSpace(in.Token)
	robotName := robot.Name
	if token == "" && strings.TrimSpace(in.CredentialID) != "" {
		if cred, ok := s.resolveHarborCredential(w, r, in.CredentialID); ok {
			token = cred.Secret
			robotName = firstNonEmptyStr(robotName, cred.Username)
		} else {
			return
		}
	}
	result := harbor.CheckRobotPull(r.Context(), &http.Client{Timeout: 8 * time.Second}, reg.URL, robotName, token, robot.ProjectName)
	status := "verified"
	if !result.OK {
		status = "failed"
	}
	_ = s.db.UpdateHarborRobotVerification(r.Context(), robot.ID, status, result.CheckedAt, result.Error)
	s.auditAdmin(r, "harbor.robot.verify", robot.ID, auditJSON(map[string]any{"registry_id": reg.ID, "project": robot.ProjectName, "ok": result.OK, "status_code": result.StatusCode, "credential_id": in.CredentialID}))
	writeJSON(w, http.StatusOK, map[string]any{"result": result, "status": status, "token_policy": "token is resolved from the encrypted user credential when credential_id is used"})
}

func (s *Server) handleHarborMappings(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListHarborProjectMappings(r.Context(), strings.TrimSpace(r.URL.Query().Get("registry_id")), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_mapping_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mappings": rows, "count": len(rows)})
	case http.MethodPost:
		var in store.HarborProjectMapping
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.RegistryID) == "" || strings.TrimSpace(in.ProjectName) == "" || strings.TrimSpace(in.ClusterID) == "" || strings.TrimSpace(in.Namespace) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "registry_id, project_name, cluster_id and namespace are required", "invalid_request_error", "missing_fields")
			return
		}
		in.ID = firstNonEmpty(strings.TrimSpace(in.ID), newID("hmap"))
		in.SecretName = firstNonEmpty(strings.TrimSpace(in.SecretName), harbor.DefaultSecretName(in.ProjectName))
		in.CreatedBy = adminID(r)
		if err := s.db.UpsertHarborProjectMapping(r.Context(), in); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_mapping_save_failed")
			return
		}
		s.auditAdmin(r, "harbor.mapping.upsert", in.ID, auditJSON(map[string]any{"registry_id": in.RegistryID, "project": in.ProjectName, "cluster_id": in.ClusterID, "namespace": in.Namespace}))
		writeJSON(w, http.StatusCreated, map[string]any{"mapping": in})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleHarborMappingByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/harbor/mappings/"), "/")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "mapping id required", "invalid_request_error", "missing_mapping_id")
		return
	}
	mapping, err := s.db.GetHarborProjectMapping(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "harbor mapping not found", "invalid_request_error", "not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_mapping_failed")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"mapping": mapping})
	case http.MethodPost:
		var in store.HarborProjectMapping
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		mapping.RegistryID = firstNonEmpty(in.RegistryID, mapping.RegistryID)
		mapping.ProjectName = firstNonEmpty(in.ProjectName, mapping.ProjectName)
		mapping.ClusterID = firstNonEmpty(in.ClusterID, mapping.ClusterID)
		mapping.Namespace = firstNonEmpty(in.Namespace, mapping.Namespace)
		mapping.SecretName = firstNonEmpty(in.SecretName, harbor.DefaultSecretName(mapping.ProjectName))
		mapping.OwnerTeam = strings.TrimSpace(in.OwnerTeam)
		if strings.TrimSpace(mapping.RegistryID) == "" || strings.TrimSpace(mapping.ProjectName) == "" || strings.TrimSpace(mapping.ClusterID) == "" || strings.TrimSpace(mapping.Namespace) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "registry_id, project_name, cluster_id and namespace are required", "invalid_request_error", "missing_fields")
			return
		}
		if _, err := s.db.GetHarborRegistry(r.Context(), mapping.RegistryID); err != nil {
			status := http.StatusInternalServerError
			code := "harbor_registry_failed"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "harbor_registry_not_found"
			}
			writeOpenAIError(w, status, err.Error(), "server_error", code)
			return
		}
		if err := s.db.UpsertHarborProjectMapping(r.Context(), mapping); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_mapping_save_failed")
			return
		}
		s.auditAdmin(r, "harbor.mapping.update", mapping.ID, auditJSON(map[string]any{"registry_id": mapping.RegistryID, "project": mapping.ProjectName, "cluster_id": mapping.ClusterID, "namespace": mapping.Namespace}))
		writeJSON(w, http.StatusOK, map[string]any{"mapping": mapping})
	case http.MethodDelete:
		if err := s.db.DeleteHarborProjectMapping(r.Context(), mapping.ID); err != nil {
			status := http.StatusInternalServerError
			code := "harbor_mapping_delete_failed"
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
				code = "not_found"
			}
			writeOpenAIError(w, status, err.Error(), "server_error", code)
			return
		}
		s.auditAdmin(r, "harbor.mapping.delete", mapping.ID, auditJSON(map[string]any{"registry_id": mapping.RegistryID, "project": mapping.ProjectName, "cluster_id": mapping.ClusterID, "namespace": mapping.Namespace}))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": mapping.ID})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleHarborCatalogQuery(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		RegistryID   string `json:"registry_id"`
		RegistryURL  string `json:"registry_url"`
		Target       string `json:"target"`
		ProjectName  string `json:"project_name"`
		Repository   string `json:"repository"`
		RobotName    string `json:"robot_name"`
		Token        string `json:"token"`
		CredentialID string `json:"credential_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	reg, err := s.resolveHarborRegistry(w, r, in.RegistryID, in.RegistryURL)
	if err != nil {
		return
	}
	token := strings.TrimSpace(in.Token)
	robotName := strings.TrimSpace(in.RobotName)
	if token == "" && strings.TrimSpace(in.CredentialID) != "" {
		if cred, ok := s.resolveHarborCredential(w, r, in.CredentialID); ok {
			token = cred.Secret
			robotName = firstNonEmptyStr(robotName, cred.Username)
		} else {
			return
		}
	}
	result := harbor.QueryCatalog(r.Context(), &http.Client{Timeout: 10 * time.Second}, reg.URL, in.Target, in.ProjectName, in.Repository, robotName, token)
	s.auditAdmin(r, "harbor.catalog.query", reg.ID, auditJSON(map[string]any{"target": result.Target, "project": in.ProjectName, "repository": in.Repository, "ok": result.OK, "status_code": result.StatusCode, "robot_supplied": robotName != "", "credential_id": in.CredentialID}))
	status := http.StatusOK
	if !result.OK && result.StatusCode >= 400 {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]any{"result": result, "token_policy": "robot token is resolved from the encrypted user credential when credential_id is used; never echoed"})
}

func (s *Server) handleHarborPullSecretPreview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		RegistryID   string `json:"registry_id"`
		RegistryURL  string `json:"registry_url"`
		ProjectName  string `json:"project_name"`
		Namespace    string `json:"namespace"`
		SecretName   string `json:"secret_name"`
		RobotName    string `json:"robot_name"`
		Token        string `json:"token"`
		CredentialID string `json:"credential_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	reg, err := s.resolveHarborRegistry(w, r, in.RegistryID, in.RegistryURL)
	if err != nil {
		return
	}
	secret := firstNonEmpty(in.SecretName, harbor.DefaultSecretName(in.ProjectName))
	token := strings.TrimSpace(in.Token)
	robotName := strings.TrimSpace(in.RobotName)
	if token == "" && strings.TrimSpace(in.CredentialID) != "" {
		if cred, ok := s.resolveHarborCredential(w, r, in.CredentialID); ok {
			token = cred.Secret
			robotName = firstNonEmptyStr(robotName, cred.Username)
		} else {
			return
		}
	}
	manifest := harbor.RedactedPullSecretManifest(secret, in.Namespace, reg.URL, robotName)
	hash := ""
	if token != "" && robotName != "" {
		hash = harbor.DockerConfigHash(harbor.RegistryHost(reg.URL), robotName, token)
	}
	s.auditAdmin(r, "harbor.pull_secret.preview", reg.ID, auditJSON(map[string]any{"namespace": in.Namespace, "secret_name": secret, "robot": robotName, "dockerconfig_hash_present": hash != "", "credential_id": in.CredentialID}))
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest":          manifest,
		"secret_name":       secret,
		"dockerconfig_hash": hash,
		"redacted":          true,
		"note":              "토큰은 응답·DB·감사 로그에 남기지 않습니다. 실제 Secret 적용은 Credential Vault에서 메모리 복호화한 값 또는 승인된 일회성 입력 경로로만 수행하세요.",
	})
}

func (s *Server) handleHarborLaunchPreview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	in, ok := s.decodeHarborLaunchPayload(w, r)
	if !ok {
		return
	}
	out, ok := s.prepareHarborLaunch(w, r, in)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleHarborLaunches(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListHarborLaunchRequests(r.Context(), strings.TrimSpace(r.URL.Query().Get("registry_id")), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_launch_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"launches": rows, "count": len(rows)})
	case http.MethodPost:
		in, ok := s.decodeHarborLaunchPayload(w, r)
		if !ok {
			return
		}
		prepared, ok := s.prepareHarborLaunch(w, r, in)
		if !ok {
			return
		}
		policyJSON, _ := json.Marshal(prepared["policy_findings"])
		status := "pending_approval"
		if prepared["decision"] == "deny" {
			status = "blocked"
		} else if prepared["decision"] == "allow" {
			status = "draft"
		}
		registryID := strings.TrimSpace(in.RegistryID)
		if registryID == "" {
			if reg, ok := prepared["registry"].(store.HarborRegistry); ok {
				registryID = reg.ID
			}
		}
		req := store.HarborLaunchRequest{
			ID: newID("hlaunch"), RegistryID: registryID, ProjectName: strings.TrimSpace(in.ProjectName),
			Repository: strings.TrimSpace(in.Repository), Tag: strings.TrimSpace(in.Tag), Digest: strings.TrimSpace(in.Digest),
			Image: prepared["image"].(string), ClusterID: strings.TrimSpace(in.ClusterID), Namespace: firstNonEmpty(in.Namespace, "default"),
			AppName: firstNonEmpty(in.AppName, "harbor-app"), Replicas: harborMaxInt(in.Replicas, 1), Port: harborMaxInt(in.Port, 8080),
			RobotID: strings.TrimSpace(in.RobotID), SecretName: prepared["secret_name"].(string), Decision: prepared["decision"].(string),
			Reason: prepared["reason"].(string), Status: status, RequestedBy: adminID(r), ManifestPreview: prepared["manifest"].(string), PolicyJSON: string(policyJSON),
		}
		if err := s.db.CreateHarborLaunchRequest(r.Context(), req); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_launch_save_failed")
			return
		}
		s.auditAdmin(r, "harbor.launch.request", req.ID, auditJSON(map[string]any{"image": req.Image, "decision": req.Decision, "status": req.Status, "cluster_id": req.ClusterID, "namespace": req.Namespace}))
		writeJSON(w, http.StatusCreated, map[string]any{"launch": req, "preview": prepared, "note": "런칭 요청이 원장에 저장되었습니다. blocked가 아니면 Manifest Change Studio/승인형 executor 경로로 적용하세요."})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleHarborLaunchByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/harbor/launches/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeOpenAIError(w, http.StatusBadRequest, "launch id required", "invalid_request_error", "missing_launch_id")
		return
	}
	launch, err := s.db.GetHarborLaunchRequest(r.Context(), parts[0])
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "harbor launch request not found", "invalid_request_error", "not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_launch_failed")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"launch": launch})
		return
	}
	if len(parts) == 2 && parts[1] == "manifest-change" && r.Method == http.MethodPost {
		s.createHarborLaunchManifestChange(w, r, launch)
		return
	}
	writeOpenAIError(w, http.StatusNotFound, "unknown harbor launch operation", "invalid_request_error", "not_found")
}

func (s *Server) createHarborLaunchManifestChange(w http.ResponseWriter, r *http.Request, launch store.HarborLaunchRequest) {
	if launch.Decision == "deny" || launch.Status == "blocked" {
		writeOpenAIError(w, http.StatusConflict, "blocked Harbor launch cannot create a manifest change draft", "invalid_request_error", "harbor_launch_blocked")
		return
	}
	if strings.TrimSpace(launch.ClusterID) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "launch cluster_id is required before creating Manifest Change draft", "invalid_request_error", "missing_cluster_id")
		return
	}
	docs := manifestDocuments(launch.ManifestPreview)
	if len(docs) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "launch manifest preview is empty", "invalid_request_error", "missing_manifest")
		return
	}
	type draftCandidate struct {
		APIVersion     string
		Kind           string
		Namespace      string
		Name           string
		AfterYAML      string
		IdempotencyKey string
	}
	candidates := make([]draftCandidate, 0, len(docs))
	for i, docYAML := range docs {
		doc, err := parseSingleManifestDoc(docYAML)
		if err != nil {
			writeManifestChangeCreateError(w, manifestChangeCreateHTTPError(http.StatusBadRequest, "launch manifest parse error: "+err.Error(), "harbor_launch_manifest_parse_failed"))
			return
		}
		apiVersion, kind, namespace, name := manifestDocIdentity(doc)
		if namespace == "" && strings.TrimSpace(launch.Namespace) != "" {
			namespace = strings.TrimSpace(launch.Namespace)
		}
		if name == "" {
			name = firstNonEmpty(launch.AppName, "harbor-app")
		}
		key := "harbor-launch-" + launch.ID + "-" + harborManifestDraftKey(kind, namespace, name, i)
		if strings.TrimSpace(apiVersion) == "" || strings.TrimSpace(kind) == "" || strings.TrimSpace(name) == "" {
			writeManifestChangeCreateError(w, manifestChangeCreateHTTPError(http.StatusBadRequest, "launch manifest requires apiVersion, kind and metadata.name", "harbor_launch_manifest_identity_failed"))
			return
		}
		if _, err := s.db.GetK8sManifestChangeRequestByIdempotencyKey(r.Context(), key); errors.Is(err, store.ErrNotFound) {
			if existing, liveErr := s.db.GetK8sInventoryItem(r.Context(), launch.ClusterID, canonicalManifestKind(kind), firstNonEmpty(namespace, "default"), name); liveErr == nil {
				writeManifestChangeCreateError(w, manifestChangeCreateHTTPError(http.StatusConflict, "resource already exists for Harbor launch draft: "+existing.Kind+"/"+existing.Namespace+"/"+existing.Name, "harbor_launch_target_exists"))
				return
			} else if !errors.Is(liveErr, store.ErrNotFound) {
				writeManifestChangeCreateError(w, manifestChangeCreateHTTPError(http.StatusInternalServerError, liveErr.Error(), "k8s_inventory_failed"))
				return
			}
		} else if err != nil {
			writeManifestChangeCreateError(w, manifestChangeCreateHTTPError(http.StatusInternalServerError, err.Error(), "k8s_manifest_change_idempotency_lookup_failed"))
			return
		}
		candidates = append(candidates, draftCandidate{
			APIVersion: apiVersion, Kind: kind, Namespace: firstNonEmpty(namespace, "default"), Name: name,
			AfterYAML: docYAML, IdempotencyKey: key,
		})
	}
	results := make([]manifestChangeCreateResult, 0, len(candidates))
	responseRows := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		result, err := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), manifestChangeCreateInput{
			ClusterID:      launch.ClusterID,
			Namespace:      candidate.Namespace,
			Kind:           candidate.Kind,
			APIVersion:     candidate.APIVersion,
			Name:           candidate.Name,
			Operation:      "create",
			AfterYAML:      candidate.AfterYAML,
			Reason:         "Harbor launch " + launch.ID + " image " + launch.Image,
			IdempotencyKey: candidate.IdempotencyKey,
		})
		if err != nil {
			writeManifestChangeCreateError(w, err)
			return
		}
		results = append(results, result)
		responseRows = append(responseRows, map[string]any{
			"id":                result.Request.ID,
			"kind":              result.Request.Kind,
			"namespace":         result.Request.Namespace,
			"name":              result.Request.Name,
			"operation":         result.Operation,
			"status":            result.Request.Status,
			"idempotent_replay": result.IdempotentReplay,
		})
	}
	first := results[0]
	ids := make([]string, 0, len(results))
	for _, result := range results {
		ids = append(ids, result.Request.ID)
	}
	status := "manifest_drafted"
	reason := firstNonEmpty(launch.Reason, "Manifest Change drafts created: "+strings.Join(ids, ","))
	_ = s.db.UpdateHarborLaunchStatus(r.Context(), launch.ID, status, reason)
	s.auditAdmin(r, "harbor.launch.manifest_change", launch.ID, auditJSON(map[string]any{
		"manifest_change_ids": ids,
		"cluster_id":          launch.ClusterID,
		"namespace":           launch.Namespace,
		"image":               launch.Image,
	}))
	writeJSON(w, http.StatusCreated, map[string]any{
		"launch_id":           launch.ID,
		"manifest_change":     manifestChangeCreateResponse(first),
		"manifest_change_id":  first.Request.ID,
		"manifest_changes":    responseRows,
		"manifest_change_ids": ids,
		"manifest_change_url": "#/k8s-manifest-changes?cluster_id=" + launch.ClusterID + "&focus_id=" + first.Request.ID,
		"note":                "Deployment/Service draft가 Manifest Change Studio에 생성되었습니다. 검증, 승인, 적용은 YAML 변경/생성 원장에서 진행하세요.",
	})
}

type harborLaunchPayload struct {
	RegistryID      string `json:"registry_id"`
	RegistryURL     string `json:"registry_url"`
	ProjectName     string `json:"project_name"`
	Repository      string `json:"repository"`
	Tag             string `json:"tag"`
	Digest          string `json:"digest"`
	ClusterID       string `json:"cluster_id"`
	Namespace       string `json:"namespace"`
	AppName         string `json:"app_name"`
	ContainerName   string `json:"container_name"`
	Replicas        int    `json:"replicas"`
	Port            int    `json:"port"`
	RobotID         string `json:"robot_id"`
	SecretName      string `json:"secret_name"`
	ImagePullSecret string `json:"image_pull_secret"`
}

func (s *Server) decodeHarborLaunchPayload(w http.ResponseWriter, r *http.Request) (harborLaunchPayload, bool) {
	var in harborLaunchPayload
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return in, false
	}
	if strings.TrimSpace(in.ProjectName) == "" || strings.TrimSpace(in.Repository) == "" {
		writeOpenAIError(w, http.StatusBadRequest, "project_name and repository are required", "invalid_request_error", "missing_fields")
		return in, false
	}
	return in, true
}

func (s *Server) prepareHarborLaunch(w http.ResponseWriter, r *http.Request, in harborLaunchPayload) (map[string]any, bool) {
	reg, err := s.resolveHarborRegistry(w, r, in.RegistryID, in.RegistryURL)
	if err != nil {
		return nil, false
	}
	robotStatus, robotExpires := "", ""
	if strings.TrimSpace(in.RobotID) != "" {
		robot, err := s.db.GetHarborRobotAccount(r.Context(), strings.TrimSpace(in.RobotID))
		if err == nil {
			robotStatus = robot.Status
			robotExpires = robot.ExpiresAt
		}
	}
	secret := firstNonEmpty(in.ImagePullSecret, in.SecretName, harbor.DefaultSecretName(in.ProjectName))
	manifest, image := harbor.LaunchManifests(harbor.LaunchManifestInput{
		RegistryURL: reg.URL, Project: in.ProjectName, Repository: in.Repository, Tag: in.Tag, Digest: in.Digest,
		Namespace: firstNonEmpty(in.Namespace, "default"), AppName: in.AppName, ContainerName: in.ContainerName,
		ImagePullSecret: secret, Replicas: harborMaxInt(in.Replicas, 1), Port: harborMaxInt(in.Port, 8080),
	})
	decision, findings := harbor.EvaluateLaunchPolicy(in.Tag, in.Digest, robotStatus, robotExpires)
	reason := harborFindingsReason(findings)
	return map[string]any{
		"registry":        reg,
		"manifest":        manifest,
		"image":           image,
		"secret_name":     secret,
		"decision":        decision,
		"reason":          reason,
		"policy_findings": findings,
		"next_steps": []string{
			"imagePullSecret은 token을 응답하지 않는 승인형 경로에서 먼저 생성합니다.",
			"manifest는 YAML 변경/생성 화면 또는 Stack Apply 경로에서 dry-run, 승인, SSA apply를 거칩니다.",
			"ImagePullBackOff 발생 시 Harbor Robot 권한, Secret namespace, digest, registry 인증서를 순서대로 확인합니다.",
		},
	}, true
}

func (s *Server) resolveHarborRegistry(w http.ResponseWriter, r *http.Request, registryID, registryURL string) (store.HarborRegistry, error) {
	if strings.TrimSpace(registryID) != "" {
		reg, err := s.db.GetHarborRegistry(r.Context(), strings.TrimSpace(registryID))
		if errors.Is(err, store.ErrNotFound) {
			writeOpenAIError(w, http.StatusNotFound, "harbor registry not found", "invalid_request_error", "harbor_registry_not_found")
		} else if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_registry_failed")
		}
		return reg, err
	}
	url := harbor.NormalizeRegistryURL(registryURL)
	if url == "" {
		writeOpenAIError(w, http.StatusBadRequest, "registry_id or registry_url is required", "invalid_request_error", "missing_registry")
		return store.HarborRegistry{}, errors.New("missing registry")
	}
	return store.HarborRegistry{ID: "ad-hoc", Name: harbor.RegistryHost(url), URL: url, Status: "ad_hoc"}, nil
}

func (s *Server) resolveHarborCredential(w http.ResponseWriter, r *http.Request, credentialID string) (resolvedExternalCredential, bool) {
	cred, found, err := s.resolveExternalCredential(r, credentialID, "")
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "harbor_credential_decrypt_failed")
		return resolvedExternalCredential{}, false
	}
	if !found {
		writeOpenAIError(w, http.StatusNotFound, "external credential not found", "invalid_request_error", "harbor_credential_not_found")
		return resolvedExternalCredential{}, false
	}
	switch normalizeExternalProvider(cred.Provider) {
	case "harbor", "harbor_robot":
		return cred, true
	default:
		writeOpenAIError(w, http.StatusBadRequest, "credential provider must be harbor or harbor_robot", "invalid_request_error", "harbor_credential_provider_mismatch")
		return resolvedExternalCredential{}, false
	}
}

func harborFindingsReason(findings []harbor.PolicyFinding) string {
	parts := []string{}
	for _, f := range findings {
		if f.Decision != "allow" {
			parts = append(parts, f.Rule+": "+f.Message)
		}
	}
	if len(parts) == 0 {
		return "Harbor launch baseline checks passed."
	}
	return strings.Join(parts, " | ")
}

func manifestDocuments(raw string) []string {
	parts := strings.Split(raw, "\n---")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if doc := strings.TrimSpace(part); doc != "" {
			out = append(out, doc)
		}
	}
	return out
}

func harborManifestDraftKey(kind, namespace, name string, index int) string {
	parts := []string{strings.ToLower(strings.TrimSpace(kind)), strings.ToLower(strings.TrimSpace(namespace)), strings.ToLower(strings.TrimSpace(name))}
	for i, part := range parts {
		part = strings.ReplaceAll(part, "/", "-")
		part = strings.ReplaceAll(part, "_", "-")
		part = strings.ReplaceAll(part, " ", "-")
		parts[i] = part
	}
	key := strings.Trim(strings.Join(parts, "-"), "-")
	if key == "" {
		key = "doc-" + strconv.Itoa(index+1)
	}
	return key
}

func boolQuery(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "1" || v == "true" || v == "yes" || v == "y"
}

func harborMaxInt(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
