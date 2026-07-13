package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/servicecatalog"
	"clustara/internal/store"
)

var serviceValuesSchema = map[string]any{"type": "object", "properties": map[string]any{
	"image":    map[string]any{"type": "string", "description": "Harbor image; digest pin recommended"},
	"replicas": map[string]any{"type": "integer", "minimum": 0, "maximum": 100},
	"cpu":      map[string]any{"type": "string"}, "memory": map[string]any{"type": "string"}, "storage": map[string]any{"type": "string"}, "port": map[string]any{"type": "integer"},
}, "required": []string{"image"}}

func (s *Server) ensureBuiltinServiceCatalogs(r *http.Request) error {
	rows, err := s.db.ListK8sServiceCatalogs(r.Context(), true)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		return nil
	}
	schema, _ := json.Marshal(serviceValuesSchema)
	for _, def := range servicecatalog.Builtins() {
		catID := "svccat_" + def.Code
		now := storeTimeNow()
		cat := store.K8sServiceCatalog{ID: catID, Code: def.Code, Name: def.Name, Category: def.Category, Description: def.Description, Icon: def.Icon, DeploymentType: def.DeploymentType, RequiredCapabilitiesJSON: `{"network_policy":true,"non_root":true}`, Enabled: true, CreatedBy: "builtin", CreatedAt: now}
		if err := s.db.UpsertK8sServiceCatalog(r.Context(), cat); err != nil {
			return err
		}
		defaults, _ := json.Marshal(map[string]any{"image": def.Image, "replicas": 1, "cpu": "500m", "memory": "1Gi", "storage": "20Gi", "port": serviceDefaultPort(def.Code)})
		ver := store.K8sServiceVersion{ID: "svcver_" + def.Code + "_" + strings.ReplaceAll(def.Version, ".", "_"), CatalogID: catID, Version: def.Version, DeploymentType: def.DeploymentType, Template: def.Template, ValuesSchemaJSON: string(schema), DefaultValuesJSON: string(defaults), Status: "available", Recommended: true, CreatedAt: now}
		if err := s.db.UpsertK8sServiceVersion(r.Context(), ver); err != nil {
			return err
		}
		for _, p := range []store.K8sServiceProfile{{ID: "svcprof_" + def.Code + "_small", Name: "small", CPU: "500m", Memory: "1Gi", Storage: "20Gi"}, {ID: "svcprof_" + def.Code + "_medium", Name: "medium", CPU: "1", Memory: "2Gi", Storage: "50Gi"}, {ID: "svcprof_" + def.Code + "_large", Name: "large", CPU: "2", Memory: "4Gi", Storage: "100Gi"}} {
			p.CatalogID = catID
			p.ValuesJSON = "{}"
			p.CreatedAt = now
			if err := s.db.UpsertK8sServiceProfile(r.Context(), p); err != nil {
				return err
			}
		}
	}
	return nil
}

func storeTimeNow() string { return fmt.Sprintf("%s", time.Now().UTC().Format(time.RFC3339Nano)) }
func serviceDefaultPort(code string) int {
	switch code {
	case "postgresql":
		return 5432
	case "redis":
		return 6379
	case "tomcat":
		return 8080
	case "jupyterlab", "jupyterhub":
		return 8888
	default:
		return 8080
	}
}

func (s *Server) canManageServiceCatalog(r *http.Request) bool {
	if !s.cfg.Auth.Enabled {
		role, _, ok := s.legacyTokenIdentity(r)
		return ok && role != "readonly_admin"
	}
	claims, ok := s.currentAccessClaims(r)
	return ok && hasScope(claims.Scopes, "service:catalog:manage")
}

func (s *Server) handleServiceCatalogs(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, 401, "unauthorized", "permission_error", "authentication_required")
		return
	}
	if err := s.ensureBuiltinServiceCatalogs(r); err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_catalog_seed_failed")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListK8sServiceCatalogs(r.Context(), r.URL.Query().Get("include_disabled") == "true")
		if err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_catalog_list_failed")
			return
		}
		writeJSON(w, 200, map[string]any{"catalogs": rows, "total": len(rows)})
	case http.MethodPost:
		var in store.K8sServiceCatalog
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeOpenAIError(w, 400, "invalid JSON", "invalid_request_error", "invalid_body")
			return
		}
		in.Code = strings.TrimSpace(in.Code)
		in.Name = strings.TrimSpace(in.Name)
		if in.Code == "" || in.Name == "" {
			writeOpenAIError(w, 400, "code and name are required", "invalid_request_error", "missing_fields")
			return
		}
		if in.ID == "" {
			in.ID = newID("svccat")
		}
		if in.DeploymentType == "" {
			in.DeploymentType = "manifest"
		}
		in.Enabled = true
		in.CreatedBy = adminID(r)
		if err := s.db.UpsertK8sServiceCatalog(r.Context(), in); err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_catalog_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.service_catalog.create", "", auditJSON(map[string]string{"id": in.ID, "code": in.Code}))
		writeJSON(w, 201, map[string]any{"catalog": in})
	default:
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleServiceCatalogByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, 401, "unauthorized", "permission_error", "authentication_required")
		return
	}
	_ = s.ensureBuiltinServiceCatalogs(r)
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/services/catalogs/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	cat, err := s.db.GetK8sServiceCatalog(r.Context(), id)
	if err != nil {
		writeOpenAIError(w, 404, "catalog not found", "invalid_request_error", "service_catalog_not_found")
		return
	}
	if len(parts) > 1 {
		switch parts[1] {
		case "versions":
			s.handleServiceCatalogVersion(w, r, cat)
			return
		case "validate":
			s.handleServiceCatalogValidate(w, r, cat)
			return
		case "schema":
			versions, _ := s.db.ListK8sServiceVersions(r.Context(), cat.ID)
			schema := "{}"
			if len(versions) > 0 {
				schema = versions[0].ValuesSchemaJSON
			}
			writeJSON(w, 200, map[string]any{"catalog_id": cat.ID, "schema": json.RawMessage(schema)})
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		versions, _ := s.db.ListK8sServiceVersions(r.Context(), cat.ID)
		if !s.canManageServiceCatalog(r) {
			filtered := versions[:0]
			for _, v := range versions {
				if v.Status == "available" {
					filtered = append(filtered, v)
				}
			}
			versions = filtered
		}
		profiles, _ := s.db.ListK8sServiceProfiles(r.Context(), cat.ID)
		writeJSON(w, 200, map[string]any{"catalog": cat, "versions": versions, "profiles": profiles})
	case http.MethodPut:
		var in store.K8sServiceCatalog
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			writeOpenAIError(w, 400, "invalid JSON", "invalid_request_error", "invalid_body")
			return
		}
		in.ID = cat.ID
		in.CreatedAt = cat.CreatedAt
		in.CreatedBy = cat.CreatedBy
		if in.Code == "" {
			in.Code = cat.Code
		}
		if in.Name == "" {
			in.Name = cat.Name
		}
		if err := s.db.UpsertK8sServiceCatalog(r.Context(), in); err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_catalog_save_failed")
			return
		}
		writeJSON(w, 200, map[string]any{"catalog": in})
	case http.MethodDelete:
		cat.Enabled = false
		if err := s.db.UpsertK8sServiceCatalog(r.Context(), cat); err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_catalog_disable_failed")
			return
		}
		writeJSON(w, 200, map[string]any{"disabled": cat.ID})
	default:
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleServiceCatalogVersion(w http.ResponseWriter, r *http.Request, cat store.K8sServiceCatalog) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in store.K8sServiceVersion
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeOpenAIError(w, 400, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	if strings.TrimSpace(in.Version) == "" || strings.TrimSpace(in.Template) == "" {
		writeOpenAIError(w, 400, "version and template are required", "invalid_request_error", "missing_fields")
		return
	}
	in.ID = newID("svcver")
	in.CatalogID = cat.ID
	if in.Status == "" {
		in.Status = "draft"
	}
	if in.DeploymentType == "" {
		in.DeploymentType = cat.DeploymentType
	}
	if in.ValuesSchemaJSON == "" {
		b, _ := json.Marshal(serviceValuesSchema)
		in.ValuesSchemaJSON = string(b)
	}
	if in.DefaultValuesJSON == "" {
		in.DefaultValuesJSON = "{}"
	}
	if err := s.db.UpsertK8sServiceVersion(r.Context(), in); err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_version_save_failed")
		return
	}
	writeJSON(w, 201, map[string]any{"version": in})
}

type serviceInstanceInput struct {
	CatalogID             string         `json:"catalog_id"`
	VersionID             string         `json:"version_id"`
	ProfileID             string         `json:"profile_id"`
	ClusterID             string         `json:"cluster_id"`
	Namespace             string         `json:"namespace"`
	Name                  string         `json:"name"`
	Environment           string         `json:"environment"`
	OwnerTeamID           string         `json:"owner_team_id"`
	WorkspaceID           string         `json:"workspace_id"`
	Criticality           string         `json:"criticality"`
	ExpiresAt             string         `json:"expires_at"`
	CostCenter            string         `json:"cost_center"`
	CredentialSecretName  string         `json:"credential_secret_name"`
	CredentialUsernameKey string         `json:"credential_username_key"`
	CredentialPasswordKey string         `json:"credential_password_key"`
	Values                map[string]any `json:"values"`
}

func (s *Server) prepareServiceInstance(r *http.Request, in serviceInstanceInput) (store.K8sServiceCatalog, store.K8sServiceVersion, string, map[string]any, []string, error) {
	cat, err := s.db.GetK8sServiceCatalog(r.Context(), in.CatalogID)
	if err != nil {
		return cat, store.K8sServiceVersion{}, "", nil, nil, fmt.Errorf("catalog not found")
	}
	versions, _ := s.db.ListK8sServiceVersions(r.Context(), cat.ID)
	var ver store.K8sServiceVersion
	if in.VersionID != "" {
		ver, err = s.db.GetK8sServiceVersion(r.Context(), in.VersionID)
	} else if len(versions) > 0 {
		ver = versions[0]
	} else {
		err = store.ErrNotFound
	}
	if err != nil {
		return cat, ver, "", nil, nil, fmt.Errorf("version not found")
	}
	if ver.Status != "available" && !s.canManageServiceCatalog(r) {
		return cat, ver, "", nil, nil, fmt.Errorf("version is not approved for self-service")
	}
	values := map[string]any{}
	_ = json.Unmarshal([]byte(ver.DefaultValuesJSON), &values)
	if in.ProfileID != "" {
		profile, profileErr := s.db.GetK8sServiceProfile(r.Context(), in.ProfileID)
		if profileErr != nil || profile.CatalogID != cat.ID {
			return cat, ver, "", nil, nil, fmt.Errorf("profile not found for catalog")
		}
		if profile.CPU != "" {
			values["cpu"] = profile.CPU
		}
		if profile.Memory != "" {
			values["memory"] = profile.Memory
		}
		if profile.Storage != "" {
			values["storage"] = profile.Storage
		}
		if profile.GPU != "" {
			values["gpu"] = profile.GPU
		}
	}
	for k, v := range in.Values {
		values[k] = v
	}
	str := func(k, d string) string {
		if v := strings.TrimSpace(fmt.Sprint(values[k])); v != "" && v != "<nil>" {
			return v
		}
		return d
	}
	num := func(k string, d int) int {
		switch v := values[k].(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			n, _ := strconv.Atoi(v)
			if n != 0 {
				return n
			}
		}
		return d
	}
	input := servicecatalog.RenderInput{Name: strings.TrimSpace(in.Name), Namespace: strings.TrimSpace(in.Namespace), Image: str("image", ""), CPU: str("cpu", "500m"), Memory: str("memory", "1Gi"), Storage: str("storage", "20Gi"), Replicas: num("replicas", 1), Port: num("port", serviceDefaultPort(cat.Code))}
	errList := servicecatalog.ValidateInput(input)
	if in.ClusterID == "" {
		errList = append(errList, "cluster_id가 필요합니다")
	} else if _, clusterErr := s.db.GetK8sCluster(r.Context(), in.ClusterID); clusterErr != nil {
		errList = append(errList, "등록된 cluster_id가 아닙니다")
	}
	if in.Environment == "production" && strings.Contains(input.Image, ":") && !strings.Contains(input.Image, "@sha256:") {
		errList = append(errList, "운영 환경 이미지는 digest 고정이 필요합니다")
	}
	if len(errList) > 0 {
		return cat, ver, "", values, errList, nil
	}
	manifest, err := servicecatalog.Render(servicecatalog.Definition{Code: cat.Code, Template: ver.Template}, input)
	return cat, ver, manifest, values, nil, err
}

func (s *Server) handleServiceCatalogValidate(w http.ResponseWriter, r *http.Request, cat store.K8sServiceCatalog) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in serviceInstanceInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeOpenAIError(w, 400, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	in.CatalogID = cat.ID
	s.writeServiceValidation(w, r, in)
}
func (s *Server) writeServiceValidation(w http.ResponseWriter, r *http.Request, in serviceInstanceInput) {
	cat, ver, manifest, values, errs, err := s.prepareServiceInstance(r, in)
	if err != nil {
		writeOpenAIError(w, 400, err.Error(), "invalid_request_error", "service_validation_failed")
		return
	}
	if len(errs) > 0 {
		writeJSON(w, 422, map[string]any{"valid": false, "errors": errs, "values": values})
		return
	}
	docs, err := decodeManifestDocs(manifest)
	if err != nil {
		writeOpenAIError(w, 400, err.Error(), "invalid_request_error", "manifest_parse_failed")
		return
	}
	policies, _ := s.db.ListK8sPolicies(r.Context())
	plan := analyzer.AnalyzeStackManifest(docs, toAnalyzerPolicies(policies))
	writeJSON(w, 200, map[string]any{"valid": true, "catalog": cat, "version": ver, "manifest": manifest, "resource_plan": plan, "values": values, "approval_required": in.Environment == "production"})
}

func (s *Server) handleServiceInstances(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, 401, "unauthorized", "permission_error", "authentication_required")
		return
	}
	_ = s.ensureBuiltinServiceCatalogs(r)
	if r.Method == http.MethodGet {
		owner := strings.TrimSpace(r.URL.Query().Get("owner_id"))
		if claims, ok := s.currentAccessClaims(r); ok && !hasScope(claims.Scopes, "service:catalog:manage") && claims.Role != "ops_admin" && claims.Role != "service_admin" {
			owner = claims.Subject
		}
		rows, err := s.db.ListK8sServiceInstances(r.Context(), r.URL.Query().Get("cluster_id"), owner, r.URL.Query().Get("status"), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_instances_failed")
			return
		}
		writeJSON(w, 200, map[string]any{"instances": rows, "total": len(rows)})
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in serviceInstanceInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeOpenAIError(w, 400, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	cat, ver, manifest, values, errs, err := s.prepareServiceInstance(r, in)
	if err != nil {
		writeOpenAIError(w, 400, err.Error(), "invalid_request_error", "service_create_failed")
		return
	}
	if len(errs) > 0 {
		writeJSON(w, 422, map[string]any{"valid": false, "errors": errs})
		return
	}
	sum := sha256.Sum256([]byte(manifest))
	stack, sNew, err := s.db.UpsertK8sStack(r.Context(), store.K8sApplicationStack{Name: in.Name, ClusterID: in.ClusterID, Namespace: in.Namespace, SourceType: "manifest", Manifest: manifest, ManifestHash: hex.EncodeToString(sum[:]), SyncPolicy: "approval", Status: "saved", CreatedBy: adminID(r)}, newID)
	if err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_stack_failed")
		return
	}
	_ = sNew
	owner := adminID(r)
	if claims, ok := s.currentAccessClaims(r); ok {
		owner = claims.Subject
	}
	valJSON, _ := json.Marshal(values)
	status := "validating"
	if in.Environment == "production" {
		status = "pending_approval"
	}
	instance := store.K8sServiceInstance{ID: newID("svcinst"), ClusterID: in.ClusterID, Namespace: in.Namespace, CatalogID: cat.ID, VersionID: ver.ID, ProfileID: in.ProfileID, StackID: stack.ID, Name: in.Name, Environment: firstNonEmpty(in.Environment, "development"), Status: status, OwnerID: owner, OwnerTeamID: in.OwnerTeamID, WorkspaceID: in.WorkspaceID, Criticality: firstNonEmpty(in.Criticality, "normal"), ValuesJSON: string(valJSON), PolicyResultJSON: `{"validated":true}`, ExpiresAt: in.ExpiresAt, CostCenter: in.CostCenter, CreatedBy: adminID(r)}
	if err := s.db.UpsertK8sServiceInstance(r.Context(), instance); err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_instance_save_failed")
		return
	}
	if strings.TrimSpace(in.CredentialSecretName) != "" {
		credential := store.K8sServiceCredential{
			ID: "svccred_" + instance.ID, ServiceInstanceID: instance.ID,
			SecretName:  strings.TrimSpace(in.CredentialSecretName),
			UsernameKey: strings.TrimSpace(in.CredentialUsernameKey),
			PasswordKey: strings.TrimSpace(in.CredentialPasswordKey), Namespace: instance.Namespace,
		}
		if err := s.db.UpsertK8sServiceCredential(r.Context(), credential); err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_credential_save_failed")
			return
		}
	}
	s.auditAdmin(r, "k8s.service_instance.create", "", auditJSON(map[string]string{"id": instance.ID, "stack_id": stack.ID}))
	writeJSON(w, 201, map[string]any{"instance": instance, "stack": stack, "next": map[string]string{"validate": "/admin/k8s/stacks/validate", "apply": "/admin/k8s/stacks/" + stack.ID + "/apply"}, "approval_required": in.Environment == "production"})
}

func (s *Server) handleServiceInstanceSpecial(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, 401, "unauthorized", "permission_error", "authentication_required")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in serviceInstanceInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeOpenAIError(w, 400, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	s.writeServiceValidation(w, r, in)
}

func (s *Server) serviceInstanceAllowed(r *http.Request, in store.K8sServiceInstance) bool {
	claims, ok := s.currentAccessClaims(r)
	if !ok {
		return true
	}
	return claims.Subject == in.OwnerID || claims.TeamID == in.OwnerTeamID || hasScope(claims.Scopes, "service:catalog:manage") || claims.Role == "ops_admin" || claims.Role == "service_admin"
}

func (s *Server) handleServiceInstanceByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, 401, "unauthorized", "permission_error", "authentication_required")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/services/instances/"), "/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	in, err := s.db.GetK8sServiceInstance(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, 404, "service instance not found", "invalid_request_error", "service_instance_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_instance_failed")
		return
	}
	if !s.serviceInstanceAllowed(r, in) {
		writeOpenAIError(w, 403, "service ownership scope denied", "permission_error", "service_scope_denied")
		return
	}
	if len(parts) > 1 {
		s.handleServiceOperation(w, r, in, parts[1])
		return
	}
	switch r.Method {
	case http.MethodGet:
		cat, _ := s.db.GetK8sServiceCatalog(r.Context(), in.CatalogID)
		ver, _ := s.db.GetK8sServiceVersion(r.Context(), in.VersionID)
		ops, _ := s.db.ListK8sServiceOperations(r.Context(), in.ID, 50)
		stack, _ := s.db.GetK8sStack(r.Context(), in.StackID)
		credentials := []store.K8sServiceCredential{}
		if claims, ok := s.currentAccessClaims(r); !ok || hasScope(claims.Scopes, "service:credential:read") || hasScope(claims.Scopes, "service:catalog:manage") || claims.Role == "ops_admin" || claims.Role == "service_admin" {
			credentials, _ = s.db.ListK8sServiceCredentials(r.Context(), in.ID)
		}
		health, healthErr := s.reconcileServiceInstance(r.Context(), in, false)
		backups, _ := s.db.ListK8sServiceBackups(r.Context(), in.ID, 50)
		restores, _ := s.db.ListK8sServiceRestores(r.Context(), in.ID, 50)
		jupyterWorkspaces := []serviceJupyterWorkspace{}
		if cat.Code == "jupyterhub" {
			jupyterWorkspaces, _ = s.discoverJupyterHubWorkspaces(r.Context(), in)
		}
		if healthErr != nil {
			components, _ := s.db.ListK8sServiceComponents(r.Context(), in.ID)
			endpoints, _ := s.db.ListK8sServiceEndpoints(r.Context(), in.ID)
			snapshot, _ := s.db.LatestK8sServiceHealthSnapshot(r.Context(), in.ID)
			writeJSON(w, 200, map[string]any{"instance": in, "catalog": cat, "version": ver, "stack": stack, "operations": ops, "components": components, "endpoints": endpoints, "credentials": credentials, "backups": backups, "restores": restores, "jupyter_workspaces": jupyterWorkspaces, "health": snapshot, "health_stale": true})
			return
		}
		writeJSON(w, 200, map[string]any{"instance": in, "catalog": cat, "version": ver, "stack": stack, "operations": ops, "components": health.Components, "endpoints": health.Endpoints, "credentials": credentials, "backups": backups, "restores": restores, "jupyter_workspaces": jupyterWorkspaces, "health": health.Health, "health_stale": false})
	case http.MethodDelete:
		s.recordServiceOperation(w, r, in, "delete", map[string]any{"preserve_pvc": true, "require_backup": true})
	default:
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleServiceOperation(w http.ResponseWriter, r *http.Request, in store.K8sServiceInstance, op string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	switch op {
	case "reconcile":
		s.handleServiceReconcile(w, r, in)
		return
	case "endpoints":
		s.handleServiceEndpoints(w, r, in)
		return
	case "credentials":
		s.handleServiceCredentials(w, r, in)
		return
	case "cost":
		s.handleServiceCost(w, r, in)
		return
	case "backups":
		s.handleServiceBackups(w, r, in)
		return
	case "jupyter-workspaces":
		s.handleServiceJupyterWorkspaces(w, r, in)
		return
	case "jupyter-config":
		s.handleServiceJupyterHubConfig(w, r, in)
		return
	case "jupyter-servers":
		s.handleServiceJupyterHubServers(w, r, in)
		return
	case "jupyter-server-actions":
		s.handleServiceJupyterHubServerAction(w, r, in)
		return
	case "jupyter-idle-policy":
		s.handleServiceJupyterHubIdlePolicy(w, r, in)
		return
	case "health":
		if r.Method == http.MethodGet {
			result, err := s.reconcileServiceInstance(r.Context(), in, false)
			if err != nil {
				writeOpenAIError(w, 500, err.Error(), "server_error", "service_health_failed")
				return
			}
			writeJSON(w, 200, result.Health)
			return
		}
	case "topology":
		if r.Method == http.MethodGet {
			components, _ := s.db.ListK8sServiceComponents(r.Context(), in.ID)
			endpoints, _ := s.db.ListK8sServiceEndpoints(r.Context(), in.ID)
			writeJSON(w, 200, map[string]any{"instance_id": in.ID, "stack_id": in.StackID, "graph_url": "#/k8s-graph?cluster_id=" + in.ClusterID + "&namespace=" + in.Namespace, "components": components, "endpoints": endpoints, "status": "observed"})
			return
		}
	}
	var params map[string]any
	_ = json.NewDecoder(r.Body).Decode(&params)
	s.recordServiceOperation(w, r, in, op, params)
}

func (s *Server) recordServiceOperation(w http.ResponseWriter, r *http.Request, in store.K8sServiceInstance, op string, params map[string]any) {
	if params == nil {
		params = map[string]any{}
	}
	idem := firstNonEmpty(strings.TrimSpace(r.Header.Get("Idempotency-Key")), newID("svcidem"))
	status := "pending_approval"
	requestID := ""
	actionName := ""
	switch op {
	case "start":
		actionName = "scale"
		params["replicas"] = 1
	case "stop":
		actionName = "scale"
		params["replicas"] = 0
	case "scale":
		actionName = "scale"
	case "restart":
		actionName = "rollout_restart"
	}
	if actionName != "" {
		requestID = newID("k8sact")
		kind := "Deployment"
		cat, _ := s.db.GetK8sServiceCatalog(r.Context(), in.CatalogID)
		if cat.Category == "database" {
			kind = "StatefulSet"
		}
		act := store.K8sActionRequest{ID: requestID, ClusterID: in.ClusterID, Namespace: in.Namespace, ResourceKind: kind, ResourceName: in.Name, Action: actionName, Parameters: params, RiskLevel: "medium", Status: "approval_required", RequestedBy: adminID(r), DryRunDiff: "Service Platform " + op + " request; existing Action Center execution", IdempotencyKey: idem}
		if err := s.db.InsertK8sActionRequest(r.Context(), act); err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_action_failed")
			return
		}
	}
	pJSON, _ := json.Marshal(params)
	rec := store.K8sServiceOperation{ID: newID("svcop"), ServiceInstanceID: in.ID, OperationType: op, Status: status, RequestID: requestID, IdempotencyKey: idem, ParametersJSON: string(pJSON), RequestedBy: adminID(r), Result: "Action Center approval required"}
	if err := s.db.InsertK8sServiceOperation(r.Context(), rec); err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_operation_failed")
		return
	}
	writeJSON(w, 202, map[string]any{"operation": rec, "action_request_id": requestID, "action_center": "#/k8s-actions", "stack_id": in.StackID})
}
