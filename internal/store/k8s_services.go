package store

import (
	"context"
	"database/sql"
	"time"
)

type K8sServiceCatalog struct {
	ID                       string `json:"id"`
	Code                     string `json:"code"`
	Name                     string `json:"name"`
	Category                 string `json:"category"`
	Description              string `json:"description"`
	Icon                     string `json:"icon"`
	DocsURL                  string `json:"docs_url"`
	DeploymentType           string `json:"deployment_type"`
	RequiredCapabilitiesJSON string `json:"required_capabilities_json"`
	Enabled                  bool   `json:"enabled"`
	CreatedBy                string `json:"created_by"`
	CreatedAt                string `json:"created_at"`
	UpdatedAt                string `json:"updated_at"`
}

type K8sServiceVersion struct {
	ID                string `json:"id"`
	CatalogID         string `json:"catalog_id"`
	Version           string `json:"version"`
	ChartRef          string `json:"chart_ref"`
	DeploymentType    string `json:"deployment_type"`
	Template          string `json:"template,omitempty"`
	ValuesSchemaJSON  string `json:"values_schema_json"`
	DefaultValuesJSON string `json:"default_values_json"`
	Status            string `json:"status"`
	Recommended       bool   `json:"recommended"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type K8sServiceProfile struct {
	ID         string `json:"id"`
	CatalogID  string `json:"catalog_id"`
	Name       string `json:"name"`
	CPU        string `json:"cpu"`
	Memory     string `json:"memory"`
	GPU        string `json:"gpu"`
	Storage    string `json:"storage"`
	ValuesJSON string `json:"values_json"`
	CreatedAt  string `json:"created_at"`
}

type K8sServiceInstance struct {
	ID               string `json:"id"`
	ClusterID        string `json:"cluster_id"`
	Namespace        string `json:"namespace"`
	CatalogID        string `json:"catalog_id"`
	VersionID        string `json:"version_id"`
	ProfileID        string `json:"profile_id"`
	StackID          string `json:"stack_id"`
	Name             string `json:"name"`
	Environment      string `json:"environment"`
	Status           string `json:"status"`
	OwnerID          string `json:"owner_id"`
	OwnerTeamID      string `json:"owner_team_id"`
	WorkspaceID      string `json:"workspace_id"`
	Criticality      string `json:"criticality"`
	ValuesJSON       string `json:"values_json"`
	PolicyResultJSON string `json:"policy_result_json"`
	ExpiresAt        string `json:"expires_at"`
	CostCenter       string `json:"cost_center"`
	CreatedBy        string `json:"created_by"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type K8sServiceOperation struct {
	ID                string `json:"id"`
	ServiceInstanceID string `json:"service_instance_id"`
	OperationType     string `json:"operation_type"`
	Status            string `json:"status"`
	RequestID         string `json:"request_id"`
	IdempotencyKey    string `json:"idempotency_key"`
	ParametersJSON    string `json:"parameters_json"`
	RequestedBy       string `json:"requested_by"`
	Result            string `json:"result"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type K8sServiceComponent struct {
	ID                string `json:"id"`
	ServiceInstanceID string `json:"service_instance_id"`
	ClusterID         string `json:"cluster_id"`
	Kind              string `json:"kind"`
	Namespace         string `json:"namespace"`
	ResourceName      string `json:"resource_name"`
	UID               string `json:"uid"`
	Status            string `json:"status"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type K8sServiceEndpoint struct {
	ID                string `json:"id"`
	ServiceInstanceID string `json:"service_instance_id"`
	EndpointType      string `json:"endpoint_type"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	TLSEnabled        bool   `json:"tls_enabled"`
	Path              string `json:"path"`
	CreatedAt         string `json:"created_at"`
}

type K8sServiceCredential struct {
	ID                string `json:"id"`
	ServiceInstanceID string `json:"service_instance_id"`
	SecretName        string `json:"secret_name"`
	UsernameKey       string `json:"username_key"`
	PasswordKey       string `json:"password_key"`
	Namespace         string `json:"namespace"`
	CreatedAt         string `json:"created_at"`
}

type K8sServiceHealthSnapshot struct {
	ID                string `json:"id"`
	ServiceInstanceID string `json:"service_instance_id"`
	ClusterID         string `json:"cluster_id"`
	Score             int    `json:"score"`
	Status            string `json:"status"`
	ReasonJSON        string `json:"reason_json"`
	ObservedAt        string `json:"observed_at"`
	CreatedAt         string `json:"created_at"`
}

type K8sServiceBackup struct {
	ID                string `json:"id"`
	ServiceInstanceID string `json:"service_instance_id"`
	BackupType        string `json:"backup_type"`
	Location          string `json:"location"`
	Status            string `json:"status"`
	RequestID         string `json:"request_id"`
	IntegrityStatus   string `json:"integrity_status"`
	StartedAt         string `json:"started_at"`
	CompletedAt       string `json:"completed_at"`
	CreatedAt         string `json:"created_at"`
}

type K8sServiceRestore struct {
	ID               string `json:"id"`
	BackupID         string `json:"backup_id"`
	TargetInstanceID string `json:"target_instance_id"`
	Status           string `json:"status"`
	RequestID        string `json:"request_id"`
	StartedAt        string `json:"started_at"`
	CompletedAt      string `json:"completed_at"`
	CreatedAt        string `json:"created_at"`
}

func (s *SQLStore) UpsertK8sServiceCatalog(ctx context.Context, v K8sServiceCatalog) error {
	now := nowString()
	if v.CreatedAt == "" {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_catalogs
		(id,code,name,category,description,icon,docs_url,deployment_type,required_capabilities_json,enabled,created_by,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET code=excluded.code,name=excluded.name,category=excluded.category,
		description=excluded.description,icon=excluded.icon,docs_url=excluded.docs_url,deployment_type=excluded.deployment_type,
		required_capabilities_json=excluded.required_capabilities_json,enabled=excluded.enabled,updated_at=excluded.updated_at`),
		v.ID, v.Code, v.Name, v.Category, v.Description, v.Icon, v.DocsURL, v.DeploymentType, v.RequiredCapabilitiesJSON, boolInt(v.Enabled), v.CreatedBy, v.CreatedAt, v.UpdatedAt)
	return err
}

func scanServiceCatalog(row interface{ Scan(...any) error }) (K8sServiceCatalog, error) {
	var v K8sServiceCatalog
	var enabled int
	err := row.Scan(&v.ID, &v.Code, &v.Name, &v.Category, &v.Description, &v.Icon, &v.DocsURL, &v.DeploymentType, &v.RequiredCapabilitiesJSON, &enabled, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	v.Enabled = enabled != 0
	return v, err
}

const serviceCatalogSelect = `SELECT id,code,name,category,description,icon,docs_url,deployment_type,required_capabilities_json,enabled,created_by,created_at,updated_at FROM k8s_service_catalogs`

func (s *SQLStore) ListK8sServiceCatalogs(ctx context.Context, includeDisabled bool) ([]K8sServiceCatalog, error) {
	q := serviceCatalogSelect
	if !includeDisabled {
		q += ` WHERE enabled = 1`
	}
	q += ` ORDER BY category,name`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceCatalog{}
	for rows.Next() {
		v, e := scanServiceCatalog(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sServiceCatalog(ctx context.Context, id string) (K8sServiceCatalog, error) {
	v, err := scanServiceCatalog(s.db.QueryRowContext(ctx, s.bind(serviceCatalogSelect+` WHERE id = ? OR code = ?`), id, id))
	if err == sql.ErrNoRows {
		return v, ErrNotFound
	}
	return v, err
}

func (s *SQLStore) UpsertK8sServiceVersion(ctx context.Context, v K8sServiceVersion) error {
	now := nowString()
	if v.CreatedAt == "" {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_versions (id,catalog_id,version,chart_ref,deployment_type,template,values_schema_json,default_values_json,status,recommended,created_at,updated_at)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,chart_ref=excluded.chart_ref,deployment_type=excluded.deployment_type,
	template=excluded.template,values_schema_json=excluded.values_schema_json,default_values_json=excluded.default_values_json,status=excluded.status,recommended=excluded.recommended,updated_at=excluded.updated_at`),
		v.ID, v.CatalogID, v.Version, v.ChartRef, v.DeploymentType, v.Template, v.ValuesSchemaJSON, v.DefaultValuesJSON, v.Status, boolInt(v.Recommended), v.CreatedAt, v.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sServiceVersions(ctx context.Context, catalogID string) ([]K8sServiceVersion, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,catalog_id,version,chart_ref,deployment_type,template,values_schema_json,default_values_json,status,recommended,created_at,updated_at FROM k8s_service_versions WHERE catalog_id=? ORDER BY recommended DESC,version DESC`), catalogID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceVersion{}
	for rows.Next() {
		var v K8sServiceVersion
		var rec int
		if err := rows.Scan(&v.ID, &v.CatalogID, &v.Version, &v.ChartRef, &v.DeploymentType, &v.Template, &v.ValuesSchemaJSON, &v.DefaultValuesJSON, &v.Status, &rec, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		v.Recommended = rec != 0
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sServiceVersion(ctx context.Context, id string) (K8sServiceVersion, error) {
	var v K8sServiceVersion
	var rec int
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id,catalog_id,version,chart_ref,deployment_type,template,values_schema_json,default_values_json,status,recommended,created_at,updated_at FROM k8s_service_versions WHERE id=?`), id).Scan(&v.ID, &v.CatalogID, &v.Version, &v.ChartRef, &v.DeploymentType, &v.Template, &v.ValuesSchemaJSON, &v.DefaultValuesJSON, &v.Status, &rec, &v.CreatedAt, &v.UpdatedAt)
	v.Recommended = rec != 0
	if err == sql.ErrNoRows {
		return v, ErrNotFound
	}
	return v, err
}

func (s *SQLStore) UpsertK8sServiceProfile(ctx context.Context, v K8sServiceProfile) error {
	if v.CreatedAt == "" {
		v.CreatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_profiles(id,catalog_id,name,cpu,memory,gpu,storage,values_json,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,cpu=excluded.cpu,memory=excluded.memory,gpu=excluded.gpu,storage=excluded.storage,values_json=excluded.values_json`), v.ID, v.CatalogID, v.Name, v.CPU, v.Memory, v.GPU, v.Storage, v.ValuesJSON, v.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sServiceProfiles(ctx context.Context, catalogID string) ([]K8sServiceProfile, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,catalog_id,name,cpu,memory,gpu,storage,values_json,created_at FROM k8s_service_profiles WHERE catalog_id=? ORDER BY CASE name WHEN 'small' THEN 1 WHEN 'medium' THEN 2 WHEN 'large' THEN 3 ELSE 4 END, name`), catalogID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceProfile{}
	for rows.Next() {
		var v K8sServiceProfile
		if err := rows.Scan(&v.ID, &v.CatalogID, &v.Name, &v.CPU, &v.Memory, &v.GPU, &v.Storage, &v.ValuesJSON, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sServiceProfile(ctx context.Context, id string) (K8sServiceProfile, error) {
	var v K8sServiceProfile
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id,catalog_id,name,cpu,memory,gpu,storage,values_json,created_at FROM k8s_service_profiles WHERE id=?`), id).Scan(&v.ID, &v.CatalogID, &v.Name, &v.CPU, &v.Memory, &v.GPU, &v.Storage, &v.ValuesJSON, &v.CreatedAt)
	if err == sql.ErrNoRows {
		return v, ErrNotFound
	}
	return v, err
}

func (s *SQLStore) UpsertK8sServiceInstance(ctx context.Context, v K8sServiceInstance) error {
	now := nowString()
	if v.CreatedAt == "" {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_instances(id,cluster_id,namespace,catalog_id,version_id,profile_id,stack_id,name,environment,status,owner_id,owner_team_id,workspace_id,criticality,values_json,policy_result_json,expires_at,cost_center,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET cluster_id=excluded.cluster_id,namespace=excluded.namespace,version_id=excluded.version_id,profile_id=excluded.profile_id,stack_id=excluded.stack_id,name=excluded.name,environment=excluded.environment,status=excluded.status,owner_id=excluded.owner_id,owner_team_id=excluded.owner_team_id,workspace_id=excluded.workspace_id,criticality=excluded.criticality,values_json=excluded.values_json,policy_result_json=excluded.policy_result_json,expires_at=excluded.expires_at,cost_center=excluded.cost_center,updated_at=excluded.updated_at`), v.ID, v.ClusterID, v.Namespace, v.CatalogID, v.VersionID, v.ProfileID, v.StackID, v.Name, v.Environment, v.Status, v.OwnerID, v.OwnerTeamID, v.WorkspaceID, v.Criticality, v.ValuesJSON, v.PolicyResultJSON, v.ExpiresAt, v.CostCenter, v.CreatedBy, v.CreatedAt, v.UpdatedAt)
	return err
}

const serviceInstanceSelect = `SELECT id,cluster_id,namespace,catalog_id,version_id,profile_id,stack_id,name,environment,status,owner_id,owner_team_id,workspace_id,criticality,values_json,policy_result_json,expires_at,cost_center,created_by,created_at,updated_at FROM k8s_service_instances`

func scanServiceInstance(row interface{ Scan(...any) error }) (K8sServiceInstance, error) {
	var v K8sServiceInstance
	err := row.Scan(&v.ID, &v.ClusterID, &v.Namespace, &v.CatalogID, &v.VersionID, &v.ProfileID, &v.StackID, &v.Name, &v.Environment, &v.Status, &v.OwnerID, &v.OwnerTeamID, &v.WorkspaceID, &v.Criticality, &v.ValuesJSON, &v.PolicyResultJSON, &v.ExpiresAt, &v.CostCenter, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func (s *SQLStore) GetK8sServiceInstance(ctx context.Context, id string) (K8sServiceInstance, error) {
	v, err := scanServiceInstance(s.db.QueryRowContext(ctx, s.bind(serviceInstanceSelect+` WHERE id=?`), id))
	if err == sql.ErrNoRows {
		return v, ErrNotFound
	}
	return v, err
}
func (s *SQLStore) ListK8sServiceInstances(ctx context.Context, clusterID, ownerID, status string, limit int) ([]K8sServiceInstance, error) {
	q := serviceInstanceSelect + ` WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		q += ` AND cluster_id=?`
		args = append(args, clusterID)
	}
	if ownerID != "" {
		q += ` AND owner_id=?`
		args = append(args, ownerID)
	}
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	}
	q += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceInstance{}
	for rows.Next() {
		v, e := scanServiceInstance(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) InsertK8sServiceOperation(ctx context.Context, v K8sServiceOperation) error {
	now := nowString()
	if v.CreatedAt == "" {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_operations(id,service_instance_id,operation_type,status,request_id,idempotency_key,parameters_json,requested_by,result,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`), v.ID, v.ServiceInstanceID, v.OperationType, v.Status, v.RequestID, v.IdempotencyKey, v.ParametersJSON, v.RequestedBy, v.Result, v.CreatedAt, v.UpdatedAt)
	return err
}
func (s *SQLStore) ListK8sServiceOperations(ctx context.Context, id string, limit int) ([]K8sServiceOperation, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,service_instance_id,operation_type,status,request_id,idempotency_key,parameters_json,requested_by,result,created_at,updated_at FROM k8s_service_operations WHERE service_instance_id=? ORDER BY created_at DESC LIMIT ?`), id, boundedLimit(limit, 50, 500))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceOperation{}
	for rows.Next() {
		var v K8sServiceOperation
		if err := rows.Scan(&v.ID, &v.ServiceInstanceID, &v.OperationType, &v.Status, &v.RequestID, &v.IdempotencyKey, &v.ParametersJSON, &v.RequestedBy, &v.Result, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ReplaceK8sServiceComponents(ctx context.Context, instanceID string, rows []K8sServiceComponent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM k8s_service_components WHERE service_instance_id=?`), instanceID); err != nil {
		return err
	}
	for _, v := range rows {
		now := nowString()
		if v.CreatedAt == "" {
			v.CreatedAt = now
		}
		v.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_components(id,service_instance_id,cluster_id,kind,namespace,resource_name,uid,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`), v.ID, v.ServiceInstanceID, v.ClusterID, v.Kind, v.Namespace, v.ResourceName, v.UID, v.Status, v.CreatedAt, v.UpdatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ListK8sServiceComponents(ctx context.Context, instanceID string) ([]K8sServiceComponent, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,service_instance_id,cluster_id,kind,namespace,resource_name,uid,status,created_at,updated_at FROM k8s_service_components WHERE service_instance_id=? ORDER BY kind,resource_name`), instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceComponent{}
	for rows.Next() {
		var v K8sServiceComponent
		if err := rows.Scan(&v.ID, &v.ServiceInstanceID, &v.ClusterID, &v.Kind, &v.Namespace, &v.ResourceName, &v.UID, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ReplaceK8sServiceEndpoints(ctx context.Context, instanceID string, rows []K8sServiceEndpoint) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM k8s_service_endpoints WHERE service_instance_id=?`), instanceID); err != nil {
		return err
	}
	for _, v := range rows {
		if v.CreatedAt == "" {
			v.CreatedAt = nowString()
		}
		if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_endpoints(id,service_instance_id,endpoint_type,host,port,tls_enabled,path,created_at) VALUES(?,?,?,?,?,?,?,?)`), v.ID, v.ServiceInstanceID, v.EndpointType, v.Host, v.Port, boolInt(v.TLSEnabled), v.Path, v.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *SQLStore) ListK8sServiceEndpoints(ctx context.Context, instanceID string) ([]K8sServiceEndpoint, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,service_instance_id,endpoint_type,host,port,tls_enabled,path,created_at FROM k8s_service_endpoints WHERE service_instance_id=? ORDER BY endpoint_type,host,port`), instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceEndpoint{}
	for rows.Next() {
		var v K8sServiceEndpoint
		var tls int
		if err := rows.Scan(&v.ID, &v.ServiceInstanceID, &v.EndpointType, &v.Host, &v.Port, &tls, &v.Path, &v.CreatedAt); err != nil {
			return nil, err
		}
		v.TLSEnabled = tls != 0
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertK8sServiceCredential(ctx context.Context, v K8sServiceCredential) error {
	if v.CreatedAt == "" {
		v.CreatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_credentials(id,service_instance_id,secret_name,username_key,password_key,namespace,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET secret_name=excluded.secret_name,username_key=excluded.username_key,password_key=excluded.password_key,namespace=excluded.namespace`), v.ID, v.ServiceInstanceID, v.SecretName, v.UsernameKey, v.PasswordKey, v.Namespace, v.CreatedAt)
	return err
}
func (s *SQLStore) ListK8sServiceCredentials(ctx context.Context, instanceID string) ([]K8sServiceCredential, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,service_instance_id,secret_name,username_key,password_key,namespace,created_at FROM k8s_service_credentials WHERE service_instance_id=? ORDER BY created_at`), instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceCredential{}
	for rows.Next() {
		var v K8sServiceCredential
		if err := rows.Scan(&v.ID, &v.ServiceInstanceID, &v.SecretName, &v.UsernameKey, &v.PasswordKey, &v.Namespace, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) InsertK8sServiceHealthSnapshot(ctx context.Context, v K8sServiceHealthSnapshot) error {
	now := nowString()
	if v.ObservedAt == "" {
		v.ObservedAt = now
	}
	if v.CreatedAt == "" {
		v.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_health_snapshots(id,service_instance_id,cluster_id,score,status,reason_json,observed_at,created_at) VALUES(?,?,?,?,?,?,?,?)`), v.ID, v.ServiceInstanceID, v.ClusterID, v.Score, v.Status, v.ReasonJSON, v.ObservedAt, v.CreatedAt)
	return err
}
func (s *SQLStore) LatestK8sServiceHealthSnapshot(ctx context.Context, instanceID string) (K8sServiceHealthSnapshot, error) {
	var v K8sServiceHealthSnapshot
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id,service_instance_id,cluster_id,score,status,reason_json,observed_at,created_at FROM k8s_service_health_snapshots WHERE service_instance_id=? ORDER BY observed_at DESC LIMIT 1`), instanceID).Scan(&v.ID, &v.ServiceInstanceID, &v.ClusterID, &v.Score, &v.Status, &v.ReasonJSON, &v.ObservedAt, &v.CreatedAt)
	if err == sql.ErrNoRows {
		return v, ErrNotFound
	}
	return v, err
}

func (s *SQLStore) LatestK8sServiceBackupStatus(ctx context.Context, instanceID string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT status FROM k8s_service_backups WHERE service_instance_id=? ORDER BY started_at DESC LIMIT 1`), instanceID).Scan(&status)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return status, err
}

func (s *SQLStore) InsertK8sServiceBackup(ctx context.Context, backup K8sServiceBackup) error {
	now := nowString()
	if backup.StartedAt == "" {
		backup.StartedAt = now
	}
	if backup.CreatedAt == "" {
		backup.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_backups(id,service_instance_id,backup_type,location,status,request_id,integrity_status,started_at,completed_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,request_id=excluded.request_id,integrity_status=excluded.integrity_status,completed_at=excluded.completed_at`), backup.ID, backup.ServiceInstanceID, backup.BackupType, backup.Location, backup.Status, backup.RequestID, backup.IntegrityStatus, backup.StartedAt, backup.CompletedAt, backup.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sServiceBackups(ctx context.Context, instanceID string, limit int) ([]K8sServiceBackup, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,service_instance_id,backup_type,location,status,request_id,integrity_status,started_at,completed_at,created_at
		FROM k8s_service_backups WHERE service_instance_id=? ORDER BY started_at DESC LIMIT ?`), instanceID, boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceBackup{}
	for rows.Next() {
		var backup K8sServiceBackup
		if err := rows.Scan(&backup.ID, &backup.ServiceInstanceID, &backup.BackupType, &backup.Location, &backup.Status, &backup.RequestID, &backup.IntegrityStatus, &backup.StartedAt, &backup.CompletedAt, &backup.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, backup)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sServiceBackup(ctx context.Context, id string) (K8sServiceBackup, error) {
	var backup K8sServiceBackup
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id,service_instance_id,backup_type,location,status,request_id,integrity_status,started_at,completed_at,created_at
		FROM k8s_service_backups WHERE id=?`), id).Scan(&backup.ID, &backup.ServiceInstanceID, &backup.BackupType, &backup.Location, &backup.Status, &backup.RequestID, &backup.IntegrityStatus, &backup.StartedAt, &backup.CompletedAt, &backup.CreatedAt)
	if err == sql.ErrNoRows {
		return backup, ErrNotFound
	}
	return backup, err
}

func (s *SQLStore) UpsertK8sServiceRestore(ctx context.Context, restore K8sServiceRestore) error {
	now := nowString()
	if restore.StartedAt == "" {
		restore.StartedAt = now
	}
	if restore.CreatedAt == "" {
		restore.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_restores(id,backup_id,target_instance_id,status,request_id,started_at,completed_at,created_at)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,request_id=excluded.request_id,completed_at=excluded.completed_at`),
		restore.ID, restore.BackupID, restore.TargetInstanceID, restore.Status, restore.RequestID, restore.StartedAt, restore.CompletedAt, restore.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sServiceRestores(ctx context.Context, targetInstanceID string, limit int) ([]K8sServiceRestore, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,backup_id,target_instance_id,status,request_id,started_at,completed_at,created_at
		FROM k8s_service_restores WHERE target_instance_id=? ORDER BY started_at DESC LIMIT ?`), targetInstanceID, boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceRestore{}
	for rows.Next() {
		var restore K8sServiceRestore
		if err := rows.Scan(&restore.ID, &restore.BackupID, &restore.TargetInstanceID, &restore.Status, &restore.RequestID, &restore.StartedAt, &restore.CompletedAt, &restore.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, restore)
	}
	return out, rows.Err()
}

func (s *SQLStore) FindK8sServiceRestoreByRequestID(ctx context.Context, requestID string) (K8sServiceRestore, error) {
	var restore K8sServiceRestore
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id,backup_id,target_instance_id,status,request_id,started_at,completed_at,created_at
		FROM k8s_service_restores WHERE request_id=? ORDER BY created_at DESC LIMIT 1`), requestID).Scan(&restore.ID, &restore.BackupID, &restore.TargetInstanceID, &restore.Status, &restore.RequestID, &restore.StartedAt, &restore.CompletedAt, &restore.CreatedAt)
	if err == sql.ErrNoRows {
		return restore, ErrNotFound
	}
	return restore, err
}

// ListK8sServiceInstancesDue returns active instances whose last persisted health evidence is
// older than before. It intentionally has no owner filter because it is used by the platform
// reconciler; the bounded batch keeps each scheduler tick predictable with 10k+ instances.
func (s *SQLStore) ListK8sServiceInstancesDue(ctx context.Context, before string, limit int) ([]K8sServiceInstance, error) {
	query := serviceInstanceSelect + ` AS i
		LEFT JOIN (SELECT service_instance_id, MAX(observed_at) AS last_observed_at FROM k8s_service_health_snapshots GROUP BY service_instance_id) h
		ON h.service_instance_id=i.id
		WHERE i.status NOT IN ('deleted','deleting') AND (h.last_observed_at IS NULL OR h.last_observed_at < ?)
		ORDER BY COALESCE(h.last_observed_at,''), i.updated_at LIMIT ?`
	rows, err := s.db.QueryContext(ctx, s.bind(query), before, boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sServiceInstance{}
	for rows.Next() {
		v, scanErr := scanServiceInstance(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// TryAcquireK8sServiceReconcileLease is a database-backed per-instance lease. The conditional
// upsert works on SQLite and PostgreSQL and prevents two Clustara pods from reconciling the same
// ServiceInstance concurrently.
func (s *SQLStore) TryAcquireK8sServiceReconcileLease(ctx context.Context, instanceID, ownerID string, now time.Time, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	nowText := now.UTC().Format(time.RFC3339Nano)
	expires := now.UTC().Add(ttl).Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_service_reconcile_leases(service_instance_id,owner_id,acquired_at,expires_at)
		VALUES(?,?,?,?) ON CONFLICT(service_instance_id) DO UPDATE SET owner_id=excluded.owner_id,acquired_at=excluded.acquired_at,expires_at=excluded.expires_at
		WHERE k8s_service_reconcile_leases.expires_at < ? OR k8s_service_reconcile_leases.owner_id = ?`),
		instanceID, ownerID, nowText, expires, nowText, ownerID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1, err
}

func (s *SQLStore) ReleaseK8sServiceReconcileLease(ctx context.Context, instanceID, ownerID string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_service_reconcile_leases WHERE service_instance_id=? AND owner_id=?`), instanceID, ownerID)
	return err
}

func (s *SQLStore) PruneK8sServiceHealthSnapshots(ctx context.Context, before string) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_service_health_snapshots WHERE observed_at < ?`), before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
