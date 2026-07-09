package store

import (
	"context"
	"database/sql"
)

type HarborRegistry struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	InsecureTLS   bool   `json:"insecure_tls"`
	CARef         string `json:"ca_ref"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	LastCheckedAt string `json:"last_checked_at"`
	LastError     string `json:"last_error"`
	CreatedBy     string `json:"created_by"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type HarborRobotAccount struct {
	ID             string `json:"id"`
	RegistryID     string `json:"registry_id"`
	ProjectName    string `json:"project_name"`
	Name           string `json:"name"`
	TokenHash      string `json:"token_hash,omitempty"`
	HasTokenHash   bool   `json:"has_token_hash"`
	ExpiresAt      string `json:"expires_at"`
	Status         string `json:"status"`
	LastVerifiedAt string `json:"last_verified_at"`
	LastError      string `json:"last_error"`
	CreatedBy      string `json:"created_by"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type HarborProjectMapping struct {
	ID          string `json:"id"`
	RegistryID  string `json:"registry_id"`
	ProjectName string `json:"project_name"`
	ClusterID   string `json:"cluster_id"`
	Namespace   string `json:"namespace"`
	SecretName  string `json:"secret_name"`
	OwnerTeam   string `json:"owner_team"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type HarborLaunchRequest struct {
	ID              string `json:"id"`
	RegistryID      string `json:"registry_id"`
	ProjectName     string `json:"project_name"`
	Repository      string `json:"repository"`
	Tag             string `json:"tag"`
	Digest          string `json:"digest"`
	Image           string `json:"image"`
	ClusterID       string `json:"cluster_id"`
	Namespace       string `json:"namespace"`
	AppName         string `json:"app_name"`
	Replicas        int    `json:"replicas"`
	Port            int    `json:"port"`
	RobotID         string `json:"robot_id"`
	SecretName      string `json:"secret_name"`
	Decision        string `json:"decision"`
	Reason          string `json:"reason"`
	Status          string `json:"status"`
	RequestedBy     string `json:"requested_by"`
	ManifestPreview string `json:"manifest_preview"`
	PolicyJSON      string `json:"policy_json"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

func (s *SQLStore) UpsertHarborRegistry(ctx context.Context, r HarborRegistry) error {
	now := nowString()
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	if r.UpdatedAt == "" {
		r.UpdatedAt = now
	}
	if r.Status == "" {
		r.Status = "unknown"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO harbor_registries
		(id, name, url, insecure_tls, ca_ref, status, version, last_checked_at, last_error, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, url=excluded.url, insecure_tls=excluded.insecure_tls,
		ca_ref=excluded.ca_ref, status=excluded.status, version=excluded.version, last_checked_at=excluded.last_checked_at,
		last_error=excluded.last_error, updated_at=excluded.updated_at`),
		r.ID, r.Name, r.URL, boolInt(r.InsecureTLS), r.CARef, r.Status, r.Version, r.LastCheckedAt, r.LastError, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return err
}

func (s *SQLStore) UpdateHarborRegistryStatus(ctx context.Context, id, status, version, checkedAt, lastError string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE harbor_registries SET status=?, version=?, last_checked_at=?, last_error=?, updated_at=? WHERE id=?`),
		status, version, checkedAt, lastError, nowString(), id)
	return err
}

func (s *SQLStore) ListHarborRegistries(ctx context.Context, limit int) ([]HarborRegistry, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, name, url, insecure_tls, ca_ref, status, version, last_checked_at, last_error, created_by, created_at, updated_at
		FROM harbor_registries ORDER BY created_at DESC LIMIT ?`), boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HarborRegistry{}
	for rows.Next() {
		r, err := scanHarborRegistry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetHarborRegistry(ctx context.Context, id string) (HarborRegistry, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, name, url, insecure_tls, ca_ref, status, version, last_checked_at, last_error, created_by, created_at, updated_at
		FROM harbor_registries WHERE id=?`), id)
	r, err := scanHarborRegistry(row)
	if err == sql.ErrNoRows {
		return HarborRegistry{}, ErrNotFound
	}
	return r, err
}

func (s *SQLStore) CountHarborRegistryReferences(ctx context.Context, id string) (map[string]int, error) {
	out := map[string]int{"robots": 0, "mappings": 0, "launches": 0}
	for table, query := range map[string]string{
		"robots":   `SELECT COUNT(*) FROM harbor_robot_accounts WHERE registry_id=?`,
		"mappings": `SELECT COUNT(*) FROM harbor_project_mappings WHERE registry_id=?`,
		"launches": `SELECT COUNT(*) FROM harbor_launch_requests WHERE registry_id=?`,
	} {
		var n int
		if err := s.db.QueryRowContext(ctx, s.bind(query), id).Scan(&n); err != nil {
			return out, err
		}
		out[table] = n
	}
	return out, nil
}

func (s *SQLStore) DeleteHarborRegistry(ctx context.Context, id string, force bool) error {
	if force {
		if _, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM harbor_robot_accounts WHERE registry_id=?`), id); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM harbor_project_mappings WHERE registry_id=?`), id); err != nil {
			return err
		}
	}
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM harbor_registries WHERE id=?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) UpsertHarborRobotAccount(ctx context.Context, r HarborRobotAccount) error {
	now := nowString()
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	if r.UpdatedAt == "" {
		r.UpdatedAt = now
	}
	if r.Status == "" {
		r.Status = "registered"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO harbor_robot_accounts
		(id, registry_id, project_name, name, token_hash, expires_at, status, last_verified_at, last_error, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET registry_id=excluded.registry_id, project_name=excluded.project_name, name=excluded.name,
		token_hash=CASE WHEN excluded.token_hash <> '' THEN excluded.token_hash ELSE harbor_robot_accounts.token_hash END,
		expires_at=excluded.expires_at, status=excluded.status, last_verified_at=excluded.last_verified_at,
		last_error=excluded.last_error, updated_at=excluded.updated_at`),
		r.ID, r.RegistryID, r.ProjectName, r.Name, r.TokenHash, r.ExpiresAt, r.Status, r.LastVerifiedAt, r.LastError, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return err
}

func (s *SQLStore) UpdateHarborRobotVerification(ctx context.Context, id, status, verifiedAt, lastError string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE harbor_robot_accounts SET status=?, last_verified_at=?, last_error=?, updated_at=? WHERE id=?`),
		status, verifiedAt, lastError, nowString(), id)
	return err
}

func (s *SQLStore) ListHarborRobotAccounts(ctx context.Context, registryID string, limit int) ([]HarborRobotAccount, error) {
	query := `SELECT id, registry_id, project_name, name, token_hash, expires_at, status, last_verified_at, last_error, created_by, created_at, updated_at
		FROM harbor_robot_accounts WHERE 1=1`
	args := []any{}
	if registryID != "" {
		query += ` AND registry_id=?`
		args = append(args, registryID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HarborRobotAccount{}
	for rows.Next() {
		r, err := scanHarborRobot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetHarborRobotAccount(ctx context.Context, id string) (HarborRobotAccount, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, registry_id, project_name, name, token_hash, expires_at, status, last_verified_at, last_error, created_by, created_at, updated_at
		FROM harbor_robot_accounts WHERE id=?`), id)
	r, err := scanHarborRobot(row)
	if err == sql.ErrNoRows {
		return HarborRobotAccount{}, ErrNotFound
	}
	return r, err
}

func (s *SQLStore) DeleteHarborRobotAccount(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM harbor_robot_accounts WHERE id=?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) UpsertHarborProjectMapping(ctx context.Context, m HarborProjectMapping) error {
	now := nowString()
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO harbor_project_mappings
		(id, registry_id, project_name, cluster_id, namespace, secret_name, owner_team, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET registry_id=excluded.registry_id, project_name=excluded.project_name, cluster_id=excluded.cluster_id,
		namespace=excluded.namespace, secret_name=excluded.secret_name, owner_team=excluded.owner_team, updated_at=excluded.updated_at`),
		m.ID, m.RegistryID, m.ProjectName, m.ClusterID, m.Namespace, m.SecretName, m.OwnerTeam, m.CreatedBy, m.CreatedAt, m.UpdatedAt)
	return err
}

func (s *SQLStore) ListHarborProjectMappings(ctx context.Context, registryID string, limit int) ([]HarborProjectMapping, error) {
	query := `SELECT id, registry_id, project_name, cluster_id, namespace, secret_name, owner_team, created_by, created_at, updated_at
		FROM harbor_project_mappings WHERE 1=1`
	args := []any{}
	if registryID != "" {
		query += ` AND registry_id=?`
		args = append(args, registryID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HarborProjectMapping{}
	for rows.Next() {
		var m HarborProjectMapping
		if err := rows.Scan(&m.ID, &m.RegistryID, &m.ProjectName, &m.ClusterID, &m.Namespace, &m.SecretName, &m.OwnerTeam, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetHarborProjectMapping(ctx context.Context, id string) (HarborProjectMapping, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, registry_id, project_name, cluster_id, namespace, secret_name, owner_team, created_by, created_at, updated_at
		FROM harbor_project_mappings WHERE id=?`), id)
	var m HarborProjectMapping
	err := row.Scan(&m.ID, &m.RegistryID, &m.ProjectName, &m.ClusterID, &m.Namespace, &m.SecretName, &m.OwnerTeam, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return HarborProjectMapping{}, ErrNotFound
	}
	return m, err
}

func (s *SQLStore) DeleteHarborProjectMapping(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM harbor_project_mappings WHERE id=?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) CreateHarborLaunchRequest(ctx context.Context, r HarborLaunchRequest) error {
	now := nowString()
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	if r.UpdatedAt == "" {
		r.UpdatedAt = now
	}
	if r.Status == "" {
		r.Status = "draft"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO harbor_launch_requests
		(id, registry_id, project_name, repository, tag, digest, image, cluster_id, namespace, app_name, replicas, port,
		robot_id, secret_name, decision, reason, status, requested_by, manifest_preview, policy_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		r.ID, r.RegistryID, r.ProjectName, r.Repository, r.Tag, r.Digest, r.Image, r.ClusterID, r.Namespace, r.AppName, r.Replicas, r.Port,
		r.RobotID, r.SecretName, r.Decision, r.Reason, r.Status, r.RequestedBy, r.ManifestPreview, r.PolicyJSON, r.CreatedAt, r.UpdatedAt)
	return err
}

func (s *SQLStore) ListHarborLaunchRequests(ctx context.Context, registryID string, limit int) ([]HarborLaunchRequest, error) {
	query := `SELECT id, registry_id, project_name, repository, tag, digest, image, cluster_id, namespace, app_name, replicas, port,
		robot_id, secret_name, decision, reason, status, requested_by, manifest_preview, policy_json, created_at, updated_at
		FROM harbor_launch_requests WHERE 1=1`
	args := []any{}
	if registryID != "" {
		query += ` AND registry_id=?`
		args = append(args, registryID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HarborLaunchRequest{}
	for rows.Next() {
		var r HarborLaunchRequest
		if err := rows.Scan(&r.ID, &r.RegistryID, &r.ProjectName, &r.Repository, &r.Tag, &r.Digest, &r.Image, &r.ClusterID, &r.Namespace,
			&r.AppName, &r.Replicas, &r.Port, &r.RobotID, &r.SecretName, &r.Decision, &r.Reason, &r.Status, &r.RequestedBy,
			&r.ManifestPreview, &r.PolicyJSON, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetHarborLaunchRequest(ctx context.Context, id string) (HarborLaunchRequest, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, registry_id, project_name, repository, tag, digest, image, cluster_id, namespace, app_name, replicas, port,
		robot_id, secret_name, decision, reason, status, requested_by, manifest_preview, policy_json, created_at, updated_at
		FROM harbor_launch_requests WHERE id=?`), id)
	var r HarborLaunchRequest
	err := row.Scan(&r.ID, &r.RegistryID, &r.ProjectName, &r.Repository, &r.Tag, &r.Digest, &r.Image, &r.ClusterID, &r.Namespace,
		&r.AppName, &r.Replicas, &r.Port, &r.RobotID, &r.SecretName, &r.Decision, &r.Reason, &r.Status, &r.RequestedBy,
		&r.ManifestPreview, &r.PolicyJSON, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return HarborLaunchRequest{}, ErrNotFound
	}
	return r, err
}

func (s *SQLStore) UpdateHarborLaunchStatus(ctx context.Context, id, status, reason string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE harbor_launch_requests SET status=?, reason=?, updated_at=? WHERE id=?`),
		status, reason, nowString(), id)
	return err
}

func scanHarborRegistry(scanner interface {
	Scan(dest ...any) error
}) (HarborRegistry, error) {
	var r HarborRegistry
	var insecure int
	err := scanner.Scan(&r.ID, &r.Name, &r.URL, &insecure, &r.CARef, &r.Status, &r.Version, &r.LastCheckedAt, &r.LastError, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	r.InsecureTLS = insecure != 0
	return r, err
}

func scanHarborRobot(scanner interface {
	Scan(dest ...any) error
}) (HarborRobotAccount, error) {
	var r HarborRobotAccount
	err := scanner.Scan(&r.ID, &r.RegistryID, &r.ProjectName, &r.Name, &r.TokenHash, &r.ExpiresAt, &r.Status, &r.LastVerifiedAt, &r.LastError, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	r.HasTokenHash = r.TokenHash != ""
	r.TokenHash = ""
	return r, err
}
