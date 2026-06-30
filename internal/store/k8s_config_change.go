package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// K8sConfigChangeRequest turns ConfigMap/Secret edits into an auditable lifecycle:
// impact attached at request time, approval when needed, apply recording, and post verification.
// It intentionally stores only summaries and hashes, never raw Secret payloads.
type K8sConfigChangeRequest struct {
	ID                    string `json:"id"`
	ClusterID             string `json:"cluster_id"`
	Namespace             string `json:"namespace"`
	SourceKind            string `json:"source_kind"` // ConfigMap | Secret
	SourceName            string `json:"source_name"`
	ChangeType            string `json:"change_type"`
	ProposedSummary       string `json:"proposed_summary"`
	ProposedHash          string `json:"proposed_hash"`
	Reason                string `json:"reason"`
	RiskLevel             string `json:"risk_level"`
	Status                string `json:"status"` // pending | approval_required | approved | applied | verified | verification_failed | rejected | failed
	RequiresApproval      bool   `json:"requires_approval"`
	ImpactCount           int    `json:"impact_count"`
	RestartNeeded         int    `json:"restart_needed"`
	RequestedBy           string `json:"requested_by"`
	ApprovedBy            string `json:"approved_by"`
	AppliedBy             string `json:"applied_by"`
	VerifiedBy            string `json:"verified_by"`
	Result                string `json:"result"`
	IdempotencyKey        string `json:"idempotency_key"`
	SourceUID             string `json:"source_uid"`
	SourceResourceVersion string `json:"source_resource_version"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
	ApprovedAt            string `json:"approved_at"`
	AppliedAt             string `json:"applied_at"`
	VerifiedAt            string `json:"verified_at"`
}

type K8sConfigChangeImpact struct {
	ID        string   `json:"id"`
	RequestID string   `json:"request_id"`
	ClusterID string   `json:"cluster_id"`
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Via       []string `json:"via"`
	CreatedAt string   `json:"created_at"`
}

type K8sConfigChangeVerification struct {
	ID        string         `json:"id"`
	RequestID string         `json:"request_id"`
	Status    string         `json:"status"` // passed | attention_required | pending_observation
	Summary   map[string]any `json:"summary"`
	CreatedBy string         `json:"created_by"`
	CreatedAt string         `json:"created_at"`
}

type K8sConfigChangeFilter struct {
	ClusterID  string
	Status     string
	SourceKind string
	Namespace  string
	Limit      int
}

func (s *SQLStore) CreateK8sConfigChangeRequest(ctx context.Context, req K8sConfigChangeRequest, impacts []K8sConfigChangeImpact) error {
	now := nowString()
	if req.CreatedAt == "" {
		req.CreatedAt = now
	}
	if req.UpdatedAt == "" {
		req.UpdatedAt = now
	}
	if req.RiskLevel == "" {
		req.RiskLevel = "medium"
	}
	if req.Status == "" {
		req.Status = "pending"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_config_change_requests
		(id, cluster_id, namespace, source_kind, source_name, change_type, proposed_summary, proposed_hash, reason,
		risk_level, status, requires_approval, impact_count, restart_needed, requested_by, approved_by, applied_by,
		verified_by, result, idempotency_key, source_uid, source_resource_version, created_at, updated_at,
		approved_at, applied_at, verified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		req.ID, req.ClusterID, req.Namespace, req.SourceKind, req.SourceName, req.ChangeType, req.ProposedSummary,
		req.ProposedHash, req.Reason, req.RiskLevel, req.Status, boolInt(req.RequiresApproval), req.ImpactCount,
		req.RestartNeeded, req.RequestedBy, req.ApprovedBy, req.AppliedBy, req.VerifiedBy, req.Result,
		req.IdempotencyKey, req.SourceUID, req.SourceResourceVersion, req.CreatedAt, req.UpdatedAt,
		req.ApprovedAt, req.AppliedAt, req.VerifiedAt)
	if err != nil {
		return err
	}
	for _, im := range impacts {
		if im.ID == "" {
			continue
		}
		if im.CreatedAt == "" {
			im.CreatedAt = now
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_config_change_impacts
			(id, request_id, cluster_id, namespace, kind, name, via_json, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			im.ID, im.RequestID, im.ClusterID, im.Namespace, im.Kind, im.Name, encodeStringSlice(im.Via), im.CreatedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ListK8sConfigChangeRequests(ctx context.Context, f K8sConfigChangeFilter) ([]K8sConfigChangeRequest, error) {
	query := `SELECT id, cluster_id, namespace, source_kind, source_name, change_type, proposed_summary,
		proposed_hash, reason, risk_level, status, requires_approval, impact_count, restart_needed,
		requested_by, approved_by, applied_by, verified_by, result, COALESCE(idempotency_key, ''),
		COALESCE(source_uid, ''), COALESCE(source_resource_version, ''), created_at, updated_at,
		approved_at, applied_at, verified_at FROM k8s_config_change_requests WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	if f.SourceKind != "" {
		query += ` AND lower(source_kind) = lower(?)`
		args = append(args, f.SourceKind)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sConfigChangeRequest{}
	for rows.Next() {
		req, err := scanK8sConfigChangeRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sConfigChangeRequest(ctx context.Context, id string) (K8sConfigChangeRequest, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, source_kind, source_name,
		change_type, proposed_summary, proposed_hash, reason, risk_level, status, requires_approval,
		impact_count, restart_needed, requested_by, approved_by, applied_by, verified_by, result,
		COALESCE(idempotency_key, ''), COALESCE(source_uid, ''), COALESCE(source_resource_version, ''),
		created_at, updated_at, approved_at, applied_at, verified_at
		FROM k8s_config_change_requests WHERE id = ?`), id)
	req, err := scanK8sConfigChangeRequest(row)
	if err == sql.ErrNoRows {
		return K8sConfigChangeRequest{}, ErrNotFound
	}
	return req, err
}

func (s *SQLStore) GetK8sConfigChangeRequestByIdempotencyKey(ctx context.Context, key string) (K8sConfigChangeRequest, error) {
	if strings.TrimSpace(key) == "" {
		return K8sConfigChangeRequest{}, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, source_kind, source_name,
		change_type, proposed_summary, proposed_hash, reason, risk_level, status, requires_approval,
		impact_count, restart_needed, requested_by, approved_by, applied_by, verified_by, result,
		COALESCE(idempotency_key, ''), COALESCE(source_uid, ''), COALESCE(source_resource_version, ''),
		created_at, updated_at, approved_at, applied_at, verified_at
		FROM k8s_config_change_requests WHERE idempotency_key = ?`), key)
	req, err := scanK8sConfigChangeRequest(row)
	if err == sql.ErrNoRows {
		return K8sConfigChangeRequest{}, ErrNotFound
	}
	return req, err
}

func (s *SQLStore) ListK8sConfigChangeImpacts(ctx context.Context, requestID string) ([]K8sConfigChangeImpact, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, request_id, cluster_id, namespace, kind, name,
		COALESCE(via_json, '[]'), created_at FROM k8s_config_change_impacts
		WHERE request_id = ? ORDER BY namespace, kind, name`), requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sConfigChangeImpact{}
	for rows.Next() {
		var im K8sConfigChangeImpact
		var via string
		if err := rows.Scan(&im.ID, &im.RequestID, &im.ClusterID, &im.Namespace, &im.Kind, &im.Name, &via, &im.CreatedAt); err != nil {
			return nil, err
		}
		im.Via = decodeStringSlice(via)
		out = append(out, im)
	}
	return out, rows.Err()
}

func (s *SQLStore) InsertK8sConfigChangeVerification(ctx context.Context, v K8sConfigChangeVerification) error {
	if v.CreatedAt == "" {
		v.CreatedAt = nowString()
	}
	summary := "{}"
	if len(v.Summary) > 0 {
		if b, err := json.Marshal(v.Summary); err == nil {
			summary = string(b)
		}
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_config_change_verifications
		(id, request_id, status, summary_json, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`), v.ID, v.RequestID, v.Status, summary, v.CreatedBy, v.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sConfigChangeVerifications(ctx context.Context, requestID string) ([]K8sConfigChangeVerification, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, request_id, status, COALESCE(summary_json, '{}'),
		created_by, created_at FROM k8s_config_change_verifications
		WHERE request_id = ? ORDER BY created_at DESC`), requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sConfigChangeVerification{}
	for rows.Next() {
		var v K8sConfigChangeVerification
		var summary string
		if err := rows.Scan(&v.ID, &v.RequestID, &v.Status, &summary, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		v.Summary = map[string]any{}
		_ = json.Unmarshal([]byte(summary), &v.Summary)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateK8sConfigChangeStatus(ctx context.Context, id, status, actor, result string) error {
	now := nowString()
	query := `UPDATE k8s_config_change_requests SET status = ?, updated_at = ?, result = ?`
	args := []any{status, now, result}
	allowedWhere := ""
	switch status {
	case "approved":
		query += `, approved_by = ?, approved_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status IN ('pending', 'approval_required')`
	case "rejected":
		allowedWhere = ` AND status IN ('pending', 'approval_required')`
	case "applied":
		query += `, applied_by = ?, applied_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status IN ('pending', 'approved')`
	case "verified", "verification_failed":
		query += `, verified_by = ?, verified_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status IN ('applied', 'verification_failed')`
	case "failed":
		allowedWhere = ` AND status IN ('pending', 'approved', 'applied')`
	default:
		return ErrInvalidTransition
	}
	query += ` WHERE id = ?` + allowedWhere
	args = append(args, id)
	res, err := s.db.ExecContext(ctx, s.bind(query), args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		if _, getErr := s.GetK8sConfigChangeRequest(ctx, id); getErr == nil {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return nil
}

func scanK8sConfigChangeRequest(sc k8sClusterScanner) (K8sConfigChangeRequest, error) {
	var req K8sConfigChangeRequest
	var requiresApproval int
	if err := sc.Scan(&req.ID, &req.ClusterID, &req.Namespace, &req.SourceKind, &req.SourceName,
		&req.ChangeType, &req.ProposedSummary, &req.ProposedHash, &req.Reason, &req.RiskLevel,
		&req.Status, &requiresApproval, &req.ImpactCount, &req.RestartNeeded, &req.RequestedBy,
		&req.ApprovedBy, &req.AppliedBy, &req.VerifiedBy, &req.Result, &req.IdempotencyKey,
		&req.SourceUID, &req.SourceResourceVersion, &req.CreatedAt, &req.UpdatedAt, &req.ApprovedAt,
		&req.AppliedAt, &req.VerifiedAt); err != nil {
		return K8sConfigChangeRequest{}, err
	}
	req.RequiresApproval = requiresApproval != 0
	return req, nil
}
