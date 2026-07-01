package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// K8sManifestChangeRequest is the auditable ledger for editing one live Kubernetes
// resource manifest through Clustara: request, validation, approval, SSA apply, and verification.
// Secret bodies are stored only after caller-side masking; the store keeps the immutable evidence
// needed for review and rollback without holding sensitive cleartext.
type K8sManifestChangeRequest struct {
	ID                    string                 `json:"id"`
	ClusterID             string                 `json:"cluster_id"`
	Namespace             string                 `json:"namespace"`
	Kind                  string                 `json:"kind"`
	APIVersion            string                 `json:"api_version"`
	Name                  string                 `json:"name"`
	Status                string                 `json:"status"`
	RiskLevel             string                 `json:"risk_level"`
	RequiresApproval      bool                   `json:"requires_approval"`
	Reason                string                 `json:"reason"`
	BeforeYAML            string                 `json:"before_yaml"`
	AfterYAML             string                 `json:"after_yaml"`
	BeforeHash            string                 `json:"before_hash"`
	AfterHash             string                 `json:"after_hash"`
	Diffs                 []K8sManifestFieldDiff `json:"diffs"`
	Impact                map[string]any         `json:"impact"`
	Validation            map[string]any         `json:"validation"`
	ApplyResult           map[string]any         `json:"apply_result"`
	VerifyResult          map[string]any         `json:"verify_result"`
	CreatedBy             string                 `json:"created_by"`
	ApprovedBy            string                 `json:"approved_by"`
	AppliedBy             string                 `json:"applied_by"`
	VerifiedBy            string                 `json:"verified_by"`
	Result                string                 `json:"result"`
	IdempotencyKey        string                 `json:"idempotency_key"`
	TargetUID             string                 `json:"target_uid"`
	TargetResourceVersion string                 `json:"target_resource_version"`
	CreatedAt             string                 `json:"created_at"`
	UpdatedAt             string                 `json:"updated_at"`
	ApprovedAt            string                 `json:"approved_at"`
	AppliedAt             string                 `json:"applied_at"`
	VerifiedAt            string                 `json:"verified_at"`
}

type K8sManifestFieldDiff struct {
	Path     string `json:"path"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
	Type     string `json:"type"` // added | removed | changed
	Risk     string `json:"risk"`
}

type K8sManifestChangeFilter struct {
	ClusterID string
	Status    string
	Kind      string
	Namespace string
	Limit     int
}

func (s *SQLStore) CreateK8sManifestChangeRequest(ctx context.Context, req K8sManifestChangeRequest) error {
	now := nowString()
	if req.CreatedAt == "" {
		req.CreatedAt = now
	}
	if req.UpdatedAt == "" {
		req.UpdatedAt = now
	}
	if req.Status == "" {
		req.Status = "draft"
	}
	if req.RiskLevel == "" {
		req.RiskLevel = "low"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_manifest_change_requests
		(id, cluster_id, namespace, kind, api_version, name, status, risk_level, requires_approval, reason,
		before_yaml, after_yaml, before_hash, after_hash, diffs_json, impact_json, validation_json, apply_result_json,
		verify_result_json, created_by, approved_by, applied_by, verified_by, result, idempotency_key, target_uid,
		target_resource_version, created_at, updated_at, approved_at, applied_at, verified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		req.ID, req.ClusterID, req.Namespace, req.Kind, req.APIVersion, req.Name, req.Status, req.RiskLevel,
		boolInt(req.RequiresApproval), req.Reason, req.BeforeYAML, req.AfterYAML, req.BeforeHash, req.AfterHash,
		encodeManifestDiffs(req.Diffs), encodeAnyMap(req.Impact), encodeAnyMap(req.Validation), encodeAnyMap(req.ApplyResult),
		encodeAnyMap(req.VerifyResult), req.CreatedBy, req.ApprovedBy, req.AppliedBy, req.VerifiedBy, req.Result,
		req.IdempotencyKey, req.TargetUID, req.TargetResourceVersion, req.CreatedAt, req.UpdatedAt, req.ApprovedAt,
		req.AppliedAt, req.VerifiedAt)
	return err
}

func (s *SQLStore) ListK8sManifestChangeRequests(ctx context.Context, f K8sManifestChangeFilter) ([]K8sManifestChangeRequest, error) {
	query := `SELECT id, cluster_id, namespace, kind, api_version, name, status, risk_level, requires_approval, reason,
		before_yaml, after_yaml, before_hash, after_hash, COALESCE(diffs_json, '[]'), COALESCE(impact_json, '{}'),
		COALESCE(validation_json, '{}'), COALESCE(apply_result_json, '{}'), COALESCE(verify_result_json, '{}'),
		created_by, approved_by, applied_by, verified_by, result, COALESCE(idempotency_key, ''), COALESCE(target_uid, ''),
		COALESCE(target_resource_version, ''), created_at, updated_at, approved_at, applied_at, verified_at
		FROM k8s_manifest_change_requests WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	if f.Kind != "" {
		query += ` AND lower(kind) = lower(?)`
		args = append(args, f.Kind)
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
	out := []K8sManifestChangeRequest{}
	for rows.Next() {
		req, err := scanK8sManifestChangeRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sManifestChangeRequest(ctx context.Context, id string) (K8sManifestChangeRequest, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, kind, api_version, name, status,
		risk_level, requires_approval, reason, before_yaml, after_yaml, before_hash, after_hash, COALESCE(diffs_json, '[]'),
		COALESCE(impact_json, '{}'), COALESCE(validation_json, '{}'), COALESCE(apply_result_json, '{}'),
		COALESCE(verify_result_json, '{}'), created_by, approved_by, applied_by, verified_by, result,
		COALESCE(idempotency_key, ''), COALESCE(target_uid, ''), COALESCE(target_resource_version, ''), created_at,
		updated_at, approved_at, applied_at, verified_at FROM k8s_manifest_change_requests WHERE id = ?`), id)
	req, err := scanK8sManifestChangeRequest(row)
	if err == sql.ErrNoRows {
		return K8sManifestChangeRequest{}, ErrNotFound
	}
	return req, err
}

func (s *SQLStore) GetK8sManifestChangeRequestByIdempotencyKey(ctx context.Context, key string) (K8sManifestChangeRequest, error) {
	if strings.TrimSpace(key) == "" {
		return K8sManifestChangeRequest{}, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, kind, api_version, name, status,
		risk_level, requires_approval, reason, before_yaml, after_yaml, before_hash, after_hash, COALESCE(diffs_json, '[]'),
		COALESCE(impact_json, '{}'), COALESCE(validation_json, '{}'), COALESCE(apply_result_json, '{}'),
		COALESCE(verify_result_json, '{}'), created_by, approved_by, applied_by, verified_by, result,
		COALESCE(idempotency_key, ''), COALESCE(target_uid, ''), COALESCE(target_resource_version, ''), created_at,
		updated_at, approved_at, applied_at, verified_at FROM k8s_manifest_change_requests WHERE idempotency_key = ?`), key)
	req, err := scanK8sManifestChangeRequest(row)
	if err == sql.ErrNoRows {
		return K8sManifestChangeRequest{}, ErrNotFound
	}
	return req, err
}

func (s *SQLStore) UpdateK8sManifestChangeAnalysis(ctx context.Context, id, status, riskLevel string, requiresApproval bool, impact, validation map[string]any, result string) error {
	now := nowString()
	allowedWhere := ""
	switch status {
	case "validated":
		allowedWhere = ` AND status IN ('draft', 'validated')`
	case "approval_required":
		allowedWhere = ` AND status IN ('draft', 'validated', 'approval_required')`
	case "failed":
		allowedWhere = ` AND status IN ('draft', 'validated', 'approval_required')`
	default:
		return ErrInvalidTransition
	}
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_manifest_change_requests SET status = ?, risk_level = ?,
		requires_approval = ?, impact_json = ?, validation_json = ?, result = ?, updated_at = ? WHERE id = ?`+allowedWhere),
		status, firstStoreNonEmpty(riskLevel, "low"), boolInt(requiresApproval), encodeAnyMap(impact), encodeAnyMap(validation),
		result, now, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		if _, getErr := s.GetK8sManifestChangeRequest(ctx, id); getErr == nil {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) UpdateK8sManifestChangeStatus(ctx context.Context, id, status, actor, result string) error {
	now := nowString()
	query := `UPDATE k8s_manifest_change_requests SET status = ?, updated_at = ?, result = ?`
	args := []any{status, now, result}
	allowedWhere := ""
	switch status {
	case "approved":
		query += `, approved_by = ?, approved_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status IN ('validated', 'approval_required')`
	case "rejected":
		allowedWhere = ` AND status IN ('draft', 'validated', 'approval_required')`
	case "running":
		query += `, applied_by = ?, applied_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status IN ('validated', 'approved')`
	case "applied", "failed":
		query += `, applied_by = ?, applied_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status = 'running'`
	case "verified", "verify_failed":
		query += `, verified_by = ?, verified_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status IN ('applied', 'verify_failed')`
	case "rollback_requested":
		allowedWhere = ` AND status IN ('applied', 'verified', 'verify_failed')`
	case "rolled_back":
		query += `, applied_by = ?, applied_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status = 'rollback_requested'`
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
		if _, getErr := s.GetK8sManifestChangeRequest(ctx, id); getErr == nil {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) UpdateK8sManifestChangeApplyResult(ctx context.Context, id, status, actor string, applyResult map[string]any, result string) error {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_manifest_change_requests SET status = ?, apply_result_json = ?,
		result = ?, applied_by = ?, applied_at = ?, updated_at = ? WHERE id = ? AND status = 'running'`),
		status, encodeAnyMap(applyResult), result, actor, now, now, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		if _, getErr := s.GetK8sManifestChangeRequest(ctx, id); getErr == nil {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) UpdateK8sManifestChangeVerifyResult(ctx context.Context, id, status, actor string, verifyResult map[string]any, result string) error {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_manifest_change_requests SET status = ?, verify_result_json = ?,
		result = ?, verified_by = ?, verified_at = ?, updated_at = ? WHERE id = ? AND status IN ('applied', 'verify_failed')`),
		status, encodeAnyMap(verifyResult), result, actor, now, now, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		if _, getErr := s.GetK8sManifestChangeRequest(ctx, id); getErr == nil {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return nil
}

func scanK8sManifestChangeRequest(sc k8sClusterScanner) (K8sManifestChangeRequest, error) {
	var req K8sManifestChangeRequest
	var requiresApproval int
	var diffs, impact, validation, applyResult, verifyResult string
	if err := sc.Scan(&req.ID, &req.ClusterID, &req.Namespace, &req.Kind, &req.APIVersion, &req.Name,
		&req.Status, &req.RiskLevel, &requiresApproval, &req.Reason, &req.BeforeYAML, &req.AfterYAML,
		&req.BeforeHash, &req.AfterHash, &diffs, &impact, &validation, &applyResult, &verifyResult,
		&req.CreatedBy, &req.ApprovedBy, &req.AppliedBy, &req.VerifiedBy, &req.Result, &req.IdempotencyKey,
		&req.TargetUID, &req.TargetResourceVersion, &req.CreatedAt, &req.UpdatedAt, &req.ApprovedAt,
		&req.AppliedAt, &req.VerifiedAt); err != nil {
		return K8sManifestChangeRequest{}, err
	}
	req.RequiresApproval = requiresApproval != 0
	req.Diffs = decodeManifestDiffs(diffs)
	req.Impact = decodeAnyMap(impact)
	req.Validation = decodeAnyMap(validation)
	req.ApplyResult = decodeAnyMap(applyResult)
	req.VerifyResult = decodeAnyMap(verifyResult)
	return req, nil
}

func encodeManifestDiffs(values []K8sManifestFieldDiff) string {
	if len(values) == 0 {
		return "[]"
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeManifestDiffs(raw string) []K8sManifestFieldDiff {
	out := []K8sManifestFieldDiff{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func firstStoreNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
