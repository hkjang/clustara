package store

import (
	"context"
	"database/sql"
)

// Stack deployment operations (CLU-REQ-08/09/10): apply / promotion / rollback each produce an
// immutable history record so operators can see what was deployed, by whom, against which cluster,
// and with what outcome — the audit backbone for Portainer-style stack deploys.
type K8sStackApplyHistory struct {
	ID            string `json:"id"`
	StackID       string `json:"stack_id"`
	Operation     string `json:"operation"` // apply | promote | rollback
	RevisionNo    int    `json:"revision_no"`
	ClusterID     string `json:"cluster_id"`
	TargetStackID string `json:"target_stack_id"` // promotion target
	DryRun        bool   `json:"dry_run"`
	Status        string `json:"status"` // success | partial | failed | denied | approval_required
	Applied       int    `json:"applied"`
	Failed        int    `json:"failed"`
	Detail        string `json:"detail"` // JSON per-resource results
	Actor         string `json:"actor"`
	CreatedAt     string `json:"created_at"`
}

func (s *SQLStore) InsertK8sStackApplyHistory(ctx context.Context, h K8sStackApplyHistory) error {
	if h.CreatedAt == "" {
		h.CreatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_stack_apply_history
		(id, stack_id, operation, revision_no, cluster_id, target_stack_id, dry_run, status, applied, failed, detail, actor, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		h.ID, h.StackID, h.Operation, h.RevisionNo, h.ClusterID, h.TargetStackID, boolInt(h.DryRun),
		h.Status, h.Applied, h.Failed, h.Detail, h.Actor, h.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sStackApplyHistory(ctx context.Context, stackID string, limit int) ([]K8sStackApplyHistory, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, stack_id, operation, revision_no, cluster_id, target_stack_id,
		dry_run, status, applied, failed, detail, actor, created_at
		FROM k8s_stack_apply_history WHERE stack_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`),
		stackID, boundedLimit(limit, 50, 500))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sStackApplyHistory{}
	for rows.Next() {
		var h K8sStackApplyHistory
		var dry int
		if err := rows.Scan(&h.ID, &h.StackID, &h.Operation, &h.RevisionNo, &h.ClusterID, &h.TargetStackID,
			&dry, &h.Status, &h.Applied, &h.Failed, &h.Detail, &h.Actor, &h.CreatedAt); err != nil {
			return nil, err
		}
		h.DryRun = dry != 0
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetK8sStackStatus updates only a stack's lifecycle status (saved | applied | drifted) without
// touching the manifest or bumping a revision.
func (s *SQLStore) SetK8sStackStatus(ctx context.Context, id, status string) error {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_application_stacks SET status = ?, updated_at = ? WHERE id = ?`),
		status, nowString(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetK8sStackRevision fetches a specific immutable revision of a stack (for rollback).
func (s *SQLStore) GetK8sStackRevision(ctx context.Context, stackID string, revisionNo int) (K8sStackRevision, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, stack_id, revision_no, manifest_hash, manifest, note, created_by, created_at
		FROM k8s_stack_revisions WHERE stack_id = ? AND revision_no = ?`), stackID, revisionNo)
	var rev K8sStackRevision
	if err := row.Scan(&rev.ID, &rev.StackID, &rev.RevisionNo, &rev.ManifestHash, &rev.Manifest, &rev.Note, &rev.CreatedBy, &rev.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return K8sStackRevision{}, ErrNotFound
		}
		return K8sStackRevision{}, err
	}
	return rev, nil
}
