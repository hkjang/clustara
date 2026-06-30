package store

import (
	"context"
	"database/sql"
)

// Image Promotion (CLU-NEXT-13): a digest-pinned promotion request between environments
// (dev → stage → prod) with an approval lifecycle. Promotes an immutable digest, never a tag.
type K8sImagePromotion struct {
	ID          string `json:"id"`
	ClusterID   string `json:"cluster_id"`
	Repository  string `json:"repository"`
	Digest      string `json:"digest"`
	SourceEnv   string `json:"source_env"`
	TargetEnv   string `json:"target_env"`
	Status      string `json:"status"` // pending | approved | rejected | promoted
	RequestedBy string `json:"requested_by"`
	ApprovedBy  string `json:"approved_by"`
	Reason      string `json:"reason"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

var imagePromotionTransitions = map[string][]string{
	"pending":  {"approved", "rejected"},
	"approved": {"promoted", "rejected"},
}

func (s *SQLStore) CreateK8sImagePromotion(ctx context.Context, p K8sImagePromotion) error {
	now := nowString()
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	if p.Status == "" {
		p.Status = "pending"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_image_promotions
		(id, cluster_id, repository, digest, source_env, target_env, status, requested_by, approved_by, reason, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		p.ID, p.ClusterID, p.Repository, p.Digest, p.SourceEnv, p.TargetEnv, p.Status, p.RequestedBy, p.ApprovedBy, p.Reason, p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *SQLStore) UpdateK8sImagePromotionStatus(ctx context.Context, id, status, approver string) error {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT status FROM k8s_image_promotions WHERE id=?`), id)
	var cur string
	if err := row.Scan(&cur); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	allowed := false
	for _, a := range imagePromotionTransitions[cur] {
		if a == status {
			allowed = true
		}
	}
	if !allowed {
		return ErrInvalidTransition
	}
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_image_promotions SET status=?, approved_by=COALESCE(NULLIF(?,''), approved_by), updated_at=? WHERE id=?`),
		status, approver, nowString(), id)
	return err
}

// ListK8sImagePromotions returns promotions (optionally for one cluster), newest first.
func (s *SQLStore) ListK8sImagePromotions(ctx context.Context, clusterID string, limit int) ([]K8sImagePromotion, error) {
	query := `SELECT id, cluster_id, repository, digest, source_env, target_env, status, requested_by, approved_by, reason, created_at, updated_at
		FROM k8s_image_promotions WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 200, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sImagePromotion{}
	for rows.Next() {
		var p K8sImagePromotion
		if err := rows.Scan(&p.ID, &p.ClusterID, &p.Repository, &p.Digest, &p.SourceEnv, &p.TargetEnv, &p.Status, &p.RequestedBy, &p.ApprovedBy, &p.Reason, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
