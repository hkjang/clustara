package store

import (
	"context"
	"database/sql"
)

// Security Exception Workflow (CLU-NEXT-12): a tracked, approved, expiring exception for a workload
// that fails the Runtime Security Profile (privileged, hostPath, ...). Turns security analysis into
// governance — every accepted risk has an owner, a reason, an approver, and an expiry.
type K8sSecurityException struct {
	ID          string `json:"id"`
	ClusterID   string `json:"cluster_id"`
	Namespace   string `json:"namespace"`
	Workload    string `json:"workload"`
	Finding     string `json:"finding"` // which risk is excepted (e.g. "privileged")
	Reason      string `json:"reason"`
	Status      string `json:"status"` // pending | approved | rejected | expired
	RequestedBy string `json:"requested_by"`
	ApprovedBy  string `json:"approved_by"`
	ExpiresAt   string `json:"expires_at"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

var secExceptionTransitions = map[string][]string{
	"pending":  {"approved", "rejected"},
	"approved": {"expired", "rejected"},
}

func (s *SQLStore) CreateK8sSecurityException(ctx context.Context, e K8sSecurityException) error {
	now := nowString()
	if e.CreatedAt == "" {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	if e.Status == "" {
		e.Status = "pending"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_security_exceptions
		(id, cluster_id, namespace, workload, finding, reason, status, requested_by, approved_by, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, e.ClusterID, e.Namespace, e.Workload, e.Finding, e.Reason, e.Status, e.RequestedBy, e.ApprovedBy, e.ExpiresAt, e.CreatedAt, e.UpdatedAt)
	return err
}

func (s *SQLStore) UpdateK8sSecurityExceptionStatus(ctx context.Context, id, status, approver string) error {
	cur, found, err := s.getSecException(ctx, id)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	allowed := false
	for _, a := range secExceptionTransitions[cur.Status] {
		if a == status {
			allowed = true
		}
	}
	if !allowed {
		return ErrInvalidTransition
	}
	_, err = s.db.ExecContext(ctx, s.bind(`UPDATE k8s_security_exceptions SET status=?, approved_by=COALESCE(NULLIF(?,''), approved_by), updated_at=? WHERE id=?`),
		status, approver, nowString(), id)
	return err
}

func (s *SQLStore) getSecException(ctx context.Context, id string) (K8sSecurityException, bool, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, workload, finding, reason, status, requested_by, approved_by, expires_at, created_at, updated_at FROM k8s_security_exceptions WHERE id=?`), id)
	var e K8sSecurityException
	if err := row.Scan(&e.ID, &e.ClusterID, &e.Namespace, &e.Workload, &e.Finding, &e.Reason, &e.Status, &e.RequestedBy, &e.ApprovedBy, &e.ExpiresAt, &e.CreatedAt, &e.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return K8sSecurityException{}, false, nil
		}
		return K8sSecurityException{}, false, err
	}
	return e, true, nil
}

// ListK8sSecurityExceptions returns exceptions (optionally for one cluster), newest first.
func (s *SQLStore) ListK8sSecurityExceptions(ctx context.Context, clusterID string, limit int) ([]K8sSecurityException, error) {
	query := `SELECT id, cluster_id, namespace, workload, finding, reason, status, requested_by, approved_by, expires_at, created_at, updated_at
		FROM k8s_security_exceptions WHERE 1=1`
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
	out := []K8sSecurityException{}
	for rows.Next() {
		var e K8sSecurityException
		if err := rows.Scan(&e.ID, &e.ClusterID, &e.Namespace, &e.Workload, &e.Finding, &e.Reason, &e.Status, &e.RequestedBy, &e.ApprovedBy, &e.ExpiresAt, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExpireK8sSecurityExceptions flips approved exceptions past their expiry to "expired" (best-effort).
func (s *SQLStore) ExpireK8sSecurityExceptions(ctx context.Context, now string) (int, error) {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_security_exceptions SET status='expired', updated_at=?
		WHERE status='approved' AND expires_at <> '' AND expires_at < ?`), now, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
