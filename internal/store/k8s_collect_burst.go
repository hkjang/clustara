package store

import "context"

// K8sCollectBurst is a short-lived request to collect a cluster at high frequency right after a
// change (Config Change apply, Stack apply, or K8s Action execute), so post-change verification
// sees fresh inventory quickly. The adaptive scheduler shortens a cluster's collect interval while
// any burst is active (ExpiresAt in the future). Namespace/Reason are informational.
type K8sCollectBurst struct {
	ID        string `json:"id"`
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	Reason    string `json:"reason"`
	Trigger   string `json:"trigger"` // config_change | stack_apply | action | manual
	StartedAt string `json:"started_at"`
	ExpiresAt string `json:"expires_at"`
}

// RegisterK8sCollectBurst records a burst window. StartedAt defaults to now.
func (s *SQLStore) RegisterK8sCollectBurst(ctx context.Context, b K8sCollectBurst) error {
	if b.StartedAt == "" {
		b.StartedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_collect_bursts
		(id, cluster_id, namespace, reason, trigger, started_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		b.ID, b.ClusterID, b.Namespace, b.Reason, b.Trigger, b.StartedAt, b.ExpiresAt)
	return err
}

// ListActiveK8sCollectBursts returns bursts whose window has not expired (expires_at > now),
// optionally filtered to one cluster, newest first. `now` is an RFC3339Nano string.
func (s *SQLStore) ListActiveK8sCollectBursts(ctx context.Context, clusterID, now string) ([]K8sCollectBurst, error) {
	if now == "" {
		now = nowString()
	}
	query := `SELECT id, cluster_id, namespace, reason, trigger, started_at, expires_at
		FROM k8s_collect_bursts WHERE expires_at > ?`
	args := []any{now}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY expires_at DESC`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sCollectBurst{}
	for rows.Next() {
		var b K8sCollectBurst
		if err := rows.Scan(&b.ID, &b.ClusterID, &b.Namespace, &b.Reason, &b.Trigger, &b.StartedAt, &b.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// PruneExpiredK8sCollectBursts deletes bursts that expired before the given RFC3339 cutoff.
func (s *SQLStore) PruneExpiredK8sCollectBursts(ctx context.Context, olderThan string) error {
	if olderThan == "" {
		olderThan = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_collect_bursts WHERE expires_at <= ?`), olderThan)
	return err
}
