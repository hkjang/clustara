package store

import "context"

// K8sPodWatch is an operator's standing watch on an important workload/namespace — proactive
// monitoring so risk changes on critical services surface without hunting the full pod list.
type K8sPodWatch struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	OwnerKind string `json:"owner_kind"` // optional — empty = whole namespace
	OwnerName string `json:"owner_name"` // optional
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type K8sPodWatchFilter struct {
	UserID    string
	ClusterID string
	Limit     int
}

// UpsertK8sPodWatch creates or refreshes a watch, keyed by (user, cluster, namespace, owner).
func (s *SQLStore) UpsertK8sPodWatch(ctx context.Context, wtch *K8sPodWatch) error {
	now := nowString()
	if wtch.CreatedAt == "" {
		wtch.CreatedAt = now
	}
	wtch.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_watches
		(id, user_id, cluster_id, namespace, owner_kind, owner_name, note, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, cluster_id, namespace, owner_kind, owner_name) DO UPDATE SET
			note = excluded.note,
			updated_at = excluded.updated_at`),
		wtch.ID, wtch.UserID, wtch.ClusterID, wtch.Namespace, wtch.OwnerKind, wtch.OwnerName, wtch.Note, wtch.CreatedAt, wtch.UpdatedAt)
	return err
}

// ListK8sPodWatches returns watches, newest first.
func (s *SQLStore) ListK8sPodWatches(ctx context.Context, f K8sPodWatchFilter) ([]K8sPodWatch, error) {
	query := `SELECT id, user_id, cluster_id, namespace, owner_kind, owner_name, note, created_at, updated_at
		FROM k8s_pod_watches WHERE 1=1`
	args := []any{}
	if f.UserID != "" {
		query += ` AND user_id = ?`
		args = append(args, f.UserID)
	}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodWatch{}
	for rows.Next() {
		var wtch K8sPodWatch
		if err := rows.Scan(&wtch.ID, &wtch.UserID, &wtch.ClusterID, &wtch.Namespace, &wtch.OwnerKind, &wtch.OwnerName, &wtch.Note, &wtch.CreatedAt, &wtch.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, wtch)
	}
	return out, rows.Err()
}

// DeleteK8sPodWatch removes a watch (scoped to the owner when userID is set).
func (s *SQLStore) DeleteK8sPodWatch(ctx context.Context, id, userID string) error {
	query := `DELETE FROM k8s_pod_watches WHERE id = ?`
	args := []any{id}
	if userID != "" {
		query += ` AND user_id = ?`
		args = append(args, userID)
	}
	_, err := s.db.ExecContext(ctx, s.bind(query), args...)
	return err
}
