package store

import "context"

type K8sPodLogQuery struct {
	ID           string `json:"id"`
	ClusterID    string `json:"cluster_id"`
	Namespace    string `json:"namespace"`
	Pod          string `json:"pod"`
	Container    string `json:"container"`
	Previous     bool   `json:"previous"`
	Stream       bool   `json:"stream"`
	TailLines    int    `json:"tail_lines"`
	SinceSeconds int    `json:"since_seconds"`
	SinceTime    string `json:"since_time"`
	Query        string `json:"query"`
	RequestedBy  string `json:"requested_by"`
	Masked       bool   `json:"masked"`
	LineCount    int    `json:"line_count"`
	ErrorCount   int    `json:"error_count"`
	WarnCount    int    `json:"warn_count"`
	CreatedAt    string `json:"created_at"`
}

func (s *SQLStore) InsertK8sPodLogQuery(ctx context.Context, q K8sPodLogQuery) error {
	if q.CreatedAt == "" {
		q.CreatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_log_queries
		(id, cluster_id, namespace, pod, container, previous, stream, tail_lines, since_seconds, since_time, query, requested_by, masked, line_count, error_count, warn_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		q.ID, q.ClusterID, q.Namespace, q.Pod, q.Container, boolInt(q.Previous), boolInt(q.Stream), q.TailLines, q.SinceSeconds,
		q.SinceTime, q.Query, q.RequestedBy, boolInt(q.Masked), q.LineCount, q.ErrorCount, q.WarnCount, q.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sPodLogQueries(ctx context.Context, clusterID string, limit int) ([]K8sPodLogQuery, error) {
	query := `SELECT id, cluster_id, namespace, pod, container, previous, stream, tail_lines, since_seconds, since_time, query, requested_by, masked, line_count, error_count, warn_count, created_at
		FROM k8s_pod_log_queries WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodLogQuery{}
	for rows.Next() {
		var q K8sPodLogQuery
		var previous, stream, masked int
		if err := rows.Scan(&q.ID, &q.ClusterID, &q.Namespace, &q.Pod, &q.Container, &previous, &stream, &q.TailLines,
			&q.SinceSeconds, &q.SinceTime, &q.Query, &q.RequestedBy, &masked, &q.LineCount, &q.ErrorCount, &q.WarnCount, &q.CreatedAt); err != nil {
			return nil, err
		}
		q.Previous = previous != 0
		q.Stream = stream != 0
		q.Masked = masked != 0
		out = append(out, q)
	}
	return out, rows.Err()
}
