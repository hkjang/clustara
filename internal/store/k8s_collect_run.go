package store

import "context"

// K8sCollectRun is one recorded inventory-collect attempt (manual, scheduled, or agent-triggered).
// It is the source data for the Collector SLO dashboard and Collect Gap RCA: success/failure, the
// pipeline stage that failed, the classified gap category, latency, and how many resources landed.
type K8sCollectRun struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	Trigger       string `json:"trigger"` // manual | scheduled | agent
	Stage         string `json:"stage"`   // ok | client | probe | collect | snapshot
	OK            bool   `json:"ok"`
	Category      string `json:"category"` // gap category for failures (empty on success)
	ErrorText     string `json:"error_text,omitempty"`
	LatencyMS     int64  `json:"latency_ms"`
	ResourceCount int    `json:"resource_count"`
	StartedAt     string `json:"started_at"`
}

// RecordK8sCollectRun appends one collect attempt outcome.
func (s *SQLStore) RecordK8sCollectRun(ctx context.Context, run K8sCollectRun) error {
	if run.StartedAt == "" {
		run.StartedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_collect_runs
		(id, cluster_id, trigger, stage, ok, category, error_text, latency_ms, resource_count, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		run.ID, run.ClusterID, run.Trigger, run.Stage, boolInt(run.OK), run.Category, run.ErrorText,
		run.LatencyMS, run.ResourceCount, run.StartedAt)
	return err
}

// ListK8sCollectRuns returns recent collect attempts (optionally for one cluster), newest first.
func (s *SQLStore) ListK8sCollectRuns(ctx context.Context, clusterID string, limit int) ([]K8sCollectRun, error) {
	query := `SELECT id, cluster_id, trigger, stage, ok, category, error_text, latency_ms, resource_count, started_at
		FROM k8s_collect_runs WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY started_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 500, 5000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sCollectRun{}
	for rows.Next() {
		var r K8sCollectRun
		var ok int
		if err := rows.Scan(&r.ID, &r.ClusterID, &r.Trigger, &r.Stage, &ok, &r.Category, &r.ErrorText,
			&r.LatencyMS, &r.ResourceCount, &r.StartedAt); err != nil {
			return nil, err
		}
		r.OK = ok != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneK8sCollectRuns deletes collect-run rows older than the given RFC3339 cutoff (retention).
func (s *SQLStore) PruneK8sCollectRuns(ctx context.Context, olderThan string) error {
	if olderThan == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_collect_runs WHERE started_at < ?`), olderThan)
	return err
}
