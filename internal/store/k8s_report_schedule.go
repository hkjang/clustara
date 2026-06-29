package store

import "context"

// K8sReportSchedule auto-delivers the K8s operations digest to a Mattermost channel on an interval.
type K8sReportSchedule struct {
	ID         string `json:"id"`
	ClusterID  string `json:"cluster_id"`
	Channel    string `json:"channel"` // Mattermost channel override (empty = default)
	Interval   string `json:"interval"` // e.g. "24h"; empty = manual only
	Enabled    bool   `json:"enabled"`
	LastRunAt  string `json:"last_run_at"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// UpsertK8sReportSchedule creates or refreshes a schedule, keyed by (cluster_id, channel).
func (s *SQLStore) UpsertK8sReportSchedule(ctx context.Context, sc *K8sReportSchedule) error {
	now := nowString()
	if sc.CreatedAt == "" {
		sc.CreatedAt = now
	}
	sc.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_report_schedules
		(id, cluster_id, channel, interval, enabled, last_run_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, channel) DO UPDATE SET
			interval = excluded.interval,
			enabled = excluded.enabled,
			updated_at = excluded.updated_at`),
		sc.ID, sc.ClusterID, sc.Channel, sc.Interval, boolInt(sc.Enabled), sc.LastRunAt, sc.CreatedAt, sc.UpdatedAt)
	return err
}

// ListK8sReportSchedules returns all schedules (newest first). When enabledOnly, filters to enabled.
func (s *SQLStore) ListK8sReportSchedules(ctx context.Context, enabledOnly bool) ([]K8sReportSchedule, error) {
	query := `SELECT id, cluster_id, channel, interval, enabled, COALESCE(last_run_at, ''), created_at, updated_at
		FROM k8s_report_schedules`
	if enabledOnly {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, s.bind(query))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sReportSchedule{}
	for rows.Next() {
		var sc K8sReportSchedule
		var enabled int
		if err := rows.Scan(&sc.ID, &sc.ClusterID, &sc.Channel, &sc.Interval, &enabled, &sc.LastRunAt, &sc.CreatedAt, &sc.UpdatedAt); err != nil {
			return nil, err
		}
		sc.Enabled = enabled != 0
		out = append(out, sc)
	}
	return out, rows.Err()
}

// MarkK8sReportScheduleRun records the last delivery time so retries are spaced by the interval.
func (s *SQLStore) MarkK8sReportScheduleRun(ctx context.Context, id, ts string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_report_schedules SET last_run_at = ? WHERE id = ?`), ts, id)
	return err
}

// DeleteK8sReportSchedule removes a schedule.
func (s *SQLStore) DeleteK8sReportSchedule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_report_schedules WHERE id = ?`), id)
	return err
}
