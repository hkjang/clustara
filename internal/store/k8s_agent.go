package store

import "context"

// K8sAgentHeartbeat is one realtime collector agent's liveness + watch telemetry, keyed by
// (cluster_id, agent_id). The agent reports cumulative counters; the server records staleness.
type K8sAgentHeartbeat struct {
	ClusterID           string `json:"cluster_id"`
	AgentID             string `json:"agent_id"`
	Version             string `json:"version"`
	LastResourceVersion string `json:"last_resource_version"`
	WatchLagMS          int64  `json:"watch_lag_ms"`
	EventsReceived      int64  `json:"events_received"`
	Reconnects          int64  `json:"reconnects"`
	LastError           string `json:"last_error"`
	LastSeen            string `json:"last_seen"`
}

// UpsertK8sAgentHeartbeat records or refreshes an agent's heartbeat row.
func (s *SQLStore) UpsertK8sAgentHeartbeat(ctx context.Context, h K8sAgentHeartbeat) error {
	if h.LastSeen == "" {
		h.LastSeen = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_agent_heartbeats
		(cluster_id, agent_id, version, last_resource_version, watch_lag_ms, events_received, reconnects, last_error, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, agent_id) DO UPDATE SET
			version = excluded.version,
			last_resource_version = excluded.last_resource_version,
			watch_lag_ms = excluded.watch_lag_ms,
			events_received = excluded.events_received,
			reconnects = excluded.reconnects,
			last_error = excluded.last_error,
			last_seen = excluded.last_seen`),
		h.ClusterID, h.AgentID, h.Version, h.LastResourceVersion, h.WatchLagMS,
		h.EventsReceived, h.Reconnects, h.LastError, h.LastSeen)
	return err
}

// ListK8sAgentHeartbeats returns agent heartbeats (optionally filtered by cluster), newest first.
func (s *SQLStore) ListK8sAgentHeartbeats(ctx context.Context, clusterID string) ([]K8sAgentHeartbeat, error) {
	query := `SELECT cluster_id, agent_id, version, last_resource_version, watch_lag_ms,
		events_received, reconnects, last_error, last_seen FROM k8s_agent_heartbeats`
	args := []any{}
	if clusterID != "" {
		query += ` WHERE cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY last_seen DESC`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sAgentHeartbeat{}
	for rows.Next() {
		var h K8sAgentHeartbeat
		if err := rows.Scan(&h.ClusterID, &h.AgentID, &h.Version, &h.LastResourceVersion, &h.WatchLagMS,
			&h.EventsReceived, &h.Reconnects, &h.LastError, &h.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DeleteK8sInventoryItem removes one inventory row (realtime DELETED watch event).
func (s *SQLStore) DeleteK8sInventoryItem(ctx context.Context, clusterID, kind, namespace, name string) error {
	_, err := s.db.ExecContext(ctx, s.bind(
		`DELETE FROM k8s_inventory WHERE cluster_id = ? AND kind = ? AND namespace = ? AND name = ?`),
		clusterID, kind, namespace, name)
	return err
}
