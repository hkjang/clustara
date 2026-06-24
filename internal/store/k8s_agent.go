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

// K8sWatchEvent is the append-only audit trail for watch deltas received from realtime agents.
// EventKey is a deterministic idempotency key so retrying an offline queue does not reapply the
// same Kubernetes resourceVersion event twice.
type K8sWatchEvent struct {
	ID              string `json:"id"`
	EventKey        string `json:"event_key"`
	ClusterID       string `json:"cluster_id"`
	AgentID         string `json:"agent_id"`
	EventType       string `json:"event_type"`
	ResourceVersion string `json:"resource_version"`
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ObservedAt      string `json:"observed_at"`
	CreatedAt       string `json:"created_at"`
}

// K8sCollectorOffset is the restart checkpoint per agent/kind. The in-cluster agent can use this
// state to resume from the last accepted resourceVersion, and operators can inspect lag/drift.
type K8sCollectorOffset struct {
	ClusterID           string `json:"cluster_id"`
	AgentID             string `json:"agent_id"`
	ResourceKind        string `json:"resource_kind"`
	LastResourceVersion string `json:"last_resource_version"`
	LastObservedAt      string `json:"last_observed_at"`
	EventsSeen          int64  `json:"events_seen"`
	DuplicateEvents     int64  `json:"duplicate_events"`
	UpdatedAt           string `json:"updated_at"`
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

// InsertK8sWatchEvent records one accepted watch event. It returns inserted=false when the event's
// idempotency key has already been seen.
func (s *SQLStore) InsertK8sWatchEvent(ctx context.Context, e K8sWatchEvent) (bool, error) {
	if e.CreatedAt == "" {
		e.CreatedAt = nowString()
	}
	if e.ObservedAt == "" {
		e.ObservedAt = e.CreatedAt
	}
	res, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_watch_events
		(id, event_key, cluster_id, agent_id, event_type, resource_version, kind, namespace, name, uid, observed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(event_key) DO NOTHING`),
		e.ID, e.EventKey, e.ClusterID, e.AgentID, e.EventType, e.ResourceVersion, e.Kind, e.Namespace, e.Name, e.UID, e.ObservedAt, e.CreatedAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return err == nil && n > 0, err
}

// ListK8sWatchEvents returns recent realtime watch events, newest first.
func (s *SQLStore) ListK8sWatchEvents(ctx context.Context, clusterID string, limit int) ([]K8sWatchEvent, error) {
	query := `SELECT id, event_key, cluster_id, agent_id, event_type, resource_version, kind, namespace, name, uid, observed_at, created_at
		FROM k8s_watch_events WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY observed_at DESC, created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 50, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sWatchEvent{}
	for rows.Next() {
		var e K8sWatchEvent
		if err := rows.Scan(&e.ID, &e.EventKey, &e.ClusterID, &e.AgentID, &e.EventType, &e.ResourceVersion,
			&e.Kind, &e.Namespace, &e.Name, &e.UID, &e.ObservedAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpsertK8sCollectorOffset refreshes the restart checkpoint and cumulative counters for a kind.
func (s *SQLStore) UpsertK8sCollectorOffset(ctx context.Context, o K8sCollectorOffset) error {
	if o.UpdatedAt == "" {
		o.UpdatedAt = nowString()
	}
	if o.LastObservedAt == "" {
		o.LastObservedAt = o.UpdatedAt
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_collector_offsets
		(cluster_id, agent_id, resource_kind, last_resource_version, last_observed_at, events_seen, duplicate_events, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, agent_id, resource_kind) DO UPDATE SET
			last_resource_version = excluded.last_resource_version,
			last_observed_at = excluded.last_observed_at,
			events_seen = k8s_collector_offsets.events_seen + excluded.events_seen,
			duplicate_events = k8s_collector_offsets.duplicate_events + excluded.duplicate_events,
			updated_at = excluded.updated_at`),
		o.ClusterID, o.AgentID, o.ResourceKind, o.LastResourceVersion, o.LastObservedAt, o.EventsSeen, o.DuplicateEvents, o.UpdatedAt)
	return err
}

// ListK8sCollectorOffsets returns resourceVersion checkpoints by agent/kind.
func (s *SQLStore) ListK8sCollectorOffsets(ctx context.Context, clusterID string) ([]K8sCollectorOffset, error) {
	query := `SELECT cluster_id, agent_id, resource_kind, last_resource_version, last_observed_at,
		events_seen, duplicate_events, updated_at FROM k8s_collector_offsets WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY updated_at DESC, cluster_id, agent_id, resource_kind`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sCollectorOffset{}
	for rows.Next() {
		var o K8sCollectorOffset
		if err := rows.Scan(&o.ClusterID, &o.AgentID, &o.ResourceKind, &o.LastResourceVersion, &o.LastObservedAt,
			&o.EventsSeen, &o.DuplicateEvents, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
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
