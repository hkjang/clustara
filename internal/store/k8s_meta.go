package store

import (
	"context"
	"database/sql"
	"time"
)

// ShouldSendK8sNotification implements notification de-duplication (NOTI-02): it returns true
// (and records now) only when the dedup key has not fired within the window. Concurrent-safe
// enough for best-effort alerting via an upsert guarded by a freshness check.
func (s *SQLStore) ShouldSendK8sNotification(ctx context.Context, key string, now time.Time, window time.Duration) (bool, error) {
	var lastStr string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT last_sent_at FROM k8s_notification_state WHERE dedup_key = ?`), key).Scan(&lastStr)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if err == nil {
		if last, perr := time.Parse(time.RFC3339Nano, lastStr); perr == nil && now.Sub(last) < window {
			return false, nil // still within the suppression window
		}
	}
	_, werr := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_notification_state (dedup_key, last_sent_at)
		VALUES (?, ?) ON CONFLICT(dedup_key) DO UPDATE SET last_sent_at = excluded.last_sent_at`),
		key, now.UTC().Format(time.RFC3339Nano))
	if werr != nil {
		return false, werr
	}
	return true, nil
}

// K8sClusterGroup groups clusters by network/zone (업무망/개발망/운영망/인터넷망/DMZ) for
// roll-up status, cost and security views (K8S-16).
type K8sClusterGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// K8sNamespaceOwnership records who owns a namespace for filtering failures/cost/security by
// team and for notification routing (K8S-17 / NOTI-04).
type K8sNamespaceOwnership struct {
	ID          string `json:"id"`
	ClusterID   string `json:"cluster_id"`
	Namespace   string `json:"namespace"`
	Team        string `json:"team"`
	Owner       string `json:"owner"`
	ServiceName string `json:"service_name"`
	Criticality string `json:"criticality"`
	CostCenter  string `json:"cost_center"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (s *SQLStore) UpsertK8sClusterGroup(ctx context.Context, g K8sClusterGroup) error {
	now := nowString()
	if g.CreatedAt == "" {
		g.CreatedAt = now
	}
	g.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_cluster_groups
		(id, name, kind, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
			description = excluded.description, updated_at = excluded.updated_at`),
		g.ID, g.Name, g.Kind, g.Description, g.CreatedAt, g.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sClusterGroups(ctx context.Context) ([]K8sClusterGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, COALESCE(kind, ''), COALESCE(description, ''), created_at, updated_at
		FROM k8s_cluster_groups ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sClusterGroup{}
	for rows.Next() {
		var g K8sClusterGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Kind, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteK8sClusterGroup(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_clusters SET group_id = '', updated_at = ? WHERE group_id = ?`), nowString(), id); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_cluster_groups WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) UpsertK8sNamespaceOwnership(ctx context.Context, o K8sNamespaceOwnership) error {
	now := nowString()
	if o.CreatedAt == "" {
		o.CreatedAt = now
	}
	o.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_namespace_ownership
		(id, cluster_id, namespace, team, owner, service_name, criticality, cost_center, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, namespace) DO UPDATE SET
			team = excluded.team, owner = excluded.owner, service_name = excluded.service_name,
			criticality = excluded.criticality, cost_center = excluded.cost_center, updated_at = excluded.updated_at`),
		o.ID, o.ClusterID, o.Namespace, o.Team, o.Owner, o.ServiceName, o.Criticality, o.CostCenter, o.CreatedAt, o.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sNamespaceOwnership(ctx context.Context, clusterID, team string) ([]K8sNamespaceOwnership, error) {
	query := `SELECT id, cluster_id, namespace, COALESCE(team, ''), COALESCE(owner, ''), COALESCE(service_name, ''),
		COALESCE(criticality, ''), COALESCE(cost_center, ''), created_at, updated_at FROM k8s_namespace_ownership WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	if team != "" {
		query += ` AND lower(team) = lower(?)`
		args = append(args, team)
	}
	query += ` ORDER BY cluster_id, namespace`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sNamespaceOwnership{}
	for rows.Next() {
		var o K8sNamespaceOwnership
		if err := rows.Scan(&o.ID, &o.ClusterID, &o.Namespace, &o.Team, &o.Owner, &o.ServiceName,
			&o.Criticality, &o.CostCenter, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteK8sNamespaceOwnership(ctx context.Context, clusterID, namespace string) error {
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_namespace_ownership WHERE cluster_id = ? AND namespace = ?`), clusterID, namespace)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// K8sCostSnapshot is one daily cost data point per dimension key, enabling cost-trend/increase
// analysis without an external warehouse (DW-08 trend).
type K8sCostSnapshot struct {
	ClusterID  string  `json:"cluster_id"`
	Dimension  string  `json:"dimension"`
	Key        string  `json:"key"`
	Day        string  `json:"day"` // YYYY-MM-DD
	MonthlyKRW float64 `json:"monthly_krw"`
	ObservedAt string  `json:"observed_at"`
}

// RecordK8sCostSnapshot upserts one cost line for its (cluster,dimension,key,day) — idempotent
// per day, so repeated runs the same day overwrite rather than duplicate.
func (s *SQLStore) RecordK8sCostSnapshot(ctx context.Context, c K8sCostSnapshot) error {
	if c.ObservedAt == "" {
		c.ObservedAt = nowString()
	}
	if c.Day == "" && len(c.ObservedAt) >= 10 {
		c.Day = c.ObservedAt[:10]
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_cost_snapshots
		(cluster_id, dimension, key, day, monthly_krw, observed_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, dimension, key, day) DO UPDATE SET
			monthly_krw = excluded.monthly_krw, observed_at = excluded.observed_at`),
		c.ClusterID, c.Dimension, c.Key, c.Day, c.MonthlyKRW, c.ObservedAt)
	return err
}

// ListK8sCostSnapshots returns recent snapshots for a dimension (newest day first).
func (s *SQLStore) ListK8sCostSnapshots(ctx context.Context, clusterID, dimension string, limit int) ([]K8sCostSnapshot, error) {
	query := `SELECT cluster_id, dimension, key, day, monthly_krw, observed_at FROM k8s_cost_snapshots WHERE dimension = ?`
	args := []any{dimension}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY day DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 500, 5000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sCostSnapshot{}
	for rows.Next() {
		var c K8sCostSnapshot
		if err := rows.Scan(&c.ClusterID, &c.Dimension, &c.Key, &c.Day, &c.MonthlyKRW, &c.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// K8sPolicy is a stored guardrail (SEC-05/SEC-10). RuleType/Action are validated at the handler.
type K8sPolicy struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	RuleType  string `json:"rule_type"`
	Action    string `json:"action"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (s *SQLStore) UpsertK8sPolicy(ctx context.Context, p K8sPolicy) error {
	now := nowString()
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_policies
		(id, name, rule_type, action, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, rule_type = excluded.rule_type,
			action = excluded.action, enabled = excluded.enabled, updated_at = excluded.updated_at`),
		p.ID, p.Name, p.RuleType, p.Action, enabled, p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sPolicies(ctx context.Context) ([]K8sPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, rule_type, action, enabled, created_at, updated_at
		FROM k8s_policies ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPolicy{}
	for rows.Next() {
		var p K8sPolicy
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.RuleType, &p.Action, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteK8sPolicy(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_policies WHERE id = ?`), id)
	return err
}

// GetK8sNamespaceOwner returns the ownership row for a namespace, or ErrNotFound. Used by
// notification routing and team-scoped filtering.
func (s *SQLStore) GetK8sNamespaceOwner(ctx context.Context, clusterID, namespace string) (K8sNamespaceOwnership, error) {
	var o K8sNamespaceOwnership
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, COALESCE(team, ''), COALESCE(owner, ''),
		COALESCE(service_name, ''), COALESCE(criticality, ''), COALESCE(cost_center, ''), created_at, updated_at
		FROM k8s_namespace_ownership WHERE cluster_id = ? AND namespace = ?`), clusterID, namespace).
		Scan(&o.ID, &o.ClusterID, &o.Namespace, &o.Team, &o.Owner, &o.ServiceName, &o.Criticality, &o.CostCenter, &o.CreatedAt, &o.UpdatedAt)
	if err == sql.ErrNoRows {
		return K8sNamespaceOwnership{}, ErrNotFound
	}
	return o, err
}
