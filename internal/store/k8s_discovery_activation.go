package store

import "context"

// Discovery activation (CLU-NEXT-15/16): persists which discovered inventory targets and MCP tool
// candidates an operator has activated, per cluster. kind = "target" | "mcp_tool"; key identifies
// the resource (group/version/resource) or the tool name. This is the curated allow-list; the
// collector / MCP gateway enforcement consumes it.
type K8sDiscoveryActivation struct {
	ClusterID string `json:"cluster_id"`
	Kind      string `json:"kind"`
	Key       string `json:"key"`
	Enabled   bool   `json:"enabled"`
	UpdatedBy string `json:"updated_by"`
	UpdatedAt string `json:"updated_at"`
}

// SetK8sDiscoveryActivation upserts an activation toggle.
func (s *SQLStore) SetK8sDiscoveryActivation(ctx context.Context, a K8sDiscoveryActivation) error {
	if a.UpdatedAt == "" {
		a.UpdatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_discovery_activations
		(cluster_id, kind, key, enabled, updated_by, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, kind, key) DO UPDATE SET
			enabled = excluded.enabled, updated_by = excluded.updated_by, updated_at = excluded.updated_at`),
		a.ClusterID, a.Kind, a.Key, boolInt(a.Enabled), a.UpdatedBy, a.UpdatedAt)
	return err
}

// ListK8sDiscoveryActivations returns activations for a cluster (optionally filtered by kind).
func (s *SQLStore) ListK8sDiscoveryActivations(ctx context.Context, clusterID, kind string) ([]K8sDiscoveryActivation, error) {
	query := `SELECT cluster_id, kind, key, enabled, updated_by, updated_at FROM k8s_discovery_activations WHERE cluster_id = ?`
	args := []any{clusterID}
	if kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sDiscoveryActivation{}
	for rows.Next() {
		var a K8sDiscoveryActivation
		var en int
		if err := rows.Scan(&a.ClusterID, &a.Kind, &a.Key, &en, &a.UpdatedBy, &a.UpdatedAt); err != nil {
			return nil, err
		}
		a.Enabled = en != 0
		out = append(out, a)
	}
	return out, rows.Err()
}
