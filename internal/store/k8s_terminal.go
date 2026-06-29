package store

import (
	"context"
)

// K8sTerminalPolicy controls future Pod exec / web terminal sessions. It is intentionally
// stored separately from action executor permissions so read-only terminal access can be governed
// without granting mutating Kubernetes verbs.
type K8sTerminalPolicy struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Role              string   `json:"role"`
	ClusterID         string   `json:"cluster_id"`
	NamespacePattern  string   `json:"namespace_pattern"`
	PodSelector       string   `json:"pod_selector"`
	CommandAllowlist  []string `json:"command_allowlist"`
	CommandDenylist   []string `json:"command_denylist"`
	RequireApproval   bool     `json:"require_approval"`
	MaxSessionMinutes int      `json:"max_session_minutes"`
	AuditEnabled      bool     `json:"audit_enabled"`
	Enabled           bool     `json:"enabled"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

type K8sTerminalPolicyFilter struct {
	Role      string
	ClusterID string
	Enabled   string // "", "true", "false"
	Limit     int
}

func (s *SQLStore) UpsertK8sTerminalPolicy(ctx context.Context, p K8sTerminalPolicy) error {
	now := nowString()
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	if p.NamespacePattern == "" {
		p.NamespacePattern = "*"
	}
	if p.MaxSessionMinutes <= 0 {
		p.MaxSessionMinutes = 10
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_terminal_policies
		(id, name, role, cluster_id, namespace_pattern, pod_selector, command_allowlist, command_denylist,
		 require_approval, max_session_minutes, audit_enabled, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name, role = excluded.role, cluster_id = excluded.cluster_id,
			namespace_pattern = excluded.namespace_pattern, pod_selector = excluded.pod_selector,
			command_allowlist = excluded.command_allowlist, command_denylist = excluded.command_denylist,
			require_approval = excluded.require_approval, max_session_minutes = excluded.max_session_minutes,
			audit_enabled = excluded.audit_enabled, enabled = excluded.enabled, updated_at = excluded.updated_at`),
		p.ID, p.Name, p.Role, p.ClusterID, p.NamespacePattern, p.PodSelector, joinTags(p.CommandAllowlist), joinTags(p.CommandDenylist),
		boolInt(p.RequireApproval), p.MaxSessionMinutes, boolInt(p.AuditEnabled), boolInt(p.Enabled), p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sTerminalPolicies(ctx context.Context, f K8sTerminalPolicyFilter) ([]K8sTerminalPolicy, error) {
	query := `SELECT id, name, COALESCE(role, ''), COALESCE(cluster_id, ''), COALESCE(namespace_pattern, '*'), COALESCE(pod_selector, ''),
		COALESCE(command_allowlist, ''), COALESCE(command_denylist, ''), require_approval, max_session_minutes, audit_enabled, enabled, created_at, updated_at
		FROM k8s_terminal_policies WHERE 1=1`
	args := []any{}
	if f.Role != "" {
		query += ` AND (role = ? OR role = '' OR role = '*')`
		args = append(args, f.Role)
	}
	if f.ClusterID != "" {
		query += ` AND (cluster_id = ? OR cluster_id = '')`
		args = append(args, f.ClusterID)
	}
	switch f.Enabled {
	case "true":
		query += ` AND enabled = 1`
	case "false":
		query += ` AND enabled = 0`
	}
	query += ` ORDER BY enabled DESC, role ASC, cluster_id ASC, namespace_pattern ASC, name ASC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 200, 2000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sTerminalPolicy{}
	for rows.Next() {
		var p K8sTerminalPolicy
		var allowRaw, denyRaw string
		var requireApproval, auditEnabled, enabled int
		if err := rows.Scan(&p.ID, &p.Name, &p.Role, &p.ClusterID, &p.NamespacePattern, &p.PodSelector,
			&allowRaw, &denyRaw, &requireApproval, &p.MaxSessionMinutes, &auditEnabled, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.CommandAllowlist = parseTags(allowRaw)
		p.CommandDenylist = parseTags(denyRaw)
		p.RequireApproval = requireApproval != 0
		p.AuditEnabled = auditEnabled != 0
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteK8sTerminalPolicy(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_terminal_policies WHERE id = ?`), id)
	return err
}
