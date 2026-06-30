package store

import (
	"context"
	"time"
)

// MCP Tool Scope Enforcement (CLU-REQ-11): a per-tool least-privilege policy layered on top of the
// risk profile. It constrains which roles may call a tool, which namespaces/clusters its arguments
// may target, what masking level applies to responses, and whether it forces/skips the approval
// gate. server_label/tool_name support '*' wildcards (most-specific match wins).
type MCPToolScope struct {
	ID                string    `json:"id"`
	ServerLabel       string    `json:"server_label"`
	ToolName          string    `json:"tool_name"`
	AllowedRoles      string    `json:"allowed_roles"`      // CSV; empty = any role
	AllowedNamespaces string    `json:"allowed_namespaces"` // CSV; empty = any namespace
	AllowedClusters   string    `json:"allowed_clusters"`   // CSV; empty = any cluster
	MaskingLevel      string    `json:"masking_level"`      // none | partial | strict
	ApprovalRule      string    `json:"approval_rule"`      // inherit | always | never
	Enabled           bool      `json:"enabled"`
	Note              string    `json:"note"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (s *SQLStore) UpsertMCPToolScope(ctx context.Context, p MCPToolScope) error {
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	if p.ID == "" {
		p.ID = "mts_" + auditHash(p.ServerLabel+"|"+p.ToolName)
	}
	if p.MaskingLevel == "" {
		p.MaskingLevel = "none"
	}
	if p.ApprovalRule == "" {
		p.ApprovalRule = "inherit"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO mcp_tool_scopes
		(id, server_label, tool_name, allowed_roles, allowed_namespaces, allowed_clusters, masking_level, approval_rule, enabled, note, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(server_label, tool_name) DO UPDATE SET
			allowed_roles = excluded.allowed_roles,
			allowed_namespaces = excluded.allowed_namespaces,
			allowed_clusters = excluded.allowed_clusters,
			masking_level = excluded.masking_level,
			approval_rule = excluded.approval_rule,
			enabled = excluded.enabled,
			note = excluded.note,
			updated_at = excluded.updated_at`),
		p.ID, p.ServerLabel, p.ToolName, p.AllowedRoles, p.AllowedNamespaces, p.AllowedClusters,
		p.MaskingLevel, p.ApprovalRule, boolInt(p.Enabled), p.Note, formatTime(p.CreatedAt), formatTime(p.UpdatedAt))
	return err
}

func (s *SQLStore) DeleteMCPToolScope(ctx context.Context, serverLabel, toolName string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM mcp_tool_scopes WHERE server_label = ? AND tool_name = ?`), serverLabel, toolName)
	return err
}

func (s *SQLStore) ListMCPToolScopes(ctx context.Context) ([]MCPToolScope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, server_label, tool_name, allowed_roles, allowed_namespaces,
		allowed_clusters, masking_level, approval_rule, enabled, COALESCE(note, ''), created_at, updated_at
		FROM mcp_tool_scopes ORDER BY server_label ASC, tool_name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMCPToolScopes(rows)
}

// MCPToolScope returns the most-specific scope matching (server, tool), trying exact, then
// server/*, then */tool, then */*. ok=false when no scope is configured.
func (s *SQLStore) MCPToolScope(ctx context.Context, serverLabel, toolName string) (MCPToolScope, bool, error) {
	candidates := [][2]string{
		{serverLabel, toolName},
		{serverLabel, "*"},
		{"*", toolName},
		{"*", "*"},
	}
	for _, cand := range candidates {
		rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, server_label, tool_name, allowed_roles, allowed_namespaces,
			allowed_clusters, masking_level, approval_rule, enabled, COALESCE(note, ''), created_at, updated_at
			FROM mcp_tool_scopes WHERE server_label = ? AND tool_name = ? LIMIT 1`), cand[0], cand[1])
		if err != nil {
			return MCPToolScope{}, false, err
		}
		items, scanErr := scanMCPToolScopes(rows)
		rows.Close()
		if scanErr != nil {
			return MCPToolScope{}, false, scanErr
		}
		if len(items) > 0 {
			return items[0], true, nil
		}
	}
	return MCPToolScope{}, false, nil
}

func scanMCPToolScopes(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]MCPToolScope, error) {
	result := []MCPToolScope{}
	for rows.Next() {
		var p MCPToolScope
		var enabled int
		var createdAt, updatedAt string
		if err := rows.Scan(&p.ID, &p.ServerLabel, &p.ToolName, &p.AllowedRoles, &p.AllowedNamespaces,
			&p.AllowedClusters, &p.MaskingLevel, &p.ApprovalRule, &enabled, &p.Note, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		p.CreatedAt = parseOptionalTime(createdAt)
		p.UpdatedAt = parseOptionalTime(updatedAt)
		result = append(result, p)
	}
	return result, rows.Err()
}
