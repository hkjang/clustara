package store

import (
	"context"
	"encoding/json"
	"strings"
)

// EnterpriseRecord is a generic enterprise operations ledger row. It intentionally
// backs cross-domain artifacts that have the same lifecycle shape: evidence chains,
// CMDB links, ITSM tickets, risk register entries, Git source registries, change
// calendars, billing imports and workflow drafts.
type EnterpriseRecord struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	ScopeType   string         `json:"scope_type"`
	ScopeID     string         `json:"scope_id"`
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	OwnerTeamID string         `json:"owner_team_id"`
	SourceRef   string         `json:"source_ref"`
	EvidenceID  string         `json:"evidence_id"`
	Payload     map[string]any `json:"payload"`
	CreatedBy   string         `json:"created_by"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
}

type EnterpriseRecordFilter struct {
	Kind        string
	ScopeType   string
	ScopeID     string
	Status      string
	OwnerTeamID string
	SourceRef   string
	Limit       int
}

func (s *SQLStore) UpsertEnterpriseRecord(ctx context.Context, rec EnterpriseRecord) error {
	now := nowString()
	if rec.CreatedAt == "" {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	rec.Kind = strings.ToLower(strings.TrimSpace(rec.Kind))
	if rec.Payload == nil {
		rec.Payload = map[string]any{}
	}
	payload, err := json.Marshal(rec.Payload)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO enterprise_records
		(id, kind, scope_type, scope_id, name, status, owner_team_id, source_ref, evidence_id, payload_json, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind, scope_type = excluded.scope_type, scope_id = excluded.scope_id,
			name = excluded.name, status = excluded.status, owner_team_id = excluded.owner_team_id,
			source_ref = excluded.source_ref, evidence_id = excluded.evidence_id,
			payload_json = excluded.payload_json, updated_at = excluded.updated_at`),
		rec.ID, rec.Kind, rec.ScopeType, rec.ScopeID, rec.Name, rec.Status, rec.OwnerTeamID,
		rec.SourceRef, rec.EvidenceID, string(payload), rec.CreatedBy, rec.CreatedAt, rec.UpdatedAt)
	return err
}

func (s *SQLStore) ListEnterpriseRecords(ctx context.Context, f EnterpriseRecordFilter) ([]EnterpriseRecord, error) {
	query := `SELECT id, kind, COALESCE(scope_type,''), COALESCE(scope_id,''), COALESCE(name,''), COALESCE(status,''),
		COALESCE(owner_team_id,''), COALESCE(source_ref,''), COALESCE(evidence_id,''), COALESCE(payload_json,'{}'),
		COALESCE(created_by,''), created_at, updated_at FROM enterprise_records WHERE 1=1`
	args := []any{}
	addEq := func(col, value string) {
		if strings.TrimSpace(value) != "" {
			query += ` AND ` + col + ` = ?`
			args = append(args, strings.TrimSpace(value))
		}
	}
	addEq("kind", strings.ToLower(f.Kind))
	addEq("scope_type", f.ScopeType)
	addEq("scope_id", f.ScopeID)
	addEq("status", f.Status)
	addEq("owner_team_id", f.OwnerTeamID)
	addEq("source_ref", f.SourceRef)
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 200, 2000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnterpriseRecord{}
	for rows.Next() {
		var rec EnterpriseRecord
		var payload string
		if err := rows.Scan(&rec.ID, &rec.Kind, &rec.ScopeType, &rec.ScopeID, &rec.Name, &rec.Status,
			&rec.OwnerTeamID, &rec.SourceRef, &rec.EvidenceID, &payload, &rec.CreatedBy, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &rec.Payload); err != nil || rec.Payload == nil {
			rec.Payload = map[string]any{}
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
