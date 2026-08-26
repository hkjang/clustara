package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// K8sIncident groups a failure's evidence (RCA cause, events, recent change, actions) into one
// trackable unit — the Incident Workspace backbone. dedup_key identifies the same recurring
// failure so repeated scans update one open incident rather than spawning duplicates.
type K8sIncident struct {
	ID         string   `json:"id"`
	DedupKey   string   `json:"dedup_key"`
	ClusterID  string   `json:"cluster_id"`
	Namespace  string   `json:"namespace"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Condition  string   `json:"condition"`
	Severity   string   `json:"severity"`
	Status     string   `json:"status"` // open | resolved
	Title      string   `json:"title"`
	Evidence   []string `json:"evidence"`
	OpenedAt   string   `json:"opened_at"`
	UpdatedAt  string   `json:"updated_at"`
	ResolvedAt string   `json:"resolved_at"`
}

type K8sIncidentFilter struct {
	ClusterID string
	Status    string
	Limit     int
}

// UpsertK8sIncidentByKey opens a new incident for the dedup key, or refreshes the existing OPEN
// one (preserving id/opened_at). Returns the incident id and whether it was newly created.
func (s *SQLStore) UpsertK8sIncidentByKey(ctx context.Context, in K8sIncident, newID func(string) string) (string, bool, error) {
	now := nowString()
	var existingID string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id FROM k8s_incidents WHERE dedup_key = ? AND status = 'open'
		ORDER BY opened_at DESC LIMIT 1`), in.DedupKey).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return "", false, err
	}
	evJSON := encodeStringSlice(in.Evidence)
	if err == nil {
		_, uerr := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_incidents SET severity = ?, title = ?, condition = ?,
			evidence_json = ?, updated_at = ? WHERE id = ?`),
			in.Severity, in.Title, in.Condition, evJSON, now, existingID)
		return existingID, false, uerr
	}
	id := in.ID
	if id == "" {
		id = newID("k8sinc")
	}
	// The insert is the decision, not the SELECT above. Two syncs of the same cluster
	// can both reach here having each seen no open incident; without a conflict target
	// both would insert and the dedup key would hold two open incidents, each reported
	// as newly created and so each alerted on. The partial unique index makes the
	// second insert a no-op, and the loser falls through to updating the winner's row.
	res, ierr := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_incidents
		(id, dedup_key, cluster_id, namespace, kind, name, condition, severity, status, title, evidence_json, opened_at, updated_at, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, '')
		ON CONFLICT(dedup_key) WHERE status = 'open' DO NOTHING`),
		id, in.DedupKey, in.ClusterID, in.Namespace, in.Kind, in.Name, in.Condition, in.Severity, in.Title, evJSON, now, now)
	if ierr != nil {
		return "", false, ierr
	}
	if affected, aerr := res.RowsAffected(); aerr != nil {
		return "", false, aerr
	} else if affected == 1 {
		return id, true, nil
	}
	// Lost the race: another writer opened this incident first. Refresh theirs.
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT id FROM k8s_incidents WHERE dedup_key = ? AND status = 'open'
		ORDER BY opened_at DESC LIMIT 1`), in.DedupKey).Scan(&existingID); err != nil {
		return "", false, err
	}
	_, uerr := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_incidents SET severity = ?, title = ?, condition = ?,
		evidence_json = ?, updated_at = ? WHERE id = ?`),
		in.Severity, in.Title, in.Condition, evJSON, now, existingID)
	return existingID, false, uerr
}

func (s *SQLStore) ListK8sIncidents(ctx context.Context, f K8sIncidentFilter) ([]K8sIncident, error) {
	query := `SELECT id, dedup_key, cluster_id, namespace, kind, name, condition, severity, status, title,
		evidence_json, opened_at, updated_at, COALESCE(resolved_at, '') FROM k8s_incidents WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY (status = 'open') DESC, updated_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sIncident{}
	for rows.Next() {
		inc, err := scanK8sIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sIncident(ctx context.Context, id string) (K8sIncident, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, dedup_key, cluster_id, namespace, kind, name, condition, severity, status, title,
		evidence_json, opened_at, updated_at, COALESCE(resolved_at, '') FROM k8s_incidents WHERE id = ?`), id)
	inc, err := scanK8sIncident(row)
	if err == sql.ErrNoRows {
		return K8sIncident{}, ErrNotFound
	}
	return inc, err
}

func (s *SQLStore) ResolveK8sIncident(ctx context.Context, id string) error {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_incidents SET status = 'resolved', resolved_at = ?, updated_at = ?
		WHERE id = ? AND status = 'open'`), now, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolveOpenK8sIncidentsByKeyPrefix resolves preventive incidents whose signal disappeared while
// leaving observed-failure incidents untouched. activeKeys is the current scan's live signal set.
func (s *SQLStore) ResolveOpenK8sIncidentsByKeyPrefix(ctx context.Context, clusterID, prefix string, activeKeys map[string]bool) (int, error) {
	incidents, err := s.ListK8sIncidents(ctx, K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 500})
	if err != nil {
		return 0, err
	}
	resolved := 0
	for _, incident := range incidents {
		if !strings.HasPrefix(incident.DedupKey, prefix) || activeKeys[incident.DedupKey] {
			continue
		}
		if err := s.ResolveK8sIncident(ctx, incident.ID); err == nil {
			resolved++
		}
	}
	return resolved, nil
}

func scanK8sIncident(sc k8sClusterScanner) (K8sIncident, error) {
	var inc K8sIncident
	var ev string
	if err := sc.Scan(&inc.ID, &inc.DedupKey, &inc.ClusterID, &inc.Namespace, &inc.Kind, &inc.Name,
		&inc.Condition, &inc.Severity, &inc.Status, &inc.Title, &ev, &inc.OpenedAt, &inc.UpdatedAt, &inc.ResolvedAt); err != nil {
		return K8sIncident{}, err
	}
	inc.Evidence = decodeStringSlice(ev)
	return inc, nil
}

func encodeStringSlice(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeStringSlice(raw string) []string {
	out := []string{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

const k8sIncidentDedupMigrationReason = "superseded during incident dedup-key migration"

// migrateK8sIncidentOpenDedupKey enforces the invariant the dedup_key was always
// meant to carry: at most one OPEN incident per key. The column had only a
// non-unique index, so two concurrent syncs of the same cluster could both find no
// open incident and both insert one — measured at six duplicates for a single key
// under eight concurrent writers. Duplicates mean duplicate alerts (each insert
// reports created=true) and an incident that stays open after the other is
// resolved.
//
// Existing duplicates are collapsed onto the earliest open incident per key, which
// preserves the original opened_at, before the unique index is created. Same shape
// as migrateK8sRolloutTargetLock, including the Postgres table lock that holds off
// old-version writers until the index commits.
func (s *SQLStore) migrateK8sIncidentOpenDedupKey(ctx context.Context) error {
	const maxAttempts = 5
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = s.migrateK8sIncidentOpenDedupKeyAttempt(ctx, nil)
		if err == nil {
			return nil
		}
		if !retryableLockMigrationError(err) || attempt == maxAttempts-1 {
			return fmt.Errorf("migrate Kubernetes incident dedup key: %w", err)
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 25 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("migrate Kubernetes incident dedup key: %w", err)
}

// migrateK8sIncidentOpenDedupKeyAttempt is split out so the atomic boundary can be
// exercised deterministically in a concurrent-writer regression test.
func (s *SQLStore) migrateK8sIncidentOpenDedupKeyAttempt(ctx context.Context, beforeIndex func()) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if s.dialect == "postgres" {
		if _, err := tx.ExecContext(ctx, `LOCK TABLE k8s_incidents IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
	}

	now := nowString()
	// Intentionally the first SQLite statement in the transaction: even with no
	// matching row, UPDATE takes the writer lock before the victim set is evaluated
	// and holds it through index creation.
	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE k8s_incidents
		SET status='resolved',
			resolved_at=CASE WHEN resolved_at='' THEN ? ELSE resolved_at END,
			title=CASE WHEN title='' THEN ? ELSE title END,
			updated_at=?
		WHERE id IN (
			SELECT id FROM (
				SELECT id, ROW_NUMBER() OVER (
					PARTITION BY dedup_key ORDER BY opened_at, id
				) AS conflict_rank
				FROM k8s_incidents WHERE status='open'
			) ranked WHERE conflict_rank > 1
		)`), now, k8sIncidentDedupMigrationReason, now); err != nil {
		return err
	}

	if beforeIndex != nil {
		beforeIndex()
	}
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_k8s_incidents_open_dedup_key
		ON k8s_incidents(dedup_key) WHERE status = 'open'`); err != nil {
		return err
	}
	return tx.Commit()
}
