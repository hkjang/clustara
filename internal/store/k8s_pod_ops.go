package store

import (
	"context"
	"database/sql"
	"encoding/json"
)

type K8sPodBookmark struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	OwnerKind string `json:"owner_kind"`
	OwnerName string `json:"owner_name"`
	Note      string `json:"note"`
	Auto      bool   `json:"auto"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type K8sPodBookmarkFilter struct {
	UserID    string
	ClusterID string
	Namespace string
	Auto      string
	Limit     int
}

type K8sPodAccess struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Action    string `json:"action"`
	Context   string `json:"context"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

type K8sPodAccessFilter struct {
	UserID    string
	ClusterID string
	Namespace string
	Pod       string
	Action    string
	Limit     int
}

type K8sPodLogSnapshot struct {
	ID        string         `json:"id"`
	ClusterID string         `json:"cluster_id"`
	Namespace string         `json:"namespace"`
	Pod       string         `json:"pod"`
	Container string         `json:"container"`
	Previous  bool           `json:"previous"`
	TailLines int            `json:"tail_lines"`
	Reason    string         `json:"reason"`
	Summary   map[string]any `json:"summary"`
	Text      string         `json:"text,omitempty"`
	CreatedBy string         `json:"created_by"`
	CreatedAt string         `json:"created_at"`
}

type K8sPodLogSnapshotFilter struct {
	ClusterID string
	Namespace string
	Pod       string
	Limit     int
}

type K8sDebugSession struct {
	ID              string `json:"id"`
	ClusterID       string `json:"cluster_id"`
	Namespace       string `json:"namespace"`
	Pod             string `json:"pod"`
	TargetContainer string `json:"target_container"`
	DebugImage      string `json:"debug_image"`
	Template        string `json:"template"`
	Reason          string `json:"reason"`
	Status          string `json:"status"`
	RiskLevel       string `json:"risk_level"`
	RequireApproval bool   `json:"require_approval"`
	RequestedBy     string `json:"requested_by"`
	ApprovedBy      string `json:"approved_by"`
	ApprovedAt      string `json:"approved_at"`
	DecisionNote    string `json:"decision_note"`
	ManifestPreview string `json:"manifest_preview"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type K8sDebugSessionFilter struct {
	ClusterID string
	Namespace string
	Pod       string
	Status    string
	Limit     int
}

func (s *SQLStore) UpsertK8sPodBookmark(ctx context.Context, b *K8sPodBookmark) error {
	now := nowString()
	if b.CreatedAt == "" {
		b.CreatedAt = now
	}
	b.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_bookmarks
		(id, user_id, cluster_id, namespace, pod, owner_kind, owner_name, note, auto, reason, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, cluster_id, namespace, pod) DO UPDATE SET
			owner_kind = excluded.owner_kind,
			owner_name = excluded.owner_name,
			note = excluded.note,
			auto = excluded.auto,
			reason = excluded.reason,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at`),
		b.ID, b.UserID, b.ClusterID, b.Namespace, b.Pod, b.OwnerKind, b.OwnerName, b.Note, boolInt(b.Auto), b.Reason, b.ExpiresAt, b.CreatedAt, b.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sPodBookmarks(ctx context.Context, f K8sPodBookmarkFilter) ([]K8sPodBookmark, error) {
	query := `SELECT id, user_id, cluster_id, namespace, pod, owner_kind, owner_name, note, auto, reason, expires_at, created_at, updated_at
		FROM k8s_pod_bookmarks WHERE 1=1`
	args := []any{}
	if f.UserID != "" {
		query += ` AND user_id = ?`
		args = append(args, f.UserID)
	}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	if f.Auto != "" {
		query += ` AND auto = ?`
		args = append(args, boolInt(f.Auto == "true" || f.Auto == "1"))
	}
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodBookmark{}
	for rows.Next() {
		var b K8sPodBookmark
		var auto int
		if err := rows.Scan(&b.ID, &b.UserID, &b.ClusterID, &b.Namespace, &b.Pod, &b.OwnerKind, &b.OwnerName, &b.Note, &auto, &b.Reason, &b.ExpiresAt, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		b.Auto = auto != 0
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteK8sPodBookmark(ctx context.Context, id, userID string) error {
	query := `DELETE FROM k8s_pod_bookmarks WHERE id = ?`
	args := []any{id}
	if userID != "" {
		query += ` AND user_id = ?`
		args = append(args, userID)
	}
	res, err := s.db.ExecContext(ctx, s.bind(query), args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) RecordK8sPodAccess(ctx context.Context, a K8sPodAccess) error {
	now := nowString()
	if a.FirstSeen == "" {
		a.FirstSeen = now
	}
	a.LastSeen = now
	if a.Count <= 0 {
		a.Count = 1
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_accesses
		(id, user_id, cluster_id, namespace, pod, action, context, count, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, cluster_id, namespace, pod, action) DO UPDATE SET
			context = excluded.context,
			count = k8s_pod_accesses.count + 1,
			last_seen = excluded.last_seen`),
		a.ID, a.UserID, a.ClusterID, a.Namespace, a.Pod, a.Action, a.Context, a.Count, a.FirstSeen, a.LastSeen)
	return err
}

func (s *SQLStore) ListK8sPodAccesses(ctx context.Context, f K8sPodAccessFilter) ([]K8sPodAccess, error) {
	query := `SELECT id, user_id, cluster_id, namespace, pod, action, context, count, first_seen, last_seen
		FROM k8s_pod_accesses WHERE 1=1`
	args := []any{}
	if f.UserID != "" {
		query += ` AND user_id = ?`
		args = append(args, f.UserID)
	}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	if f.Pod != "" {
		query += ` AND pod = ?`
		args = append(args, f.Pod)
	}
	if f.Action != "" {
		query += ` AND action = ?`
		args = append(args, f.Action)
	}
	query += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 50, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodAccess{}
	for rows.Next() {
		var a K8sPodAccess
		if err := rows.Scan(&a.ID, &a.UserID, &a.ClusterID, &a.Namespace, &a.Pod, &a.Action, &a.Context, &a.Count, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) InsertK8sPodLogSnapshot(ctx context.Context, snap K8sPodLogSnapshot) error {
	if snap.CreatedAt == "" {
		snap.CreatedAt = nowString()
	}
	summaryJSON, _ := json.Marshal(snap.Summary)
	if len(summaryJSON) == 0 {
		summaryJSON = []byte("{}")
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_log_snapshots
		(id, cluster_id, namespace, pod, container, previous, tail_lines, reason, summary_json, text, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		snap.ID, snap.ClusterID, snap.Namespace, snap.Pod, snap.Container, boolInt(snap.Previous), snap.TailLines, snap.Reason, string(summaryJSON), snap.Text, snap.CreatedBy, snap.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sPodLogSnapshots(ctx context.Context, f K8sPodLogSnapshotFilter) ([]K8sPodLogSnapshot, error) {
	query := `SELECT id, cluster_id, namespace, pod, container, previous, tail_lines, reason, summary_json, text, created_by, created_at
		FROM k8s_pod_log_snapshots WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	if f.Pod != "" {
		query += ` AND pod = ?`
		args = append(args, f.Pod)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 20, 200))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodLogSnapshot{}
	for rows.Next() {
		var snap K8sPodLogSnapshot
		var previous int
		var summaryRaw string
		if err := rows.Scan(&snap.ID, &snap.ClusterID, &snap.Namespace, &snap.Pod, &snap.Container, &previous, &snap.TailLines, &snap.Reason, &summaryRaw, &snap.Text, &snap.CreatedBy, &snap.CreatedAt); err != nil {
			return nil, err
		}
		snap.Previous = previous != 0
		snap.Summary = map[string]any{}
		_ = json.Unmarshal([]byte(summaryRaw), &snap.Summary)
		out = append(out, snap)
	}
	return out, rows.Err()
}

func (s *SQLStore) InsertK8sDebugSession(ctx context.Context, sess *K8sDebugSession) error {
	now := nowString()
	if sess.CreatedAt == "" {
		sess.CreatedAt = now
	}
	sess.UpdatedAt = now
	if sess.Status == "" {
		sess.Status = "pending_approval"
	}
	if sess.RiskLevel == "" {
		sess.RiskLevel = "medium"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_debug_sessions
		(id, cluster_id, namespace, pod, target_container, debug_image, template, reason, status, risk_level, require_approval, requested_by, manifest_preview, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		sess.ID, sess.ClusterID, sess.Namespace, sess.Pod, sess.TargetContainer, sess.DebugImage, sess.Template, sess.Reason, sess.Status, sess.RiskLevel, boolInt(sess.RequireApproval), sess.RequestedBy, sess.ManifestPreview, sess.CreatedAt, sess.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sDebugSessions(ctx context.Context, f K8sDebugSessionFilter) ([]K8sDebugSession, error) {
	query := `SELECT id, cluster_id, namespace, pod, target_container, debug_image, template, reason, status, risk_level,
		require_approval, requested_by, approved_by, approved_at, decision_note, manifest_preview, created_at, updated_at
		FROM k8s_debug_sessions WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	if f.Pod != "" {
		query += ` AND pod = ?`
		args = append(args, f.Pod)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 50, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sDebugSession{}
	for rows.Next() {
		sess, err := scanK8sDebugSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sDebugSession(ctx context.Context, id string) (K8sDebugSession, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, pod, target_container, debug_image, template, reason, status, risk_level,
		require_approval, requested_by, approved_by, approved_at, decision_note, manifest_preview, created_at, updated_at
		FROM k8s_debug_sessions WHERE id = ?`), id)
	sess, err := scanK8sDebugSession(row)
	if err == sql.ErrNoRows {
		return K8sDebugSession{}, ErrNotFound
	}
	return sess, err
}

func (s *SQLStore) UpdateK8sDebugSessionDecision(ctx context.Context, id, status, actor, note string) (K8sDebugSession, error) {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_debug_sessions
		SET status = ?, approved_by = ?, approved_at = ?, decision_note = ?, updated_at = ?
		WHERE id = ?`), status, actor, now, note, now, id)
	if err != nil {
		return K8sDebugSession{}, err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return K8sDebugSession{}, ErrNotFound
	}
	return s.GetK8sDebugSession(ctx, id)
}

func scanK8sDebugSession(rows k8sClusterScanner) (K8sDebugSession, error) {
	var sess K8sDebugSession
	var requireApproval int
	if err := rows.Scan(&sess.ID, &sess.ClusterID, &sess.Namespace, &sess.Pod, &sess.TargetContainer, &sess.DebugImage, &sess.Template, &sess.Reason,
		&sess.Status, &sess.RiskLevel, &requireApproval, &sess.RequestedBy, &sess.ApprovedBy, &sess.ApprovedAt, &sess.DecisionNote, &sess.ManifestPreview, &sess.CreatedAt, &sess.UpdatedAt); err != nil {
		return K8sDebugSession{}, err
	}
	sess.RequireApproval = requireApproval != 0
	return sess, nil
}
