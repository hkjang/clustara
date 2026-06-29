package store

import (
	"context"
	"database/sql"
)

// K8sPodExecSession records a policy-gated Pod exec / terminal request.
// The request is captured before any interactive transport is opened so audit and
// approval workflows can stay separate from Kubernetes mutating permissions.
type K8sPodExecSession struct {
	ID                string `json:"id"`
	ClusterID         string `json:"cluster_id"`
	Namespace         string `json:"namespace"`
	Pod               string `json:"pod"`
	Container         string `json:"container"`
	Command           string `json:"command"`
	Role              string `json:"role"`
	RequestedBy       string `json:"requested_by"`
	Status            string `json:"status"`
	RiskLevel         string `json:"risk_level"`
	RequireApproval   bool   `json:"require_approval"`
	AuditEnabled      bool   `json:"audit_enabled"`
	MaxSessionMinutes int    `json:"max_session_minutes"`
	PolicyResult      string `json:"policy_result"`
	Reason            string `json:"reason"`
	DecidedBy         string `json:"decided_by"`
	DecidedAt         string `json:"decided_at"`
	DecisionNote      string `json:"decision_note"`
	ExecutedBy        string `json:"executed_by"`
	ExecutedAt        string `json:"executed_at"`
	OutputSample      string `json:"output_sample"`
	ErrorMessage      string `json:"error_message"`
	ExitCode          int    `json:"exit_code"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type K8sPodExecSessionFilter struct {
	ClusterID string
	Namespace string
	Pod       string
	Status    string
	Limit     int
}

func (s *SQLStore) CreateK8sPodExecSession(ctx context.Context, sess *K8sPodExecSession) error {
	now := nowString()
	if sess.CreatedAt == "" {
		sess.CreatedAt = now
	}
	sess.UpdatedAt = now
	if sess.Status == "" {
		sess.Status = "pending_approval"
	}
	if sess.RiskLevel == "" {
		sess.RiskLevel = "low"
	}
	if sess.MaxSessionMinutes <= 0 {
		sess.MaxSessionMinutes = 10
	}
	if sess.PolicyResult == "" {
		sess.PolicyResult = "{}"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_exec_sessions
		(id, cluster_id, namespace, pod, container, command, role, requested_by, status, risk_level,
		 require_approval, audit_enabled, max_session_minutes, policy_result, reason, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		sess.ID, sess.ClusterID, sess.Namespace, sess.Pod, sess.Container, sess.Command, sess.Role, sess.RequestedBy, sess.Status, sess.RiskLevel,
		boolInt(sess.RequireApproval), boolInt(sess.AuditEnabled), sess.MaxSessionMinutes, sess.PolicyResult, sess.Reason, sess.CreatedAt, sess.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sPodExecSessions(ctx context.Context, f K8sPodExecSessionFilter) ([]K8sPodExecSession, error) {
	query := `SELECT id, cluster_id, namespace, pod, container, command, role, requested_by, status, risk_level,
		require_approval, audit_enabled, max_session_minutes, COALESCE(policy_result, '{}'), COALESCE(reason, ''),
		COALESCE(decided_by, ''), COALESCE(decided_at, ''), COALESCE(decision_note, ''),
		COALESCE(executed_by, ''), COALESCE(executed_at, ''), COALESCE(output_sample, ''), COALESCE(error_message, ''), COALESCE(exit_code, 0),
		created_at, updated_at
		FROM k8s_pod_exec_sessions WHERE 1=1`
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
	args = append(args, boundedLimit(f.Limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodExecSession{}
	for rows.Next() {
		sess, err := scanK8sPodExecSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sPodExecSession(ctx context.Context, id string) (K8sPodExecSession, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, pod, container, command, role, requested_by, status, risk_level,
		require_approval, audit_enabled, max_session_minutes, COALESCE(policy_result, '{}'), COALESCE(reason, ''),
		COALESCE(decided_by, ''), COALESCE(decided_at, ''), COALESCE(decision_note, ''),
		COALESCE(executed_by, ''), COALESCE(executed_at, ''), COALESCE(output_sample, ''), COALESCE(error_message, ''), COALESCE(exit_code, 0),
		created_at, updated_at
		FROM k8s_pod_exec_sessions WHERE id = ?`), id)
	sess, err := scanK8sPodExecSession(row)
	if err == sql.ErrNoRows {
		return K8sPodExecSession{}, ErrNotFound
	}
	return sess, err
}

func (s *SQLStore) UpdateK8sPodExecSessionDecision(ctx context.Context, id, status, actor, note string) (K8sPodExecSession, error) {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = ?, decided_by = ?, decided_at = ?, decision_note = ?, updated_at = ?
		WHERE id = ?`), status, actor, now, note, now, id)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return K8sPodExecSession{}, ErrNotFound
	}
	return s.GetK8sPodExecSession(ctx, id)
}

func (s *SQLStore) UpdateK8sPodExecSessionExecution(ctx context.Context, id, status, actor, outputSample, errorMessage string, exitCode int) (K8sPodExecSession, error) {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = ?, executed_by = ?, executed_at = ?, output_sample = ?, error_message = ?, exit_code = ?, updated_at = ?
		WHERE id = ?`), status, actor, now, outputSample, errorMessage, exitCode, now, id)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return K8sPodExecSession{}, ErrNotFound
	}
	return s.GetK8sPodExecSession(ctx, id)
}

func scanK8sPodExecSession(rows k8sClusterScanner) (K8sPodExecSession, error) {
	var sess K8sPodExecSession
	var requireApproval, auditEnabled int
	if err := rows.Scan(&sess.ID, &sess.ClusterID, &sess.Namespace, &sess.Pod, &sess.Container, &sess.Command, &sess.Role, &sess.RequestedBy, &sess.Status, &sess.RiskLevel,
		&requireApproval, &auditEnabled, &sess.MaxSessionMinutes, &sess.PolicyResult, &sess.Reason,
		&sess.DecidedBy, &sess.DecidedAt, &sess.DecisionNote, &sess.ExecutedBy, &sess.ExecutedAt, &sess.OutputSample, &sess.ErrorMessage, &sess.ExitCode,
		&sess.CreatedAt, &sess.UpdatedAt); err != nil {
		return K8sPodExecSession{}, err
	}
	sess.RequireApproval = requireApproval != 0
	sess.AuditEnabled = auditEnabled != 0
	return sess, nil
}
