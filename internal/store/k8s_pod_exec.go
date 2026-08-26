package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
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

type K8sTerminalTicket struct {
	SessionID     string
	AdminID       string
	ClaimID       string
	AuthSessionID string
	AuthExpiresAt time.Time
	ClientIP      string
	UserAgentHash string
	ExpiresAt     time.Time
}

func terminalTicketHash(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:])
}

// k8sPodExecTimePredicate compares RFC3339 timestamps as timestamps rather than
// variable-width TEXT. In particular, RFC3339Nano renders an exact second as
// "...:00Z" and a fractional instant as "...:00.5Z", whose lexical ordering is
// the opposite of their chronological ordering around that boundary.
//
// column and comparison are internal SQL fragments, never request input.
func (s *SQLStore) k8sPodExecTimePredicate(column, comparison string) string {
	return s.timestampPredicate(column, comparison)
}

// timestampPredicate builds a dialect-correct comparison between an RFC3339 text
// column and a bound parameter. Timestamps are stored with variable fractional
// precision, so comparing them as plain strings is not reliable; both branches
// convert to a real time value first.
func (s *SQLStore) timestampPredicate(column, comparison string) string {
	switch comparison {
	case ">", "<=":
	default:
		panic("unsupported timestamp comparison")
	}
	if s.dialect == "postgres" {
		return "CAST(NULLIF(" + column + ", '') AS TIMESTAMPTZ) " + comparison + " CAST(? AS TIMESTAMPTZ)"
	}
	return "julianday(NULLIF(" + column + ", '')) " + comparison + " julianday(?)"
}

func (s *SQLStore) deleteExpiredK8sTerminalTickets(ctx context.Context, currentTime time.Time) error {
	query := `DELETE FROM k8s_terminal_tickets WHERE ` + s.k8sPodExecTimePredicate("expires_at", "<=")
	_, err := s.db.ExecContext(ctx, s.bind(query), currentTime.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *SQLStore) CreateK8sTerminalTicket(ctx context.Context, ticket string, value K8sTerminalTicket) error {
	now := time.Now().UTC()
	authExpiresAt := ""
	if !value.AuthExpiresAt.IsZero() {
		authExpiresAt = value.AuthExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	// Retain consumed rows until expiry: another replica may be between its atomic
	// consume update and the identity read that follows.
	_ = s.deleteExpiredK8sTerminalTickets(ctx, now)
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_terminal_tickets
		(ticket_hash, session_id, admin_id, auth_session_id, auth_expires_at, client_ip, user_agent_hash, expires_at, consumed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?)`),
		terminalTicketHash(ticket), value.SessionID, value.AdminID, value.AuthSessionID, authExpiresAt,
		value.ClientIP, value.UserAgentHash, value.ExpiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return err
}

// ConsumeK8sTerminalTicketAndClaimSession atomically consumes one bound browser ticket and
// claims its ready exec session for connection. Keeping both changes in one transaction means
// concurrent replicas can never each open a Kubernetes terminal for the same approved session.
func (s *SQLStore) ConsumeK8sTerminalTicketAndClaimSession(ctx context.Context, sessionID, ticket, clientIP, userAgentHash string) (K8sTerminalTicket, bool, error) {
	return s.consumeK8sTerminalTicketAndClaimSessionAt(ctx, sessionID, ticket, clientIP, userAgentHash, time.Now().UTC())
}

func (s *SQLStore) consumeK8sTerminalTicketAndClaimSessionAt(ctx context.Context, sessionID, ticket, clientIP, userAgentHash string, currentTime time.Time) (K8sTerminalTicket, bool, error) {
	now := currentTime.UTC().Format(time.RFC3339Nano)
	hash := terminalTicketHash(ticket)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return K8sTerminalTicket{}, false, err
	}
	defer tx.Rollback()
	ticketExpiry := s.k8sPodExecTimePredicate("expires_at", ">")
	authExpiry := s.k8sPodExecTimePredicate("auth_expires_at", ">")
	sessionExpiry := s.k8sPodExecTimePredicate("auth.expires_at", ">")
	consumeQuery := `UPDATE k8s_terminal_tickets
		SET consumed_at = ?
		WHERE ticket_hash = ? AND session_id = ? AND consumed_at = '' AND ` + ticketExpiry + `
		  AND client_ip = ? AND user_agent_hash = ?
		  AND (auth_expires_at = '' OR ` + authExpiry + `)
		  AND (auth_session_id = '' OR EXISTS (
			SELECT 1 FROM auth_sessions auth
			JOIN users usr ON usr.id = auth.user_id
			WHERE auth.id = k8s_terminal_tickets.auth_session_id
			  AND COALESCE(auth.revoked_at, '') = '' AND ` + sessionExpiry + `
			  AND usr.status = 'active' AND COALESCE(usr.must_change_password, 0) = 0
		  ))`
	res, err := tx.ExecContext(ctx, s.bind(consumeQuery),
		now, hash, sessionID, now, clientIP, userAgentHash, now, now)
	if err != nil {
		return K8sTerminalTicket{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return K8sTerminalTicket{}, false, err
	}
	var value K8sTerminalTicket
	var expiresAt, authExpiresAt string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT session_id, admin_id, auth_session_id, auth_expires_at, client_ip, user_agent_hash, expires_at
		FROM k8s_terminal_tickets WHERE ticket_hash = ?`), hash).Scan(
		&value.SessionID, &value.AdminID, &value.AuthSessionID, &authExpiresAt, &value.ClientIP, &value.UserAgentHash, &expiresAt)
	if err != nil {
		return K8sTerminalTicket{}, false, err
	}
	value.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return K8sTerminalTicket{}, false, err
	}
	if authExpiresAt != "" {
		value.AuthExpiresAt, err = time.Parse(time.RFC3339Nano, authExpiresAt)
		if err != nil {
			return K8sTerminalTicket{}, false, err
		}
	}
	value.ClaimID = hash
	res, err = tx.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = 'connecting', connection_claim_id = ?, executed_by = ?, executed_at = ?, updated_at = ?
		WHERE id = ? AND status = 'ready'`), hash, value.AdminID, now, now, sessionID)
	if err != nil {
		return K8sTerminalTicket{}, false, err
	}
	n, err = res.RowsAffected()
	if err != nil || n != 1 {
		return K8sTerminalTicket{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return K8sTerminalTicket{}, false, err
	}
	return value, true, nil
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

// ListK8sPodExecSessionsForRecovery returns the oldest transport-owned
// sessions first so a bounded reaper cannot starve an old crashed session
// behind newer interactive connections.
func (s *SQLStore) ListK8sPodExecSessionsForRecovery(ctx context.Context, limit int) ([]K8sPodExecSession, error) {
	recoveryDeadline := `julianday(NULLIF(updated_at, '')) +
		((CASE WHEN max_session_minutes > 0 THEN max_session_minutes ELSE 1 END * 60.0 + 30.0) / 86400.0)`
	if s.dialect == "postgres" {
		recoveryDeadline = `CAST(NULLIF(updated_at, '') AS TIMESTAMPTZ) +
			(CASE WHEN max_session_minutes > 0 THEN max_session_minutes ELSE 1 END * INTERVAL '1 minute') +
			INTERVAL '30 seconds'`
	}
	query := `SELECT id, cluster_id, namespace, pod, container, command, role, requested_by, status, risk_level,
		require_approval, audit_enabled, max_session_minutes, COALESCE(policy_result, '{}'), COALESCE(reason, ''),
		COALESCE(decided_by, ''), COALESCE(decided_at, ''), COALESCE(decision_note, ''),
		COALESCE(executed_by, ''), COALESCE(executed_at, ''), COALESCE(output_sample, ''), COALESCE(error_message, ''), COALESCE(exit_code, 0),
		created_at, updated_at
		FROM k8s_pod_exec_sessions
		WHERE status IN ('connecting', 'running')
		ORDER BY ` + recoveryDeadline + ` ASC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, s.bind(query), boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodExecSession{}
	for rows.Next() {
		sess, scanErr := scanK8sPodExecSession(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// ExpireStaleK8sPodExecSession fences a crashed transport using the exact
// snapshot observed by the reaper. A live owner that refreshed or finalized
// the row wins the CAS and cannot be overwritten.
func (s *SQLStore) ExpireStaleK8sPodExecSession(ctx context.Context, id, expectedStatus, expectedUpdatedAt, reason string) (bool, error) {
	if expectedStatus != "connecting" && expectedStatus != "running" {
		return false, ErrInvalidTransition
	}
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status='failed', connection_claim_id='', error_message=?, exit_code=124, updated_at=?
		WHERE id=? AND status=? AND updated_at=?`),
		reason, now, id, expectedStatus, expectedUpdatedAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
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
	if status != "ready" && status != "rejected" {
		return K8sPodExecSession{}, ErrInvalidTransition
	}
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = ?, decided_by = ?, decided_at = ?, decision_note = ?, updated_at = ?
		WHERE id = ? AND status = 'pending_approval'`), status, actor, now, note, now, id)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sPodExecSession(ctx, id); getErr == nil {
			return K8sPodExecSession{}, ErrInvalidTransition
		}
		return K8sPodExecSession{}, ErrNotFound
	}
	return s.GetK8sPodExecSession(ctx, id)
}

func (s *SQLStore) MarkK8sPodExecSessionRunning(ctx context.Context, id, actor string) (K8sPodExecSession, error) {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = 'running', executed_by = ?, executed_at = ?, updated_at = ?
		WHERE id = ? AND status = 'ready'`), actor, now, now, id)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sPodExecSession(ctx, id); getErr == nil {
			return K8sPodExecSession{}, ErrInvalidTransition
		}
		return K8sPodExecSession{}, ErrNotFound
	}
	return s.GetK8sPodExecSession(ctx, id)
}

func (s *SQLStore) MarkK8sPodExecSessionConnecting(ctx context.Context, id, actor, claimID string) (K8sPodExecSession, error) {
	if claimID == "" {
		return K8sPodExecSession{}, ErrInvalidTransition
	}
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = 'connecting', connection_claim_id = ?, executed_by = ?, executed_at = ?, updated_at = ?
		WHERE id = ? AND status = 'ready'`), claimID, actor, now, now, id)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sPodExecSession(ctx, id); getErr == nil {
			return K8sPodExecSession{}, ErrInvalidTransition
		}
		return K8sPodExecSession{}, ErrNotFound
	}
	return s.GetK8sPodExecSession(ctx, id)
}

func (s *SQLStore) MarkK8sPodExecSessionConnected(ctx context.Context, id, claimID string) (K8sPodExecSession, error) {
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = 'running', updated_at = ?
		WHERE id = ? AND status = 'connecting' AND connection_claim_id = ?`), now, id, claimID)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sPodExecSession(ctx, id); getErr == nil {
			return K8sPodExecSession{}, ErrInvalidTransition
		}
		return K8sPodExecSession{}, ErrNotFound
	}
	return s.GetK8sPodExecSession(ctx, id)
}

// RecoverStaleK8sPodExecSessionConnection releases a fenced connection claim only after its
// full session timeout has elapsed. A late process still holding the old claim cannot mark the
// recovered (or newly claimed) session running because every terminal transition checks claimID.
func (s *SQLStore) RecoverStaleK8sPodExecSessionConnection(ctx context.Context, id string, staleBefore time.Time) (bool, error) {
	now := nowString()
	stalePredicate := s.k8sPodExecTimePredicate("updated_at", "<=")
	query := `UPDATE k8s_pod_exec_sessions
		SET status = 'ready', connection_claim_id = '', executed_by = '', executed_at = '', updated_at = ?
		WHERE id = ? AND status = 'connecting' AND ` + stalePredicate
	res, err := s.db.ExecContext(ctx, s.bind(query),
		now, id, staleBefore.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *SQLStore) UpdateK8sPodTerminalSessionExecution(ctx context.Context, id, claimID, status, actor, outputSample, errorMessage string, exitCode int) (K8sPodExecSession, error) {
	if claimID == "" || (status != "completed" && status != "failed") {
		return K8sPodExecSession{}, ErrInvalidTransition
	}
	currentStatus := `status = 'running'`
	if status == "failed" {
		currentStatus = `status IN ('connecting', 'running')`
	}
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = ?, connection_claim_id = '', executed_by = ?, executed_at = ?, output_sample = ?, error_message = ?, exit_code = ?, updated_at = ?
		WHERE id = ? AND connection_claim_id = ? AND `+currentStatus),
		status, actor, now, outputSample, errorMessage, exitCode, now, id, claimID)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sPodExecSession(ctx, id); getErr == nil {
			return K8sPodExecSession{}, ErrInvalidTransition
		}
		return K8sPodExecSession{}, ErrNotFound
	}
	return s.GetK8sPodExecSession(ctx, id)
}

func (s *SQLStore) UpdateK8sPodExecSessionExecution(ctx context.Context, id, status, actor, outputSample, errorMessage string, exitCode int) (K8sPodExecSession, error) {
	if status != "completed" && status != "failed" {
		return K8sPodExecSession{}, ErrInvalidTransition
	}
	now := nowString()
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_exec_sessions
		SET status = ?, executed_by = ?, executed_at = ?, output_sample = ?, error_message = ?, exit_code = ?, updated_at = ?
		WHERE id = ? AND status = 'running'`), status, actor, now, outputSample, errorMessage, exitCode, now, id)
	if err != nil {
		return K8sPodExecSession{}, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sPodExecSession(ctx, id); getErr == nil {
			return K8sPodExecSession{}, ErrInvalidTransition
		}
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
