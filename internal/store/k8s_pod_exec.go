package store

import "context"

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
		require_approval, audit_enabled, max_session_minutes, COALESCE(policy_result, '{}'), COALESCE(reason, ''), created_at, updated_at
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
		var sess K8sPodExecSession
		var requireApproval, auditEnabled int
		if err := rows.Scan(&sess.ID, &sess.ClusterID, &sess.Namespace, &sess.Pod, &sess.Container, &sess.Command, &sess.Role, &sess.RequestedBy, &sess.Status, &sess.RiskLevel,
			&requireApproval, &auditEnabled, &sess.MaxSessionMinutes, &sess.PolicyResult, &sess.Reason, &sess.CreatedAt, &sess.UpdatedAt); err != nil {
			return nil, err
		}
		sess.RequireApproval = requireApproval != 0
		sess.AuditEnabled = auditEnabled != 0
		out = append(out, sess)
	}
	return out, rows.Err()
}
