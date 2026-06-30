package store

import (
	"context"
	"database/sql"
)

// Floating Ops Agent conversation: a session carries the screen-context snapshot and an ordered
// message history (user questions + grounded agent answers), so the embedded agent keeps context
// as the operator moves between screens.
type K8sAgentSession struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Route     string `json:"route"`
	Context   string `json:"context"` // JSON snapshot of the page context
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// K8sAgentMessage is one turn in an agent session.
type K8sAgentMessage struct {
	ID           string `json:"id"`
	SessionID    string `json:"session_id"`
	Role         string `json:"role"` // user | agent
	Content      string `json:"content"`
	Intent       string `json:"intent"`
	Evidence     string `json:"evidence"` // JSON array of grounding evidence lines
	LLMAvailable bool   `json:"llm_available"`
	CreatedAt    string `json:"created_at"`
}

func (s *SQLStore) CreateK8sAgentSession(ctx context.Context, sess K8sAgentSession) error {
	now := nowString()
	if sess.CreatedAt == "" {
		sess.CreatedAt = now
	}
	sess.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_agent_sessions
		(id, user_id, route, context, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		sess.ID, sess.UserID, sess.Route, sess.Context, sess.Title, sess.CreatedAt, sess.UpdatedAt)
	return err
}

func (s *SQLStore) GetK8sAgentSession(ctx context.Context, id string) (K8sAgentSession, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, user_id, route, context, title, created_at, updated_at
		FROM k8s_agent_sessions WHERE id = ?`), id)
	var sess K8sAgentSession
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.Route, &sess.Context, &sess.Title, &sess.CreatedAt, &sess.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return K8sAgentSession{}, ErrNotFound
		}
		return K8sAgentSession{}, err
	}
	return sess, nil
}

// UpdateK8sAgentSessionContext refreshes the page-context snapshot + bumps updated_at (the agent
// keeps following the operator's current screen).
func (s *SQLStore) UpdateK8sAgentSessionContext(ctx context.Context, id, route, contextJSON string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_agent_sessions SET route = ?, context = ?, updated_at = ? WHERE id = ?`),
		route, contextJSON, nowString(), id)
	return err
}

func (s *SQLStore) AppendK8sAgentMessage(ctx context.Context, m K8sAgentMessage) error {
	if m.CreatedAt == "" {
		m.CreatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_agent_messages
		(id, session_id, role, content, intent, evidence, llm_available, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		m.ID, m.SessionID, m.Role, m.Content, m.Intent, m.Evidence, boolInt(m.LLMAvailable), m.CreatedAt)
	if err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE k8s_agent_sessions SET updated_at = ? WHERE id = ?`), m.CreatedAt, m.SessionID)
	return err
}

func (s *SQLStore) ListK8sAgentMessages(ctx context.Context, sessionID string, limit int) ([]K8sAgentMessage, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, session_id, role, content, intent, evidence, llm_available, created_at
		FROM k8s_agent_messages WHERE session_id = ? ORDER BY created_at ASC, id ASC LIMIT ?`), sessionID, boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sAgentMessage{}
	for rows.Next() {
		var m K8sAgentMessage
		var llm int
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Role, &m.Content, &m.Intent, &m.Evidence, &llm, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.LLMAvailable = llm != 0
		out = append(out, m)
	}
	return out, rows.Err()
}
