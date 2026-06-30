package store

import (
	"context"
	"database/sql"
)

// Action Card Lifecycle (CLU-REQ-04): the floating agent proposes a remediation as an Action Card.
// Previously these were stateless (built and returned). Now each proposed card is persisted and
// carried through a lifecycle — proposed → pending_approval → approved → executed → (failed) →
// rolled_back — and linked to the Action Center request that actually executes it, so we can track
// whether an AI suggestion turned into a real operational outcome (and whether the issue recurred).
type K8sAgentActionCard struct {
	ID               string `json:"id"`
	SessionID        string `json:"session_id"`
	Action           string `json:"action"`
	Kind             string `json:"kind"`
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Title            string `json:"title"`
	Summary          string `json:"summary"`
	Risk             string `json:"risk"`
	Rollback         string `json:"rollback"`
	RequiresApproval bool   `json:"requires_approval"`
	Executable       bool   `json:"executable"`
	Status           string `json:"status"` // proposed|pending_approval|approved|executed|failed|rolled_back|dismissed
	ActionRequestID  string `json:"action_request_id"`
	Result           string `json:"result"`
	Recurred         bool   `json:"recurred"`
	CreatedBy        string `json:"created_by"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

// agentActionCardTransitions defines the allowed lifecycle state machine. A card may always be
// dismissed unless already in a terminal state.
var agentActionCardTransitions = map[string][]string{
	"proposed":         {"pending_approval", "dismissed"},
	"pending_approval": {"approved", "rejected", "dismissed"},
	"approved":         {"executed", "failed"},
	"failed":           {"pending_approval", "rolled_back", "dismissed"},
	"executed":         {"rolled_back", "recurred"},
	"rejected":         {"dismissed"},
}

// AgentActionCardCanTransition reports whether moving from→to is a valid lifecycle step.
func AgentActionCardCanTransition(from, to string) bool {
	for _, allowed := range agentActionCardTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

func (s *SQLStore) InsertK8sAgentActionCard(ctx context.Context, c K8sAgentActionCard) error {
	now := nowString()
	if c.CreatedAt == "" {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	if c.Status == "" {
		c.Status = "proposed"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_agent_action_cards
		(id, session_id, action, kind, namespace, name, title, summary, risk, rollback,
		 requires_approval, executable, status, action_request_id, result, recurred, created_by,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		c.ID, c.SessionID, c.Action, c.Kind, c.Namespace, c.Name, c.Title, c.Summary, c.Risk, c.Rollback,
		boolInt(c.RequiresApproval), boolInt(c.Executable), c.Status, c.ActionRequestID, c.Result,
		boolInt(c.Recurred), c.CreatedBy, c.CreatedAt, c.UpdatedAt)
	return err
}

func (s *SQLStore) GetK8sAgentActionCard(ctx context.Context, id string) (K8sAgentActionCard, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT `+agentActionCardColumns+` FROM k8s_agent_action_cards WHERE id = ?`), id)
	c, err := scanK8sAgentActionCard(row)
	if err == sql.ErrNoRows {
		return K8sAgentActionCard{}, ErrNotFound
	}
	return c, err
}

const agentActionCardColumns = `id, session_id, action, kind, namespace, name, title, summary, risk,
	rollback, requires_approval, executable, status, action_request_id, result, recurred, created_by,
	created_at, updated_at`

func scanK8sAgentActionCard(rows k8sClusterScanner) (K8sAgentActionCard, error) {
	var c K8sAgentActionCard
	var reqApproval, executable, recurred int
	if err := rows.Scan(&c.ID, &c.SessionID, &c.Action, &c.Kind, &c.Namespace, &c.Name, &c.Title,
		&c.Summary, &c.Risk, &c.Rollback, &reqApproval, &executable, &c.Status, &c.ActionRequestID,
		&c.Result, &recurred, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return K8sAgentActionCard{}, err
	}
	c.RequiresApproval = reqApproval != 0
	c.Executable = executable != 0
	c.Recurred = recurred != 0
	return c, nil
}

// K8sAgentActionCardFilter narrows a card listing.
type K8sAgentActionCardFilter struct {
	SessionID string
	Status    string
	Limit     int
}

func (s *SQLStore) ListK8sAgentActionCards(ctx context.Context, f K8sAgentActionCardFilter) ([]K8sAgentActionCard, error) {
	query := `SELECT ` + agentActionCardColumns + ` FROM k8s_agent_action_cards WHERE 1=1`
	args := []any{}
	if f.SessionID != "" {
		query += ` AND session_id = ?`
		args = append(args, f.SessionID)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sAgentActionCard{}
	for rows.Next() {
		c, err := scanK8sAgentActionCard(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateK8sAgentActionCardStatus advances a card through its lifecycle, validating the transition.
// linkRequestID (optional) records the Action Center request the card was submitted as; result is a
// free-text outcome note. Returns ErrInvalidTransition if the move is not allowed.
func (s *SQLStore) UpdateK8sAgentActionCardStatus(ctx context.Context, id, to, linkRequestID, result string) error {
	card, err := s.GetK8sAgentActionCard(ctx, id)
	if err != nil {
		return err
	}
	if to == "recurred" {
		// recurrence is a flag on an executed card, not a terminal status swap
		_, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_agent_action_cards SET recurred = 1, updated_at = ? WHERE id = ?`),
			nowString(), id)
		return err
	}
	if !AgentActionCardCanTransition(card.Status, to) {
		return ErrInvalidTransition
	}
	query := `UPDATE k8s_agent_action_cards SET status = ?, updated_at = ?`
	args := []any{to, nowString()}
	if linkRequestID != "" {
		query += `, action_request_id = ?`
		args = append(args, linkRequestID)
	}
	if result != "" {
		query += `, result = ?`
		args = append(args, result)
	}
	query += ` WHERE id = ?`
	args = append(args, id)
	_, err = s.db.ExecContext(ctx, s.bind(query), args...)
	return err
}
