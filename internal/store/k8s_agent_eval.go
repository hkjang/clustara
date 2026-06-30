package store

import (
	"context"
	"database/sql"
)

// Ops Agent Evaluation Center (CLU-REQ-02/03): every agent answer records what intent it served,
// which tools it planned/used, how many evidence lines grounded it, response latency, whether it
// fell back to the deterministic summary, a grounding score (CLU-REQ-03), and the operator's
// thumbs feedback. This turns the floating agent's behaviour into measurable quality signals.
type K8sAgentEvaluation struct {
	ID              string  `json:"id"`
	SessionID       string  `json:"session_id"`
	MessageID       string  `json:"message_id"`
	Intent          string  `json:"intent"`
	PageContext     string  `json:"page_context"` // JSON snapshot
	ToolPlan        string  `json:"tool_plan"`    // JSON []AgentToolCall
	UsedAPIs        string  `json:"used_apis"`    // JSON []string
	EvidenceCount   int     `json:"evidence_count"`
	ResponseMS      int64   `json:"response_ms"`
	Fallback        bool    `json:"fallback"`
	LLMAvailable    bool    `json:"llm_available"`
	GroundingScore  float64 `json:"grounding_score"`  // 0–100 (CLU-REQ-03)
	GroundingDetail string  `json:"grounding_detail"` // JSON breakdown
	ActionCardID    string  `json:"action_card_id"`   // link to a proposed card, if any
	Feedback        string  `json:"feedback"`         // '' | up | down
	FeedbackNote    string  `json:"feedback_note"`
	CreatedAt       string  `json:"created_at"`
}

// K8sAgentEvalFilter narrows an evaluation listing.
type K8sAgentEvalFilter struct {
	SessionID string
	Intent    string
	Limit     int
}

// K8sAgentEvalStats is the aggregate quality summary for the Evaluation Center dashboard.
type K8sAgentEvalStats struct {
	Total           int     `json:"total"`
	LLMAnswers      int     `json:"llm_answers"`
	Fallbacks       int     `json:"fallbacks"`
	ThumbsUp        int     `json:"thumbs_up"`
	ThumbsDown      int     `json:"thumbs_down"`
	AvgGrounding    float64 `json:"avg_grounding"`
	AvgResponseMS   float64 `json:"avg_response_ms"`
	AvgEvidence     float64 `json:"avg_evidence"`
	ActionsProposed int     `json:"actions_proposed"`
}

func (s *SQLStore) InsertK8sAgentEvaluation(ctx context.Context, e K8sAgentEvaluation) error {
	if e.CreatedAt == "" {
		e.CreatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_agent_evaluations
		(id, session_id, message_id, intent, page_context, tool_plan, used_apis, evidence_count,
		 response_ms, fallback, llm_available, grounding_score, grounding_detail, action_card_id,
		 feedback, feedback_note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, e.SessionID, e.MessageID, e.Intent, e.PageContext, e.ToolPlan, e.UsedAPIs, e.EvidenceCount,
		e.ResponseMS, boolInt(e.Fallback), boolInt(e.LLMAvailable), e.GroundingScore, e.GroundingDetail,
		e.ActionCardID, e.Feedback, e.FeedbackNote, e.CreatedAt)
	return err
}

// SetK8sAgentEvaluationFeedback records the operator's thumbs feedback for an answer.
func (s *SQLStore) SetK8sAgentEvaluationFeedback(ctx context.Context, id, feedback, note string) error {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_agent_evaluations SET feedback = ?, feedback_note = ? WHERE id = ?`),
		feedback, note, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanK8sAgentEvaluation(rows k8sClusterScanner) (K8sAgentEvaluation, error) {
	var e K8sAgentEvaluation
	var fallback, llm int
	if err := rows.Scan(&e.ID, &e.SessionID, &e.MessageID, &e.Intent, &e.PageContext, &e.ToolPlan,
		&e.UsedAPIs, &e.EvidenceCount, &e.ResponseMS, &fallback, &llm, &e.GroundingScore,
		&e.GroundingDetail, &e.ActionCardID, &e.Feedback, &e.FeedbackNote, &e.CreatedAt); err != nil {
		return K8sAgentEvaluation{}, err
	}
	e.Fallback = fallback != 0
	e.LLMAvailable = llm != 0
	return e, nil
}

const k8sAgentEvalColumns = `id, session_id, message_id, intent, page_context, tool_plan, used_apis,
	evidence_count, response_ms, fallback, llm_available, grounding_score, grounding_detail,
	action_card_id, feedback, feedback_note, created_at`

func (s *SQLStore) ListK8sAgentEvaluations(ctx context.Context, f K8sAgentEvalFilter) ([]K8sAgentEvaluation, error) {
	query := `SELECT ` + k8sAgentEvalColumns + ` FROM k8s_agent_evaluations WHERE 1=1`
	args := []any{}
	if f.SessionID != "" {
		query += ` AND session_id = ?`
		args = append(args, f.SessionID)
	}
	if f.Intent != "" {
		query += ` AND intent = ?`
		args = append(args, f.Intent)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sAgentEvaluation{}
	for rows.Next() {
		e, err := scanK8sAgentEvaluation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// K8sAgentEvalStatsByIntent groups the aggregate stats by intent for the dashboard breakdown.
type K8sAgentEvalIntentStat struct {
	Intent       string  `json:"intent"`
	Count        int     `json:"count"`
	AvgGrounding float64 `json:"avg_grounding"`
	ThumbsUp     int     `json:"thumbs_up"`
	ThumbsDown   int     `json:"thumbs_down"`
}

// K8sAgentEvalStats returns the overall quality aggregates plus a per-intent breakdown.
func (s *SQLStore) K8sAgentEvalStats(ctx context.Context) (K8sAgentEvalStats, []K8sAgentEvalIntentStat, error) {
	var st K8sAgentEvalStats
	row := s.db.QueryRowContext(ctx, `SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN llm_available <> 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN fallback <> 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN feedback = 'up' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN feedback = 'down' THEN 1 ELSE 0 END), 0),
		COALESCE(AVG(grounding_score), 0),
		COALESCE(AVG(response_ms), 0),
		COALESCE(AVG(evidence_count), 0),
		COALESCE(SUM(CASE WHEN action_card_id <> '' THEN 1 ELSE 0 END), 0)
		FROM k8s_agent_evaluations`)
	if err := row.Scan(&st.Total, &st.LLMAnswers, &st.Fallbacks, &st.ThumbsUp, &st.ThumbsDown,
		&st.AvgGrounding, &st.AvgResponseMS, &st.AvgEvidence, &st.ActionsProposed); err != nil {
		return st, nil, err
	}
	st.AvgGrounding = round1f(st.AvgGrounding)
	st.AvgResponseMS = round1f(st.AvgResponseMS)
	st.AvgEvidence = round1f(st.AvgEvidence)

	rows, err := s.db.QueryContext(ctx, `SELECT intent, COUNT(*), COALESCE(AVG(grounding_score), 0),
		COALESCE(SUM(CASE WHEN feedback = 'up' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN feedback = 'down' THEN 1 ELSE 0 END), 0)
		FROM k8s_agent_evaluations GROUP BY intent ORDER BY COUNT(*) DESC`)
	if err != nil {
		return st, nil, err
	}
	defer rows.Close()
	byIntent := []K8sAgentEvalIntentStat{}
	for rows.Next() {
		var is K8sAgentEvalIntentStat
		if err := rows.Scan(&is.Intent, &is.Count, &is.AvgGrounding, &is.ThumbsUp, &is.ThumbsDown); err != nil {
			return st, nil, err
		}
		is.AvgGrounding = round1f(is.AvgGrounding)
		byIntent = append(byIntent, is)
	}
	return st, byIntent, rows.Err()
}

// GetK8sAgentEvaluation fetches one evaluation by id.
func (s *SQLStore) GetK8sAgentEvaluation(ctx context.Context, id string) (K8sAgentEvaluation, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT `+k8sAgentEvalColumns+` FROM k8s_agent_evaluations WHERE id = ?`), id)
	e, err := scanK8sAgentEvaluation(row)
	if err == sql.ErrNoRows {
		return K8sAgentEvaluation{}, ErrNotFound
	}
	return e, err
}

func round1f(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
