package store

import (
	"context"
	"database/sql"
)

// K8sAgentRegressionBaseline is a saved snapshot of the Ops Agent regression suite result, tagged
// with the app version it was captured at, so a later run can be compared to detect quality drops.
type K8sAgentRegressionBaseline struct {
	ID              string  `json:"id"`
	Version         string  `json:"version"`
	Total           int     `json:"total"`
	Passed          int     `json:"passed"`
	PassRate        float64 `json:"pass_rate"`
	IntentAccuracy  float64 `json:"intent_accuracy"`
	AvgToolCoverage float64 `json:"avg_tool_coverage"`
	CreatedBy       string  `json:"created_by"`
	CreatedAt       string  `json:"created_at"`
}

// SaveK8sAgentRegressionBaseline records a new baseline snapshot.
func (s *SQLStore) SaveK8sAgentRegressionBaseline(ctx context.Context, b K8sAgentRegressionBaseline) error {
	if b.CreatedAt == "" {
		b.CreatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_agent_regression_baselines
		(id, version, total, passed, pass_rate, intent_accuracy, avg_tool_coverage, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		b.ID, b.Version, b.Total, b.Passed, b.PassRate, b.IntentAccuracy, b.AvgToolCoverage, b.CreatedBy, b.CreatedAt)
	return err
}

// LatestK8sAgentRegressionBaseline returns the most recent baseline, or ok=false when none exist.
func (s *SQLStore) LatestK8sAgentRegressionBaseline(ctx context.Context) (K8sAgentRegressionBaseline, bool, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, version, total, passed, pass_rate, intent_accuracy,
		avg_tool_coverage, created_by, created_at FROM k8s_agent_regression_baselines
		ORDER BY created_at DESC, id DESC LIMIT 1`))
	var b K8sAgentRegressionBaseline
	err := row.Scan(&b.ID, &b.Version, &b.Total, &b.Passed, &b.PassRate, &b.IntentAccuracy,
		&b.AvgToolCoverage, &b.CreatedBy, &b.CreatedAt)
	if err == sql.ErrNoRows {
		return K8sAgentRegressionBaseline{}, false, nil
	}
	if err != nil {
		return K8sAgentRegressionBaseline{}, false, err
	}
	return b, true, nil
}
