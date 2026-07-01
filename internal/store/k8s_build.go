package store

import (
	"context"
	"database/sql"
)

// Build Job Center — definitions + gated run requests (CLU-NEXT-03/05).
//
// Persists build definitions (git source, Dockerfile, output image, provider) and build-run
// requests whose lifecycle is security-gated by the Dockerfile analysis. Actual build execution
// (Kaniko/BuildKit/Tekton) is a separate infra-dependent phase; runs stay in requested/approved/
// blocked until a runner is wired.
type K8sBuildDefinition struct {
	ID          string `json:"id"`
	ClusterID   string `json:"cluster_id"`
	Name        string `json:"name"`
	GitURL      string `json:"git_url"`
	Branch      string `json:"branch"`
	ContextPath string `json:"context_path"`
	Dockerfile  string `json:"dockerfile"` // inline Dockerfile content (for the security gate)
	OutputImage string `json:"output_image"`
	Provider    string `json:"provider"` // kaniko | buildkit | tekton | job
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type K8sBuildRun struct {
	ID           string `json:"id"`
	DefinitionID string `json:"definition_id"`
	ClusterID    string `json:"cluster_id"`
	Status       string `json:"status"` // requested | blocked | approved | running | succeeded | failed
	Trigger      string `json:"trigger"`
	GateResult   string `json:"gate_result"` // JSON of the Dockerfile gate
	GatePass     bool   `json:"gate_pass"`
	FailureReason string `json:"failure_reason"`
	OutputDigest string `json:"output_digest"`
	RequestedBy  string `json:"requested_by"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

var buildRunTransitions = map[string][]string{
	"requested": {"approved", "blocked", "failed"},
	"approved":  {"running", "failed"},
	"running":   {"succeeded", "failed"},
	"blocked":   {"requested"},
}

func (s *SQLStore) UpsertK8sBuildDefinition(ctx context.Context, d K8sBuildDefinition) error {
	now := nowString()
	if d.CreatedAt == "" {
		d.CreatedAt = now
	}
	d.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_build_definitions
		(id, cluster_id, name, git_url, branch, context_path, dockerfile, output_image, provider, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, git_url=excluded.git_url, branch=excluded.branch,
			context_path=excluded.context_path, dockerfile=excluded.dockerfile, output_image=excluded.output_image,
			provider=excluded.provider, updated_at=excluded.updated_at`),
		d.ID, d.ClusterID, d.Name, d.GitURL, d.Branch, d.ContextPath, d.Dockerfile, d.OutputImage, d.Provider, d.CreatedBy, d.CreatedAt, d.UpdatedAt)
	return err
}

func (s *SQLStore) GetK8sBuildDefinition(ctx context.Context, id string) (K8sBuildDefinition, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, name, git_url, branch, context_path, dockerfile, output_image, provider, created_by, created_at, updated_at FROM k8s_build_definitions WHERE id=?`), id)
	var d K8sBuildDefinition
	if err := row.Scan(&d.ID, &d.ClusterID, &d.Name, &d.GitURL, &d.Branch, &d.ContextPath, &d.Dockerfile, &d.OutputImage, &d.Provider, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return K8sBuildDefinition{}, ErrNotFound
		}
		return K8sBuildDefinition{}, err
	}
	return d, nil
}

func (s *SQLStore) ListK8sBuildDefinitions(ctx context.Context, clusterID string) ([]K8sBuildDefinition, error) {
	query := `SELECT id, cluster_id, name, git_url, branch, context_path, dockerfile, output_image, provider, created_by, created_at, updated_at FROM k8s_build_definitions WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY created_at DESC LIMIT 500`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sBuildDefinition{}
	for rows.Next() {
		var d K8sBuildDefinition
		if err := rows.Scan(&d.ID, &d.ClusterID, &d.Name, &d.GitURL, &d.Branch, &d.ContextPath, &d.Dockerfile, &d.OutputImage, &d.Provider, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateK8sBuildRun(ctx context.Context, run K8sBuildRun) error {
	now := nowString()
	if run.CreatedAt == "" {
		run.CreatedAt = now
	}
	run.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_build_runs
		(id, definition_id, cluster_id, status, trigger, gate_result, gate_pass, failure_reason, output_digest, requested_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		run.ID, run.DefinitionID, run.ClusterID, run.Status, run.Trigger, run.GateResult, boolInt(run.GatePass), run.FailureReason, run.OutputDigest, run.RequestedBy, run.CreatedAt, run.UpdatedAt)
	return err
}

func (s *SQLStore) UpdateK8sBuildRunStatus(ctx context.Context, id, status string) error {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT status FROM k8s_build_runs WHERE id=?`), id)
	var cur string
	if err := row.Scan(&cur); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	allowed := false
	for _, a := range buildRunTransitions[cur] {
		if a == status {
			allowed = true
		}
	}
	if !allowed {
		return ErrInvalidTransition
	}
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_build_runs SET status=?, updated_at=? WHERE id=?`), status, nowString(), id)
	return err
}

func (s *SQLStore) ListK8sBuildRuns(ctx context.Context, definitionID string, limit int) ([]K8sBuildRun, error) {
	query := `SELECT id, definition_id, cluster_id, status, trigger, gate_result, gate_pass, failure_reason, output_digest, requested_by, created_at, updated_at FROM k8s_build_runs WHERE 1=1`
	args := []any{}
	if definitionID != "" {
		query += ` AND definition_id = ?`
		args = append(args, definitionID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 200, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sBuildRun{}
	for rows.Next() {
		var run K8sBuildRun
		var gp int
		if err := rows.Scan(&run.ID, &run.DefinitionID, &run.ClusterID, &run.Status, &run.Trigger, &run.GateResult, &gp, &run.FailureReason, &run.OutputDigest, &run.RequestedBy, &run.CreatedAt, &run.UpdatedAt); err != nil {
			return nil, err
		}
		run.GatePass = gp != 0
		out = append(out, run)
	}
	return out, rows.Err()
}
