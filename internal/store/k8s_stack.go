package store

import (
	"context"
	"database/sql"
)

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// K8sApplicationStack is a named, versioned deploy unit (a manifest bundle) — the Portainer-style
// "stack". Persistence + revisions are the backbone for apply / rollback / GitOps drift.
type K8sApplicationStack struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ClusterID    string `json:"cluster_id"`
	Namespace    string `json:"namespace"`
	SourceType   string `json:"source_type"` // manifest | git
	Manifest     string `json:"manifest"`
	ManifestHash string `json:"manifest_hash"`
	GitRepo      string `json:"git_repo"`
	GitBranch    string `json:"git_branch"`
	GitPath      string `json:"git_path"`
	SyncPolicy   string `json:"sync_policy"` // manual | auto | approval
	Status       string `json:"status"`      // saved | applied | drifted
	RevisionNo   int    `json:"revision_no"`
	CreatedBy    string `json:"created_by"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// K8sStackRevision is one immutable version of a stack's manifest.
type K8sStackRevision struct {
	ID           string `json:"id"`
	StackID      string `json:"stack_id"`
	RevisionNo   int    `json:"revision_no"`
	ManifestHash string `json:"manifest_hash"`
	Manifest     string `json:"manifest"`
	Note         string `json:"note"`
	CreatedBy    string `json:"created_by"`
	CreatedAt    string `json:"created_at"`
}

// UpsertK8sStack creates or updates a stack. When the manifest hash changes (or on first save) it
// bumps the revision number and appends an immutable revision. Returns the resulting stack.
func (s *SQLStore) UpsertK8sStack(ctx context.Context, st K8sApplicationStack, newID func(string) string) (K8sApplicationStack, bool, error) {
	now := nowString()
	existing, err := s.GetK8sStack(ctx, st.ID)
	isNew := err == ErrNotFound || st.ID == ""
	if err != nil && err != ErrNotFound {
		return K8sApplicationStack{}, false, err
	}
	if st.ID == "" {
		st.ID = newID("k8sstack")
	}
	changed := isNew || existing.ManifestHash != st.ManifestHash
	st.RevisionNo = existing.RevisionNo
	if changed {
		st.RevisionNo++
	}
	if st.CreatedAt == "" {
		st.CreatedAt = coalesce(existing.CreatedAt, now)
	}
	st.UpdatedAt = now
	if st.Status == "" {
		st.Status = coalesce(existing.Status, "saved")
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_application_stacks
		(id, name, cluster_id, namespace, source_type, manifest, manifest_hash, git_repo, git_branch, git_path, sync_policy, status, revision_no, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name, cluster_id = excluded.cluster_id, namespace = excluded.namespace,
			source_type = excluded.source_type, manifest = excluded.manifest, manifest_hash = excluded.manifest_hash,
			git_repo = excluded.git_repo, git_branch = excluded.git_branch, git_path = excluded.git_path,
			sync_policy = excluded.sync_policy, status = excluded.status, revision_no = excluded.revision_no,
			updated_at = excluded.updated_at`),
		st.ID, st.Name, st.ClusterID, st.Namespace, st.SourceType, st.Manifest, st.ManifestHash,
		st.GitRepo, st.GitBranch, st.GitPath, st.SyncPolicy, st.Status, st.RevisionNo, st.CreatedBy, st.CreatedAt, st.UpdatedAt)
	if err != nil {
		return K8sApplicationStack{}, false, err
	}
	if changed {
		_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_stack_revisions
			(id, stack_id, revision_no, manifest_hash, manifest, note, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			newID("k8sstackrev"), st.ID, st.RevisionNo, st.ManifestHash, st.Manifest, "", st.CreatedBy, now)
		if err != nil {
			return K8sApplicationStack{}, false, err
		}
	}
	return st, isNew, nil
}

func (s *SQLStore) GetK8sStack(ctx context.Context, id string) (K8sApplicationStack, error) {
	if id == "" {
		return K8sApplicationStack{}, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, name, cluster_id, namespace, source_type, manifest, manifest_hash,
		git_repo, git_branch, git_path, sync_policy, status, revision_no, created_by, created_at, updated_at
		FROM k8s_application_stacks WHERE id = ?`), id)
	var st K8sApplicationStack
	if err := row.Scan(&st.ID, &st.Name, &st.ClusterID, &st.Namespace, &st.SourceType, &st.Manifest, &st.ManifestHash,
		&st.GitRepo, &st.GitBranch, &st.GitPath, &st.SyncPolicy, &st.Status, &st.RevisionNo, &st.CreatedBy, &st.CreatedAt, &st.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return K8sApplicationStack{}, ErrNotFound
		}
		return K8sApplicationStack{}, err
	}
	return st, nil
}

func (s *SQLStore) ListK8sStacks(ctx context.Context, clusterID string) ([]K8sApplicationStack, error) {
	query := `SELECT id, name, cluster_id, namespace, source_type, manifest, manifest_hash,
		git_repo, git_branch, git_path, sync_policy, status, revision_no, created_by, created_at, updated_at
		FROM k8s_application_stacks`
	args := []any{}
	if clusterID != "" {
		query += ` WHERE cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sApplicationStack{}
	for rows.Next() {
		var st K8sApplicationStack
		if err := rows.Scan(&st.ID, &st.Name, &st.ClusterID, &st.Namespace, &st.SourceType, &st.Manifest, &st.ManifestHash,
			&st.GitRepo, &st.GitBranch, &st.GitPath, &st.SyncPolicy, &st.Status, &st.RevisionNo, &st.CreatedBy, &st.CreatedAt, &st.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sStackRevisions(ctx context.Context, stackID string, limit int) ([]K8sStackRevision, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, stack_id, revision_no, manifest_hash, manifest, note, created_by, created_at
		FROM k8s_stack_revisions WHERE stack_id = ? ORDER BY revision_no DESC LIMIT ?`), stackID, boundedLimit(limit, 50, 500))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sStackRevision{}
	for rows.Next() {
		var rev K8sStackRevision
		if err := rows.Scan(&rev.ID, &rev.StackID, &rev.RevisionNo, &rev.ManifestHash, &rev.Manifest, &rev.Note, &rev.CreatedBy, &rev.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteK8sStack(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_stack_revisions WHERE stack_id = ?`), id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_application_stacks WHERE id = ?`), id)
	return err
}
