package store

import (
	"context"
	"database/sql"
)

// K8s API Discovery + OpenAPI Schema Registry (CLU-DISC-04/05).

// K8sAPIResource is one discovered API resource for a cluster (the resource catalog).
type K8sAPIResource struct {
	ClusterID    string `json:"cluster_id"`
	GroupName    string `json:"group"`
	Version      string `json:"version"`
	Resource     string `json:"resource"`
	Kind         string `json:"kind"`
	Namespaced   bool   `json:"namespaced"`
	Listable     bool   `json:"listable"`
	Verbs        string `json:"verbs"`        // comma-joined
	ShortNames   string `json:"short_names"`  // comma-joined
	Categories   string `json:"categories"`   // comma-joined
	IsCRD        bool   `json:"is_crd"`       // group contains a dot (DNS-style) → CRD/aggregated
	CollectedAt  string `json:"collected_at"`
}

// K8sOpenAPIDocument indexes one group/version OpenAPI v3 document (schema registry).
type K8sOpenAPIDocument struct {
	ClusterID         string `json:"cluster_id"`
	GroupVersion      string `json:"group_version"`
	ServerRelativeURL string `json:"server_relative_url"`
	SchemaHash        string `json:"schema_hash"`
	CollectedAt       string `json:"collected_at"`
}

// K8sDiscoverySnapshot is the per-collect outcome record (freshness / audit).
type K8sDiscoverySnapshot struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	ResourceCount int    `json:"resource_count"`
	DocumentCount int    `json:"document_count"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	CollectedAt   string `json:"collected_at"`
}

// ReplaceK8sAPIResources atomically replaces a cluster's resource catalog with a fresh discovery.
func (s *SQLStore) ReplaceK8sAPIResources(ctx context.Context, clusterID string, items []K8sAPIResource) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM k8s_api_resources WHERE cluster_id = ?`), clusterID); err != nil {
		return err
	}
	now := nowString()
	for _, it := range items {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_api_resources
			(cluster_id, group_name, version, resource, kind, namespaced, listable, verbs, short_names, categories, is_crd, collected_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			clusterID, it.GroupName, it.Version, it.Resource, it.Kind, boolInt(it.Namespaced), boolInt(it.Listable),
			it.Verbs, it.ShortNames, it.Categories, boolInt(it.IsCRD), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListK8sAPIResources returns a cluster's resource catalog (group/version/resource order).
func (s *SQLStore) ListK8sAPIResources(ctx context.Context, clusterID string) ([]K8sAPIResource, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT cluster_id, group_name, version, resource, kind, namespaced,
		listable, verbs, short_names, categories, is_crd, collected_at FROM k8s_api_resources
		WHERE cluster_id = ? ORDER BY group_name, version, resource`), clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sAPIResource{}
	for rows.Next() {
		var r K8sAPIResource
		var ns, listable, crd int
		if err := rows.Scan(&r.ClusterID, &r.GroupName, &r.Version, &r.Resource, &r.Kind, &ns, &listable,
			&r.Verbs, &r.ShortNames, &r.Categories, &crd, &r.CollectedAt); err != nil {
			return nil, err
		}
		r.Namespaced, r.Listable, r.IsCRD = ns != 0, listable != 0, crd != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReplaceK8sOpenAPIDocuments atomically replaces a cluster's OpenAPI document index.
func (s *SQLStore) ReplaceK8sOpenAPIDocuments(ctx context.Context, clusterID string, docs []K8sOpenAPIDocument) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM k8s_openapi_documents WHERE cluster_id = ?`), clusterID); err != nil {
		return err
	}
	now := nowString()
	for _, d := range docs {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_openapi_documents
			(cluster_id, group_version, server_relative_url, schema_hash, collected_at)
			VALUES (?, ?, ?, ?, ?)`),
			clusterID, d.GroupVersion, d.ServerRelativeURL, d.SchemaHash, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListK8sOpenAPIDocuments returns a cluster's OpenAPI document index.
func (s *SQLStore) ListK8sOpenAPIDocuments(ctx context.Context, clusterID string) ([]K8sOpenAPIDocument, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT cluster_id, group_version, server_relative_url, schema_hash, collected_at
		FROM k8s_openapi_documents WHERE cluster_id = ? ORDER BY group_version`), clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sOpenAPIDocument{}
	for rows.Next() {
		var d K8sOpenAPIDocument
		if err := rows.Scan(&d.ClusterID, &d.GroupVersion, &d.ServerRelativeURL, &d.SchemaHash, &d.CollectedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordK8sDiscoverySnapshot appends a discovery-collect outcome.
func (s *SQLStore) RecordK8sDiscoverySnapshot(ctx context.Context, snap K8sDiscoverySnapshot) error {
	if snap.CollectedAt == "" {
		snap.CollectedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_api_discovery_snapshots
		(id, cluster_id, resource_count, document_count, ok, error, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		snap.ID, snap.ClusterID, snap.ResourceCount, snap.DocumentCount, boolInt(snap.OK), snap.Error, snap.CollectedAt)
	return err
}

// LatestK8sDiscoverySnapshot returns the most recent discovery snapshot for a cluster.
func (s *SQLStore) LatestK8sDiscoverySnapshot(ctx context.Context, clusterID string) (K8sDiscoverySnapshot, bool, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, resource_count, document_count, ok, error, collected_at
		FROM k8s_api_discovery_snapshots WHERE cluster_id = ? ORDER BY collected_at DESC, id DESC LIMIT 1`), clusterID)
	var snap K8sDiscoverySnapshot
	var ok int
	if err := row.Scan(&snap.ID, &snap.ClusterID, &snap.ResourceCount, &snap.DocumentCount, &ok, &snap.Error, &snap.CollectedAt); err != nil {
		if err == sql.ErrNoRows {
			return K8sDiscoverySnapshot{}, false, nil
		}
		return K8sDiscoverySnapshot{}, false, err
	}
	snap.OK = ok != 0
	return snap, true, nil
}
