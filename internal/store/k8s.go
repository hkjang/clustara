package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type K8sCluster struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	ServerURL         string            `json:"server_url"`
	AuthMode          string            `json:"auth_mode"`
	CredentialRef     string            `json:"credential_ref"`
	GroupID           string            `json:"group_id"`
	Status            string            `json:"status"`
	KubernetesVersion string            `json:"kubernetes_version"`
	NodeCount         int               `json:"node_count"`
	NamespaceCount    int               `json:"namespace_count"`
	Labels            map[string]string `json:"labels"`
	LastConnectedAt   string            `json:"last_connected_at"`
	LastError         string            `json:"last_error"`
	CreatedAt         string            `json:"created_at"`
	UpdatedAt         string            `json:"updated_at"`
}

type K8sClusterCredential struct {
	ID               string `json:"id"`
	ClusterID        string `json:"cluster_id"`
	Kind             string `json:"kind"`
	EncryptedPayload string `json:"-"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type K8sInventoryItem struct {
	ID           string            `json:"id"`
	ClusterID    string            `json:"cluster_id"`
	Kind         string            `json:"kind"`
	Namespace    string            `json:"namespace"`
	Name         string            `json:"name"`
	UID          string            `json:"uid"`
	APIVersion   string            `json:"api_version"`
	Status       string            `json:"status"`
	HealthScore  int               `json:"health_score"`
	RiskLevel    string            `json:"risk_level"`
	Spec         map[string]any    `json:"spec"`
	StatusObject map[string]any    `json:"status_object"` // raw .status (rollout/job/node conditions); kept out of Spec so it never churns the revision hash
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	ObservedAt   string            `json:"observed_at"`
	UpdatedAt    string            `json:"updated_at"`
}

type K8sInventoryFilter struct {
	ClusterID string
	Kind      string
	Namespace string
	Status    string
	Limit     int
}

type K8sEvent struct {
	ID           string `json:"id"`
	ClusterID    string `json:"cluster_id"`
	Namespace    string `json:"namespace"`
	InvolvedKind string `json:"involved_kind"`
	InvolvedName string `json:"involved_name"`
	Reason       string `json:"reason"`
	Type         string `json:"type"`
	Message      string `json:"message"`
	Count        int    `json:"count"`
	Source       string `json:"source"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	CreatedAt    string `json:"created_at"`
}

type K8sMetricSample struct {
	ID            string  `json:"id"`
	ClusterID     string  `json:"cluster_id"`
	Namespace     string  `json:"namespace"`
	ResourceKind  string  `json:"resource_kind"`
	ResourceName  string  `json:"resource_name"`
	CPUMillicores float64 `json:"cpu_millicores"`
	MemoryBytes   float64 `json:"memory_bytes"`
	StorageBytes  float64 `json:"storage_bytes"`
	LatencyMS     float64 `json:"latency_ms"` // request latency from an external source (Prometheus); 0 = unset
	ObservedAt    string  `json:"observed_at"`
}

type K8sSecurityFinding struct {
	ID           string `json:"id"`
	ClusterID    string `json:"cluster_id"`
	Namespace    string `json:"namespace"`
	ResourceKind string `json:"resource_kind"`
	ResourceName string `json:"resource_name"`
	Rule         string `json:"rule"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	Evidence     string `json:"evidence"`
	Status       string `json:"status"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
}

type K8sFindingFilter struct {
	ClusterID string
	Severity  string
	Status    string
	Limit     int
}

type K8sActionRequest struct {
	ID                    string         `json:"id"`
	ClusterID             string         `json:"cluster_id"`
	Namespace             string         `json:"namespace"`
	ResourceKind          string         `json:"resource_kind"`
	ResourceName          string         `json:"resource_name"`
	Action                string         `json:"action"`
	Parameters            map[string]any `json:"parameters"`
	RiskLevel             string         `json:"risk_level"`
	Status                string         `json:"status"`
	RequestedBy           string         `json:"requested_by"`
	ApprovedBy            string         `json:"approved_by"`
	ExecutedBy            string         `json:"executed_by"`
	Result                string         `json:"result"`
	DryRunDiff            string         `json:"dry_run_diff"`
	IdempotencyKey        string         `json:"idempotency_key"`
	TargetUID             string         `json:"target_uid"`
	TargetResourceVersion string         `json:"target_resource_version"`
	CommandHash           string         `json:"command_hash"`
	CreatedAt             string         `json:"created_at"`
	UpdatedAt             string         `json:"updated_at"`
	ApprovedAt            string         `json:"approved_at"`
	ExecutedAt            string         `json:"executed_at"`
}

type K8sActionFilter struct {
	ClusterID string
	Status    string
	Limit     int
}

// K8sResourceRevision is one append-only snapshot of a resource's normalized spec at a
// point in time. A new row is written only when the spec hash differs from the previous
// revision, so the table is the history backbone for Resource Diff, Deployment Timeline,
// Config-change RCA and the change_fact data-warehouse feed.
type K8sResourceRevision struct {
	ID         string         `json:"id"`
	ClusterID  string         `json:"cluster_id"`
	Kind       string         `json:"kind"`
	Namespace  string         `json:"namespace"`
	Name       string         `json:"name"`
	SpecHash   string         `json:"spec_hash"`
	Spec       map[string]any `json:"spec"`
	Replica    int            `json:"replica"`
	ImageSet   string         `json:"image_set"`
	ChangeKind string         `json:"change_kind"` // created | updated
	ObservedAt string         `json:"observed_at"`
	CreatedAt  string         `json:"created_at"`
}

type K8sRevisionFilter struct {
	ClusterID string
	Kind      string
	Namespace string
	Name      string
	Limit     int
}

type K8sCollectorStatus struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	Collector     string `json:"collector"`
	Status        string `json:"status"`
	LastSuccessAt string `json:"last_success_at"`
	LastError     string `json:"last_error"`
	LagSeconds    int    `json:"lag_seconds"`
	UpdatedAt     string `json:"updated_at"`
}

type K8sKindCount struct {
	Kind      string `json:"kind"`
	Count     int64  `json:"count"`
	Unhealthy int64  `json:"unhealthy"`
}

type K8sOverview struct {
	GeneratedAt     string         `json:"generated_at"`
	Clusters        K8sClusterRoll `json:"clusters"`
	Inventory       []K8sKindCount `json:"inventory"`
	WarningEvents24 int64          `json:"warning_events_24h"`
	OpenFindings    int64          `json:"open_findings"`
	PendingActions  int64          `json:"pending_actions"`
}

type K8sClusterRoll struct {
	Total int64 `json:"total"`
	Ready int64 `json:"ready"`
	Risky int64 `json:"risky"`
}

func (s *SQLStore) UpsertK8sCluster(ctx context.Context, c K8sCluster) error {
	now := nowString()
	if c.CreatedAt == "" {
		c.CreatedAt = now
	}
	if c.UpdatedAt == "" {
		c.UpdatedAt = now
	}
	if c.Status == "" {
		c.Status = "unknown"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_clusters
		(id, name, description, server_url, auth_mode, credential_ref, group_id, status, kubernetes_version, node_count, namespace_count, labels_json, last_connected_at, last_error, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			description = excluded.description,
			server_url = excluded.server_url,
			auth_mode = excluded.auth_mode,
			credential_ref = excluded.credential_ref,
			group_id = excluded.group_id,
			status = excluded.status,
			kubernetes_version = excluded.kubernetes_version,
			node_count = excluded.node_count,
			namespace_count = excluded.namespace_count,
			labels_json = excluded.labels_json,
			last_connected_at = excluded.last_connected_at,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at`),
		c.ID, c.Name, c.Description, c.ServerURL, c.AuthMode, c.CredentialRef, c.GroupID, c.Status,
		c.KubernetesVersion, c.NodeCount, c.NamespaceCount, encodeStringMap(c.Labels), c.LastConnectedAt, c.LastError, c.CreatedAt, c.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sClusters(ctx context.Context) ([]K8sCluster, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, COALESCE(description, ''), COALESCE(server_url, ''),
		COALESCE(auth_mode, ''), COALESCE(credential_ref, ''), COALESCE(group_id, ''), COALESCE(status, 'unknown'),
		COALESCE(kubernetes_version, ''), COALESCE(node_count, 0), COALESCE(namespace_count, 0), COALESCE(labels_json, '{}'),
		COALESCE(last_connected_at, ''), COALESCE(last_error, ''), created_at, updated_at
		FROM k8s_clusters ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sCluster{}
	for rows.Next() {
		c, err := scanK8sCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sCluster(ctx context.Context, id string) (K8sCluster, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, name, COALESCE(description, ''), COALESCE(server_url, ''),
		COALESCE(auth_mode, ''), COALESCE(credential_ref, ''), COALESCE(group_id, ''), COALESCE(status, 'unknown'),
		COALESCE(kubernetes_version, ''), COALESCE(node_count, 0), COALESCE(namespace_count, 0), COALESCE(labels_json, '{}'),
		COALESCE(last_connected_at, ''), COALESCE(last_error, ''), created_at, updated_at
		FROM k8s_clusters WHERE id = ?`), id)
	c, err := scanK8sCluster(row)
	if err == sql.ErrNoRows {
		return K8sCluster{}, ErrNotFound
	}
	return c, err
}

func (s *SQLStore) SaveK8sCredential(ctx context.Context, c K8sClusterCredential) error {
	now := nowString()
	if c.CreatedAt == "" {
		c.CreatedAt = now
	}
	if c.UpdatedAt == "" {
		c.UpdatedAt = now
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_cluster_credentials
		(id, cluster_id, kind, encrypted_payload, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id) DO UPDATE SET
			kind = excluded.kind,
			encrypted_payload = excluded.encrypted_payload,
			updated_at = excluded.updated_at`),
		c.ID, c.ClusterID, c.Kind, c.EncryptedPayload, c.CreatedAt, c.UpdatedAt)
	return err
}

func (s *SQLStore) GetK8sCredential(ctx context.Context, clusterID string) (K8sClusterCredential, error) {
	var c K8sClusterCredential
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, kind, encrypted_payload, created_at, updated_at
		FROM k8s_cluster_credentials WHERE cluster_id = ?`), clusterID).
		Scan(&c.ID, &c.ClusterID, &c.Kind, &c.EncryptedPayload, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return K8sClusterCredential{}, ErrNotFound
	}
	return c, err
}

func (s *SQLStore) UpsertK8sInventory(ctx context.Context, item K8sInventoryItem) error {
	now := nowString()
	if item.ObservedAt == "" {
		item.ObservedAt = now
	}
	if item.UpdatedAt == "" {
		item.UpdatedAt = now
	}
	if item.HealthScore <= 0 {
		item.HealthScore = 100
	}
	if item.RiskLevel == "" {
		item.RiskLevel = "low"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_inventory
		(id, cluster_id, kind, namespace, name, uid, api_version, status, health_score, risk_level, spec_json, status_json, labels_json, annotations_json, observed_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, kind, namespace, name) DO UPDATE SET
			uid = excluded.uid,
			api_version = excluded.api_version,
			status = excluded.status,
			health_score = excluded.health_score,
			risk_level = excluded.risk_level,
			spec_json = excluded.spec_json,
			status_json = excluded.status_json,
			labels_json = excluded.labels_json,
			annotations_json = excluded.annotations_json,
			observed_at = excluded.observed_at,
			updated_at = excluded.updated_at`),
		item.ID, item.ClusterID, item.Kind, item.Namespace, item.Name, item.UID, item.APIVersion,
		item.Status, item.HealthScore, item.RiskLevel, encodeAnyMap(item.Spec), encodeAnyMap(item.StatusObject), encodeStringMap(item.Labels),
		encodeStringMap(item.Annotations), item.ObservedAt, item.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sInventory(ctx context.Context, f K8sInventoryFilter) ([]K8sInventoryItem, error) {
	query := `SELECT id, cluster_id, kind, namespace, name, COALESCE(uid, ''), COALESCE(api_version, ''),
		COALESCE(status, ''), health_score, risk_level, COALESCE(spec_json, '{}'), COALESCE(status_json, '{}'), COALESCE(labels_json, '{}'),
		COALESCE(annotations_json, '{}'), observed_at, updated_at FROM k8s_inventory WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Kind != "" {
		query += ` AND lower(kind) = lower(?)`
		args = append(args, f.Kind)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 200, 10000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sInventoryItem{}
	for rows.Next() {
		item, err := scanK8sInventory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListK8sInventoryIdentities returns inventory identities for reconciliation without the
// normal UI/API list cap.
func (s *SQLStore) ListK8sInventoryIdentities(ctx context.Context, clusterID, kind string) ([]K8sInventoryItem, error) {
	query := `SELECT cluster_id, kind, namespace, name FROM k8s_inventory WHERE cluster_id = ?`
	args := []any{clusterID}
	if strings.TrimSpace(kind) != "" {
		query += ` AND lower(kind) = lower(?)`
		args = append(args, kind)
	}
	query += ` ORDER BY kind, namespace, name`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sInventoryItem{}
	for rows.Next() {
		var item K8sInventoryItem
		if err := rows.Scan(&item.ClusterID, &item.Kind, &item.Namespace, &item.Name); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetK8sInventoryItem returns the single current inventory row for a resource identity, or
// ErrNotFound. Used by the Manifest Viewer to assemble a manifest from the latest state.
func (s *SQLStore) GetK8sInventoryItem(ctx context.Context, clusterID, kind, namespace, name string) (K8sInventoryItem, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, kind, namespace, name, COALESCE(uid, ''),
		COALESCE(api_version, ''), COALESCE(status, ''), health_score, risk_level, COALESCE(spec_json, '{}'),
		COALESCE(status_json, '{}'), COALESCE(labels_json, '{}'), COALESCE(annotations_json, '{}'), observed_at, updated_at
		FROM k8s_inventory WHERE cluster_id = ? AND lower(kind) = lower(?) AND namespace = ? AND name = ?`),
		clusterID, kind, namespace, name)
	item, err := scanK8sInventory(row)
	if err == sql.ErrNoRows {
		return K8sInventoryItem{}, ErrNotFound
	}
	return item, err
}

func (s *SQLStore) InsertK8sEvent(ctx context.Context, e K8sEvent) error {
	now := nowString()
	if e.Count <= 0 {
		e.Count = 1
	}
	if e.FirstSeen == "" {
		e.FirstSeen = now
	}
	if e.LastSeen == "" {
		e.LastSeen = e.FirstSeen
	}
	if e.CreatedAt == "" {
		e.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_events
		(id, cluster_id, namespace, involved_kind, involved_name, reason, type, message, count, source, first_seen, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, e.ClusterID, e.Namespace, e.InvolvedKind, e.InvolvedName, e.Reason, e.Type, e.Message,
		e.Count, e.Source, e.FirstSeen, e.LastSeen, e.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sEvents(ctx context.Context, clusterID string, limit int) ([]K8sEvent, error) {
	query := `SELECT id, cluster_id, namespace, involved_kind, involved_name, reason, type, message,
		count, source, first_seen, last_seen, created_at FROM k8s_events WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sEvent{}
	for rows.Next() {
		var e K8sEvent
		if err := rows.Scan(&e.ID, &e.ClusterID, &e.Namespace, &e.InvolvedKind, &e.InvolvedName, &e.Reason,
			&e.Type, &e.Message, &e.Count, &e.Source, &e.FirstSeen, &e.LastSeen, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) InsertK8sMetricSample(ctx context.Context, m K8sMetricSample) error {
	if m.ObservedAt == "" {
		m.ObservedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_metrics_samples
		(id, cluster_id, namespace, resource_kind, resource_name, cpu_millicores, memory_bytes, storage_bytes, latency_ms, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		m.ID, m.ClusterID, m.Namespace, m.ResourceKind, m.ResourceName, m.CPUMillicores, m.MemoryBytes, m.StorageBytes, m.LatencyMS, m.ObservedAt)
	return err
}

// ListK8sMetricSamples returns recent metric samples (newest first) for capacity analysis.
func (s *SQLStore) ListK8sMetricSamples(ctx context.Context, clusterID string, limit int) ([]K8sMetricSample, error) {
	query := `SELECT id, cluster_id, namespace, resource_kind, resource_name, cpu_millicores, memory_bytes, storage_bytes, COALESCE(latency_ms, 0), observed_at
		FROM k8s_metrics_samples WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY observed_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 1000, 5000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sMetricSample{}
	for rows.Next() {
		var m K8sMetricSample
		if err := rows.Scan(&m.ID, &m.ClusterID, &m.Namespace, &m.ResourceKind, &m.ResourceName,
			&m.CPUMillicores, &m.MemoryBytes, &m.StorageBytes, &m.LatencyMS, &m.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertK8sSecurityFinding(ctx context.Context, f K8sSecurityFinding) error {
	now := nowString()
	if f.Status == "" {
		f.Status = "open"
	}
	if f.FirstSeen == "" {
		f.FirstSeen = now
	}
	if f.LastSeen == "" {
		f.LastSeen = now
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_security_findings
		(id, cluster_id, namespace, resource_kind, resource_name, rule, severity, message, evidence, status, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, namespace, resource_kind, resource_name, rule) DO UPDATE SET
			severity = excluded.severity,
			message = excluded.message,
			evidence = excluded.evidence,
			status = excluded.status,
			last_seen = excluded.last_seen`),
		f.ID, f.ClusterID, f.Namespace, f.ResourceKind, f.ResourceName, f.Rule, f.Severity, f.Message,
		f.Evidence, f.Status, f.FirstSeen, f.LastSeen)
	return err
}

func (s *SQLStore) ListK8sSecurityFindings(ctx context.Context, f K8sFindingFilter) ([]K8sSecurityFinding, error) {
	query := `SELECT id, cluster_id, namespace, resource_kind, resource_name, rule, severity,
		message, evidence, status, first_seen, last_seen FROM k8s_security_findings WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Severity != "" {
		query += ` AND severity = ?`
		args = append(args, f.Severity)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sSecurityFinding{}
	for rows.Next() {
		var f K8sSecurityFinding
		if err := rows.Scan(&f.ID, &f.ClusterID, &f.Namespace, &f.ResourceKind, &f.ResourceName, &f.Rule,
			&f.Severity, &f.Message, &f.Evidence, &f.Status, &f.FirstSeen, &f.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *SQLStore) InsertK8sActionRequest(ctx context.Context, a K8sActionRequest) error {
	now := nowString()
	if a.CreatedAt == "" {
		a.CreatedAt = now
	}
	if a.UpdatedAt == "" {
		a.UpdatedAt = now
	}
	if a.RiskLevel == "" {
		a.RiskLevel = "medium"
	}
	if a.Status == "" {
		a.Status = "pending"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_action_requests
		(id, cluster_id, namespace, resource_kind, resource_name, action, parameters_json, risk_level, status,
		requested_by, approved_by, executed_by, result, dry_run_diff, idempotency_key, target_uid, target_resource_version,
		command_hash, created_at, updated_at, approved_at, executed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.ID, a.ClusterID, a.Namespace, a.ResourceKind, a.ResourceName, a.Action, encodeAnyMap(a.Parameters),
		a.RiskLevel, a.Status, a.RequestedBy, a.ApprovedBy, a.ExecutedBy, a.Result, a.DryRunDiff,
		a.IdempotencyKey, a.TargetUID, a.TargetResourceVersion, a.CommandHash,
		a.CreatedAt, a.UpdatedAt, a.ApprovedAt, a.ExecutedAt)
	return err
}

func (s *SQLStore) ListK8sActionRequests(ctx context.Context, f K8sActionFilter) ([]K8sActionRequest, error) {
	query := `SELECT id, cluster_id, namespace, resource_kind, resource_name, action, parameters_json,
		risk_level, status, requested_by, approved_by, executed_by, result, dry_run_diff,
		COALESCE(idempotency_key, ''), COALESCE(target_uid, ''), COALESCE(target_resource_version, ''), COALESCE(command_hash, ''),
		created_at,
		updated_at, approved_at, executed_at FROM k8s_action_requests WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sActionRequest{}
	for rows.Next() {
		a, err := scanK8sAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sActionRequest(ctx context.Context, id string) (K8sActionRequest, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, resource_kind, resource_name, action,
		parameters_json, risk_level, status, requested_by, approved_by, executed_by, result, dry_run_diff,
		COALESCE(idempotency_key, ''), COALESCE(target_uid, ''), COALESCE(target_resource_version, ''), COALESCE(command_hash, ''),
		created_at, updated_at, approved_at, executed_at FROM k8s_action_requests WHERE id = ?`), id)
	a, err := scanK8sAction(row)
	if err == sql.ErrNoRows {
		return K8sActionRequest{}, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) GetK8sActionRequestByIdempotencyKey(ctx context.Context, key string) (K8sActionRequest, error) {
	if key == "" {
		return K8sActionRequest{}, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, namespace, resource_kind, resource_name, action,
		parameters_json, risk_level, status, requested_by, approved_by, executed_by, result, dry_run_diff,
		COALESCE(idempotency_key, ''), COALESCE(target_uid, ''), COALESCE(target_resource_version, ''), COALESCE(command_hash, ''),
		created_at, updated_at, approved_at, executed_at FROM k8s_action_requests WHERE idempotency_key = ?`), key)
	a, err := scanK8sAction(row)
	if err == sql.ErrNoRows {
		return K8sActionRequest{}, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) UpdateK8sActionStatus(ctx context.Context, id, status, actor, result string) error {
	now := nowString()
	query := `UPDATE k8s_action_requests SET status = ?, updated_at = ?, result = ?`
	args := []any{status, now, result}
	allowedWhere := ""
	switch status {
	case "approved":
		query += `, approved_by = ?, approved_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status IN ('pending', 'approval_required')`
	case "rejected":
		allowedWhere = ` AND status IN ('pending', 'approval_required')`
	case "running":
		query += `, executed_by = ?, executed_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status = 'approved'`
	case "executed", "failed":
		query += `, executed_by = ?, executed_at = ?`
		args = append(args, actor, now)
		allowedWhere = ` AND status = 'running'`
	default:
		return ErrInvalidTransition
	}
	query += ` WHERE id = ?` + allowedWhere
	args = append(args, id)
	res, err := s.db.ExecContext(ctx, s.bind(query), args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sActionRequest(ctx, id); getErr == nil {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) UpsertK8sCollectorStatus(ctx context.Context, st K8sCollectorStatus) error {
	if st.UpdatedAt == "" {
		st.UpdatedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_collector_status
		(id, cluster_id, collector, status, last_success_at, last_error, lag_seconds, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, collector) DO UPDATE SET
			status = excluded.status,
			last_success_at = excluded.last_success_at,
			last_error = excluded.last_error,
			lag_seconds = excluded.lag_seconds,
			updated_at = excluded.updated_at`),
		st.ID, st.ClusterID, st.Collector, st.Status, st.LastSuccessAt, st.LastError, st.LagSeconds, st.UpdatedAt)
	return err
}

func (s *SQLStore) K8sOverview(ctx context.Context) (K8sOverview, error) {
	out := K8sOverview{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Inventory: []K8sKindCount{}}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status IN ('ready', 'connected') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status NOT IN ('ready', 'connected', 'unknown') THEN 1 ELSE 0 END), 0)
		FROM k8s_clusters`).Scan(&out.Clusters.Total, &out.Clusters.Ready, &out.Clusters.Risky); err != nil {
		return out, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT kind, COUNT(*),
		COALESCE(SUM(CASE WHEN health_score < 80 OR risk_level IN ('medium', 'high', 'critical') THEN 1 ELSE 0 END), 0)
		FROM k8s_inventory GROUP BY kind ORDER BY COUNT(*) DESC`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var k K8sKindCount
		if err := rows.Scan(&k.Kind, &k.Count, &k.Unhealthy); err != nil {
			rows.Close()
			return out, err
		}
		out.Inventory = append(out.Inventory, k)
	}
	if err := rows.Close(); err != nil {
		return out, err
	}
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	_ = s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM k8s_events WHERE lower(type) = 'warning' AND last_seen >= ?`), since).Scan(&out.WarningEvents24)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM k8s_security_findings WHERE status = 'open'`).Scan(&out.OpenFindings)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM k8s_action_requests WHERE status IN ('pending', 'approval_required', 'approved', 'running')`).Scan(&out.PendingActions)
	return out, nil
}

type k8sClusterScanner interface {
	Scan(dest ...any) error
}

func scanK8sCluster(row k8sClusterScanner) (K8sCluster, error) {
	var c K8sCluster
	var labels string
	if err := row.Scan(&c.ID, &c.Name, &c.Description, &c.ServerURL, &c.AuthMode, &c.CredentialRef, &c.GroupID,
		&c.Status, &c.KubernetesVersion, &c.NodeCount, &c.NamespaceCount, &labels, &c.LastConnectedAt, &c.LastError, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return K8sCluster{}, err
	}
	c.Labels = decodeStringMap(labels)
	return c, nil
}

func scanK8sInventory(rows k8sClusterScanner) (K8sInventoryItem, error) {
	var item K8sInventoryItem
	var spec, statusObj, labels, annotations string
	if err := rows.Scan(&item.ID, &item.ClusterID, &item.Kind, &item.Namespace, &item.Name, &item.UID,
		&item.APIVersion, &item.Status, &item.HealthScore, &item.RiskLevel, &spec, &statusObj, &labels, &annotations,
		&item.ObservedAt, &item.UpdatedAt); err != nil {
		return K8sInventoryItem{}, err
	}
	item.Spec = decodeAnyMap(spec)
	item.StatusObject = decodeAnyMap(statusObj)
	item.Labels = decodeStringMap(labels)
	item.Annotations = decodeStringMap(annotations)
	return item, nil
}

func scanK8sAction(rows k8sClusterScanner) (K8sActionRequest, error) {
	var a K8sActionRequest
	var params string
	if err := rows.Scan(&a.ID, &a.ClusterID, &a.Namespace, &a.ResourceKind, &a.ResourceName, &a.Action,
		&params, &a.RiskLevel, &a.Status, &a.RequestedBy, &a.ApprovedBy, &a.ExecutedBy, &a.Result,
		&a.DryRunDiff, &a.IdempotencyKey, &a.TargetUID, &a.TargetResourceVersion, &a.CommandHash,
		&a.CreatedAt, &a.UpdatedAt, &a.ApprovedAt, &a.ExecutedAt); err != nil {
		return K8sActionRequest{}, err
	}
	a.Parameters = decodeAnyMap(params)
	return a, nil
}

func nowString() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func boundedLimit(value, fallback, max int) int {
	if value <= 0 {
		value = fallback
	}
	if value > max {
		return max
	}
	return value
}

func encodeStringMap(values map[string]string) string {
	if len(values) == 0 {
		return "{}"
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeStringMap(raw string) map[string]string {
	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func encodeAnyMap(values map[string]any) string {
	if len(values) == 0 {
		return "{}"
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeAnyMap(raw string) map[string]any {
	out := map[string]any{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// HashK8sSpec returns a stable sha256 of a spec map. encoding/json marshals map keys in
// sorted order, so the hash is deterministic for equal specs.
func HashK8sSpec(spec map[string]any) string {
	b, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// lastK8sRevisionHash returns the spec hash of the most recent revision for a resource,
// or "" when no revision exists yet.
func (s *SQLStore) lastK8sRevisionHash(ctx context.Context, clusterID, kind, namespace, name string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT spec_hash FROM k8s_resource_revisions
		WHERE cluster_id = ? AND kind = ? AND namespace = ? AND name = ?
		ORDER BY observed_at DESC, created_at DESC LIMIT 1`),
		clusterID, kind, namespace, name).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

// RecordK8sRevision appends a revision only when the resource's spec hash differs from the
// previous revision. It returns true when a new revision row was written. The caller passes
// the live spec; the hash, change_kind and timestamps are filled in here.
func (s *SQLStore) RecordK8sRevision(ctx context.Context, rev K8sResourceRevision) (bool, error) {
	now := nowString()
	if rev.ObservedAt == "" {
		rev.ObservedAt = now
	}
	rev.CreatedAt = now
	rev.SpecHash = HashK8sSpec(rev.Spec)
	prev, err := s.lastK8sRevisionHash(ctx, rev.ClusterID, rev.Kind, rev.Namespace, rev.Name)
	if err != nil {
		return false, err
	}
	if prev == rev.SpecHash {
		return false, nil // unchanged spec; no new revision
	}
	rev.ChangeKind = "updated"
	if prev == "" {
		rev.ChangeKind = "created"
	}
	if rev.ID == "" {
		rev.ID = "k8srev_" + rev.SpecHash[:min(len(rev.SpecHash), 24)] + "_" + rev.ObservedAt
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_resource_revisions
		(id, cluster_id, kind, namespace, name, spec_hash, spec_json, replica, image_set, change_kind, observed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`),
		rev.ID, rev.ClusterID, rev.Kind, rev.Namespace, rev.Name, rev.SpecHash,
		encodeAnyMap(rev.Spec), rev.Replica, rev.ImageSet, rev.ChangeKind, rev.ObservedAt, rev.CreatedAt)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLStore) ListK8sRevisions(ctx context.Context, f K8sRevisionFilter) ([]K8sResourceRevision, error) {
	query := `SELECT id, cluster_id, kind, namespace, name, spec_hash, COALESCE(spec_json, '{}'),
		replica, COALESCE(image_set, ''), COALESCE(change_kind, ''), observed_at, created_at
		FROM k8s_resource_revisions WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Kind != "" {
		query += ` AND lower(kind) = lower(?)`
		args = append(args, f.Kind)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	if f.Name != "" {
		query += ` AND name = ?`
		args = append(args, f.Name)
	}
	query += ` ORDER BY observed_at DESC, created_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sResourceRevision{}
	for rows.Next() {
		rev, err := scanK8sRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sRevision(ctx context.Context, id string) (K8sResourceRevision, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, kind, namespace, name, spec_hash,
		COALESCE(spec_json, '{}'), replica, COALESCE(image_set, ''), COALESCE(change_kind, ''), observed_at, created_at
		FROM k8s_resource_revisions WHERE id = ?`), id)
	rev, err := scanK8sRevision(row)
	if err == sql.ErrNoRows {
		return K8sResourceRevision{}, ErrNotFound
	}
	return rev, err
}

func scanK8sRevision(sc interface{ Scan(...any) error }) (K8sResourceRevision, error) {
	var rev K8sResourceRevision
	var spec string
	if err := sc.Scan(&rev.ID, &rev.ClusterID, &rev.Kind, &rev.Namespace, &rev.Name, &rev.SpecHash,
		&spec, &rev.Replica, &rev.ImageSet, &rev.ChangeKind, &rev.ObservedAt, &rev.CreatedAt); err != nil {
		return K8sResourceRevision{}, err
	}
	rev.Spec = decodeAnyMap(spec)
	return rev, nil
}
