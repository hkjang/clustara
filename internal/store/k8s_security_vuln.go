package store

import (
	"context"
	"database/sql"
	"encoding/json"
)

type K8sSecurityScanRun struct {
	ID             string         `json:"id"`
	ClusterID      string         `json:"cluster_id"`
	Source         string         `json:"source"`
	Scanner        string         `json:"scanner"`
	ScannerVersion string         `json:"scanner_version"`
	TargetType     string         `json:"target_type"`
	TargetRef      string         `json:"target_ref"`
	ImageDigest    string         `json:"image_digest"`
	Status         string         `json:"status"`
	StartedAt      string         `json:"started_at"`
	FinishedAt     string         `json:"finished_at"`
	RawArtifactRef string         `json:"raw_artifact_ref"`
	Summary        map[string]any `json:"summary"`
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
}

type K8sImageVulnerability struct {
	ID               string  `json:"id"`
	ScanRunID        string  `json:"scan_run_id"`
	ClusterID        string  `json:"cluster_id"`
	Namespace        string  `json:"namespace"`
	WorkloadKind     string  `json:"workload_kind"`
	WorkloadName     string  `json:"workload_name"`
	ContainerName    string  `json:"container_name"`
	Image            string  `json:"image"`
	ImageDigest      string  `json:"image_digest"`
	CVEID            string  `json:"cve_id"`
	Severity         string  `json:"severity"`
	PackageName      string  `json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	CVSS             float64 `json:"cvss"`
	EPSS             float64 `json:"epss"`
	KEV              bool    `json:"kev"`
	Status           string  `json:"status"`
	FirstSeenAt      string  `json:"first_seen_at"`
	LastSeenAt       string  `json:"last_seen_at"`
}

type K8sVulnerabilityFilter struct {
	ClusterID   string
	Namespace   string
	ImageDigest string
	Severity    string
	Fixable     string
	Status      string
	Limit       int
}

type K8sSBOM struct {
	ID           string        `json:"id"`
	Image        string        `json:"image"`
	ImageDigest  string        `json:"image_digest"`
	Format       string        `json:"format"`
	Generator    string        `json:"generator"`
	GeneratedAt  string        `json:"generated_at"`
	FileHash     string        `json:"file_hash"`
	ArtifactRef  string        `json:"artifact_ref"`
	PackageCount int           `json:"package_count"`
	Packages     []SBOMPackage `json:"packages,omitempty"`
	CreatedAt    string        `json:"created_at"`
	UpdatedAt    string        `json:"updated_at"`
}

type SBOMPackage struct {
	ID       string `json:"id"`
	SBOMID   string `json:"sbom_id"`
	PURL     string `json:"purl"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	License  string `json:"license"`
	Supplier string `json:"supplier"`
}

type K8sVulnerabilityException struct {
	ID         string `json:"id"`
	ClusterID  string `json:"cluster_id"`
	Namespace  string `json:"namespace"`
	Workload   string `json:"workload"`
	ScopeType  string `json:"scope_type"`
	ScopeValue string `json:"scope_value"`
	CVEID      string `json:"cve_id"`
	Severity   string `json:"severity"`
	Reason     string `json:"reason"`
	TicketURL  string `json:"ticket_url"`
	ExpiresAt  string `json:"expires_at"`
	ApprovedBy string `json:"approved_by"`
	CreatedBy  string `json:"created_by"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type K8sAdmissionDecision struct {
	ID            string           `json:"id"`
	ClusterID     string           `json:"cluster_id"`
	Namespace     string           `json:"namespace"`
	Kind          string           `json:"kind"`
	Name          string           `json:"name"`
	Operation     string           `json:"operation"`
	Decision      string           `json:"decision"`
	Reason        string           `json:"reason"`
	PolicyResults []map[string]any `json:"policy_results"`
	RequestUID    string           `json:"request_uid"`
	CreatedAt     string           `json:"created_at"`
}

type K8sRuntimeEvent struct {
	ID        string         `json:"id"`
	ClusterID string         `json:"cluster_id"`
	Namespace string         `json:"namespace"`
	Pod       string         `json:"pod"`
	Container string         `json:"container"`
	Image     string         `json:"image"`
	Node      string         `json:"node"`
	Rule      string         `json:"rule"`
	Priority  string         `json:"priority"`
	Output    string         `json:"output"`
	Source    string         `json:"source"`
	EventTime string         `json:"event_time"`
	Raw       map[string]any `json:"raw"`
	CreatedAt string         `json:"created_at"`
}

type K8sBenchmarkRun struct {
	ID               string `json:"id"`
	ClusterID        string `json:"cluster_id"`
	Tool             string `json:"tool"`
	BenchmarkVersion string `json:"benchmark_version"`
	Status           string `json:"status"`
	PassCount        int    `json:"pass_count"`
	FailCount        int    `json:"fail_count"`
	WarnCount        int    `json:"warn_count"`
	StartedAt        string `json:"started_at"`
	FinishedAt       string `json:"finished_at"`
	CreatedAt        string `json:"created_at"`
}

type K8sBenchmarkResult struct {
	ID          string `json:"id"`
	RunID       string `json:"run_id"`
	ControlID   string `json:"control_id"`
	Section     string `json:"section"`
	Text        string `json:"text"`
	State       string `json:"state"`
	Remediation string `json:"remediation"`
	Scored      bool   `json:"scored"`
}

func (s *SQLStore) UpsertK8sSecurityScanRun(ctx context.Context, run K8sSecurityScanRun) error {
	now := nowString()
	if run.CreatedAt == "" {
		run.CreatedAt = now
	}
	if run.UpdatedAt == "" {
		run.UpdatedAt = now
	}
	if run.Status == "" {
		run.Status = "queued"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_security_scan_runs
		(id, cluster_id, source, scanner, scanner_version, target_type, target_ref, image_digest, status, started_at, finished_at, raw_artifact_ref, summary_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET cluster_id=excluded.cluster_id, source=excluded.source, scanner=excluded.scanner,
		scanner_version=excluded.scanner_version, target_type=excluded.target_type, target_ref=excluded.target_ref,
		image_digest=excluded.image_digest, status=excluded.status, started_at=excluded.started_at, finished_at=excluded.finished_at,
		raw_artifact_ref=excluded.raw_artifact_ref, summary_json=excluded.summary_json, updated_at=excluded.updated_at`),
		run.ID, run.ClusterID, run.Source, run.Scanner, run.ScannerVersion, run.TargetType, run.TargetRef, run.ImageDigest,
		run.Status, run.StartedAt, run.FinishedAt, run.RawArtifactRef, encodeAnyMap(run.Summary), run.CreatedAt, run.UpdatedAt)
	return err
}

func (s *SQLStore) ListK8sSecurityScanRuns(ctx context.Context, clusterID string, limit int) ([]K8sSecurityScanRun, error) {
	query := `SELECT id, cluster_id, source, scanner, scanner_version, target_type, target_ref, image_digest, status,
		started_at, finished_at, raw_artifact_ref, COALESCE(summary_json, '{}'), created_at, updated_at
		FROM k8s_security_scan_runs WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sSecurityScanRun{}
	for rows.Next() {
		run, err := scanK8sSecurityScanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetK8sSecurityScanRun(ctx context.Context, id string) (K8sSecurityScanRun, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id, cluster_id, source, scanner, scanner_version, target_type, target_ref,
		image_digest, status, started_at, finished_at, raw_artifact_ref, COALESCE(summary_json, '{}'), created_at, updated_at
		FROM k8s_security_scan_runs WHERE id=?`), id)
	run, err := scanK8sSecurityScanRun(row)
	if err == sql.ErrNoRows {
		return K8sSecurityScanRun{}, ErrNotFound
	}
	return run, err
}

func (s *SQLStore) ReplaceK8sImageVulnerabilitiesForDigest(ctx context.Context, imageDigest string, vulns []K8sImageVulnerability) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if imageDigest != "" {
		if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM k8s_image_vulnerabilities WHERE image_digest=?`), imageDigest); err != nil {
			return err
		}
	}
	for _, v := range vulns {
		if v.FirstSeenAt == "" {
			v.FirstSeenAt = nowString()
		}
		if v.LastSeenAt == "" {
			v.LastSeenAt = v.FirstSeenAt
		}
		if v.Status == "" {
			v.Status = "open"
		}
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_image_vulnerabilities
			(id, scan_run_id, cluster_id, namespace, workload_kind, workload_name, container_name, image, image_digest, cve_id,
			severity, package_name, installed_version, fixed_version, cvss, epss, kev, status, first_seen_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			v.ID, v.ScanRunID, v.ClusterID, v.Namespace, v.WorkloadKind, v.WorkloadName, v.ContainerName, v.Image, v.ImageDigest,
			v.CVEID, v.Severity, v.PackageName, v.InstalledVersion, v.FixedVersion, v.CVSS, v.EPSS, boolInt(v.KEV), v.Status, v.FirstSeenAt, v.LastSeenAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ListK8sImageVulnerabilities(ctx context.Context, f K8sVulnerabilityFilter) ([]K8sImageVulnerability, error) {
	query := `SELECT id, scan_run_id, cluster_id, namespace, workload_kind, workload_name, container_name, image, image_digest,
		cve_id, severity, package_name, installed_version, fixed_version, cvss, epss, kev, status, first_seen_at, last_seen_at
		FROM k8s_image_vulnerabilities WHERE 1=1`
	args := []any{}
	if f.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, f.ClusterID)
	}
	if f.Namespace != "" {
		query += ` AND namespace = ?`
		args = append(args, f.Namespace)
	}
	if f.ImageDigest != "" {
		query += ` AND image_digest = ?`
		args = append(args, f.ImageDigest)
	}
	if f.Severity != "" {
		query += ` AND lower(severity) = lower(?)`
		args = append(args, f.Severity)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	if f.Fixable == "true" || f.Fixable == "1" {
		query += ` AND fixed_version <> ''`
	}
	query += ` ORDER BY CASE lower(severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, last_seen_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 200, 5000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sImageVulnerability{}
	for rows.Next() {
		v, err := scanK8sImageVulnerability(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertK8sSBOM(ctx context.Context, sbom K8sSBOM) error {
	now := nowString()
	if sbom.CreatedAt == "" {
		sbom.CreatedAt = now
	}
	sbom.UpdatedAt = now
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_sboms
		(id, image, image_digest, format, generator, generated_at, file_hash, artifact_ref, package_count, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET image=excluded.image, image_digest=excluded.image_digest, format=excluded.format,
		generator=excluded.generator, generated_at=excluded.generated_at, file_hash=excluded.file_hash,
		artifact_ref=excluded.artifact_ref, package_count=excluded.package_count, updated_at=excluded.updated_at`),
		sbom.ID, sbom.Image, sbom.ImageDigest, sbom.Format, sbom.Generator, sbom.GeneratedAt, sbom.FileHash, sbom.ArtifactRef,
		sbom.PackageCount, sbom.CreatedAt, sbom.UpdatedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM k8s_sbom_packages WHERE sbom_id=?`), sbom.ID); err != nil {
		return err
	}
	for _, p := range sbom.Packages {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_sbom_packages
			(id, sbom_id, purl, name, version, type, license, supplier) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			p.ID, sbom.ID, p.PURL, p.Name, p.Version, p.Type, p.License, p.Supplier); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ListK8sSBOMs(ctx context.Context, imageDigest string, limit int) ([]K8sSBOM, error) {
	query := `SELECT id, image, image_digest, format, generator, generated_at, file_hash, artifact_ref, package_count, created_at, updated_at FROM k8s_sboms WHERE 1=1`
	args := []any{}
	if imageDigest != "" {
		query += ` AND image_digest = ?`
		args = append(args, imageDigest)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sSBOM{}
	for rows.Next() {
		var b K8sSBOM
		if err := rows.Scan(&b.ID, &b.Image, &b.ImageDigest, &b.Format, &b.Generator, &b.GeneratedAt, &b.FileHash, &b.ArtifactRef, &b.PackageCount, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sSBOMPackages(ctx context.Context, sbomID string, limit int) ([]SBOMPackage, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, sbom_id, purl, name, version, type, license, supplier FROM k8s_sbom_packages WHERE sbom_id=? ORDER BY name LIMIT ?`), sbomID, boundedLimit(limit, 200, 5000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SBOMPackage{}
	for rows.Next() {
		var p SBOMPackage
		if err := rows.Scan(&p.ID, &p.SBOMID, &p.PURL, &p.Name, &p.Version, &p.Type, &p.License, &p.Supplier); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateK8sVulnerabilityException(ctx context.Context, e K8sVulnerabilityException) error {
	now := nowString()
	if e.CreatedAt == "" {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	if e.Status == "" {
		e.Status = "pending"
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_security_exceptions
		(id, cluster_id, namespace, workload, finding, reason, status, requested_by, approved_by, expires_at, created_at, updated_at,
		scope_type, scope_value, cve_id, severity, ticket_url, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, e.ClusterID, e.Namespace, e.Workload, e.CVEID, e.Reason, e.Status, e.CreatedBy, e.ApprovedBy, e.ExpiresAt,
		e.CreatedAt, e.UpdatedAt, e.ScopeType, e.ScopeValue, e.CVEID, e.Severity, e.TicketURL, e.CreatedBy)
	return err
}

func (s *SQLStore) ListK8sVulnerabilityExceptions(ctx context.Context, clusterID string, limit int) ([]K8sVulnerabilityException, error) {
	query := `SELECT id, cluster_id, namespace, workload, COALESCE(scope_type,''), COALESCE(scope_value,''), COALESCE(cve_id,''), COALESCE(severity,''),
		reason, COALESCE(ticket_url,''), expires_at, approved_by, COALESCE(created_by, requested_by), status, created_at, updated_at
		FROM k8s_security_exceptions WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 200, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sVulnerabilityException{}
	for rows.Next() {
		var e K8sVulnerabilityException
		if err := rows.Scan(&e.ID, &e.ClusterID, &e.Namespace, &e.Workload, &e.ScopeType, &e.ScopeValue, &e.CVEID, &e.Severity, &e.Reason, &e.TicketURL, &e.ExpiresAt, &e.ApprovedBy, &e.CreatedBy, &e.Status, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateK8sVulnerabilityExceptionStatus(ctx context.Context, id, status, actor string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_security_exceptions SET status=?, approved_by=COALESCE(NULLIF(?,''), approved_by), updated_at=? WHERE id=?`), status, actor, nowString(), id)
	return err
}

func (s *SQLStore) CreateK8sAdmissionDecision(ctx context.Context, d K8sAdmissionDecision) error {
	if d.CreatedAt == "" {
		d.CreatedAt = nowString()
	}
	b, _ := json.Marshal(d.PolicyResults)
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_admission_decisions
		(id, cluster_id, namespace, kind, name, operation, decision, reason, policy_results_json, request_uid, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		d.ID, d.ClusterID, d.Namespace, d.Kind, d.Name, d.Operation, d.Decision, d.Reason, string(b), d.RequestUID, d.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sAdmissionDecisions(ctx context.Context, clusterID string, limit int) ([]K8sAdmissionDecision, error) {
	query := `SELECT id, cluster_id, namespace, kind, name, operation, decision, reason, COALESCE(policy_results_json,'[]'), request_uid, created_at FROM k8s_admission_decisions WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sAdmissionDecision{}
	for rows.Next() {
		var d K8sAdmissionDecision
		var raw string
		if err := rows.Scan(&d.ID, &d.ClusterID, &d.Namespace, &d.Kind, &d.Name, &d.Operation, &d.Decision, &d.Reason, &raw, &d.RequestUID, &d.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &d.PolicyResults)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateK8sRuntimeEvent(ctx context.Context, e K8sRuntimeEvent) error {
	if e.CreatedAt == "" {
		e.CreatedAt = nowString()
	}
	raw := encodeAnyMap(e.Raw)
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_runtime_events
		(id, cluster_id, namespace, pod, container, image, node, rule, priority, output, source, event_time, raw_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, e.ClusterID, e.Namespace, e.Pod, e.Container, e.Image, e.Node, e.Rule, e.Priority, e.Output, e.Source, e.EventTime, raw, e.CreatedAt)
	return err
}

func (s *SQLStore) ListK8sRuntimeEvents(ctx context.Context, clusterID, priority string, limit int) ([]K8sRuntimeEvent, error) {
	query := `SELECT id, cluster_id, namespace, pod, container, image, node, rule, priority, output, source, event_time, COALESCE(raw_json,'{}'), created_at FROM k8s_runtime_events WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	if priority != "" {
		query += ` AND lower(priority) = lower(?)`
		args = append(args, priority)
	}
	query += ` ORDER BY event_time DESC, created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 2000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sRuntimeEvent{}
	for rows.Next() {
		var e K8sRuntimeEvent
		var raw string
		if err := rows.Scan(&e.ID, &e.ClusterID, &e.Namespace, &e.Pod, &e.Container, &e.Image, &e.Node, &e.Rule, &e.Priority, &e.Output, &e.Source, &e.EventTime, &raw, &e.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &e.Raw)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateK8sBenchmarkRun(ctx context.Context, run K8sBenchmarkRun, results []K8sBenchmarkResult) error {
	if run.CreatedAt == "" {
		run.CreatedAt = nowString()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_benchmark_runs
		(id, cluster_id, tool, benchmark_version, status, pass_count, fail_count, warn_count, started_at, finished_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		run.ID, run.ClusterID, run.Tool, run.BenchmarkVersion, run.Status, run.PassCount, run.FailCount, run.WarnCount, run.StartedAt, run.FinishedAt, run.CreatedAt); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO k8s_benchmark_results
			(id, run_id, control_id, section, text, state, remediation, scored) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			r.ID, run.ID, r.ControlID, r.Section, r.Text, r.State, r.Remediation, boolInt(r.Scored)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) ListK8sBenchmarkRuns(ctx context.Context, clusterID string, limit int) ([]K8sBenchmarkRun, error) {
	query := `SELECT id, cluster_id, tool, benchmark_version, status, pass_count, fail_count, warn_count, started_at, finished_at, created_at FROM k8s_benchmark_runs WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, clusterID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, boundedLimit(limit, 100, 1000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sBenchmarkRun{}
	for rows.Next() {
		var r K8sBenchmarkRun
		if err := rows.Scan(&r.ID, &r.ClusterID, &r.Tool, &r.BenchmarkVersion, &r.Status, &r.PassCount, &r.FailCount, &r.WarnCount, &r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sBenchmarkResults(ctx context.Context, runID string, limit int) ([]K8sBenchmarkResult, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, run_id, control_id, section, text, state, remediation, scored FROM k8s_benchmark_results WHERE run_id=? ORDER BY control_id LIMIT ?`), runID, boundedLimit(limit, 500, 5000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sBenchmarkResult{}
	for rows.Next() {
		var r K8sBenchmarkResult
		var scored int
		if err := rows.Scan(&r.ID, &r.RunID, &r.ControlID, &r.Section, &r.Text, &r.State, &r.Remediation, &scored); err != nil {
			return nil, err
		}
		r.Scored = scored != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanK8sSecurityScanRun(row interface{ Scan(dest ...any) error }) (K8sSecurityScanRun, error) {
	var r K8sSecurityScanRun
	var summary string
	err := row.Scan(&r.ID, &r.ClusterID, &r.Source, &r.Scanner, &r.ScannerVersion, &r.TargetType, &r.TargetRef, &r.ImageDigest, &r.Status, &r.StartedAt, &r.FinishedAt, &r.RawArtifactRef, &summary, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(summary), &r.Summary)
	if r.Summary == nil {
		r.Summary = map[string]any{}
	}
	return r, nil
}

func scanK8sImageVulnerability(row interface{ Scan(dest ...any) error }) (K8sImageVulnerability, error) {
	var v K8sImageVulnerability
	var kev int
	err := row.Scan(&v.ID, &v.ScanRunID, &v.ClusterID, &v.Namespace, &v.WorkloadKind, &v.WorkloadName, &v.ContainerName, &v.Image, &v.ImageDigest, &v.CVEID, &v.Severity, &v.PackageName, &v.InstalledVersion, &v.FixedVersion, &v.CVSS, &v.EPSS, &kev, &v.Status, &v.FirstSeenAt, &v.LastSeenAt)
	v.KEV = kev != 0
	return v, err
}
