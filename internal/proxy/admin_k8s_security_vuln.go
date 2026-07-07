package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"

	"gopkg.in/yaml.v3"
)

type securityScanImportPayload struct {
	ClusterID      string          `json:"cluster_id"`
	Namespace      string          `json:"namespace"`
	WorkloadKind   string          `json:"workload_kind"`
	WorkloadName   string          `json:"workload_name"`
	ContainerName  string          `json:"container_name"`
	Image          string          `json:"image"`
	ImageDigest    string          `json:"image_digest"`
	Source         string          `json:"source"`
	Scanner        string          `json:"scanner"`
	ScannerVersion string          `json:"scanner_version"`
	TargetType     string          `json:"target_type"`
	TargetRef      string          `json:"target_ref"`
	BuildID        string          `json:"build_id"`
	GitSHA         string          `json:"git_sha"`
	Status         string          `json:"status"`
	RawJSON        json.RawMessage `json:"raw_json"`
	Artifact       json.RawMessage `json:"artifact"`
}

func (s *Server) handleK8sSecurityVulnSummary(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	vulns, err := s.db.ListK8sImageVulnerabilities(r.Context(), store.K8sVulnerabilityFilter{ClusterID: clusterID, Status: firstQuery(r.URL.Query().Get("status"), "open"), Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_vuln_failed")
		return
	}
	exceptions, _ := s.db.ListK8sVulnerabilityExceptions(r.Context(), clusterID, 1000)
	runtimeEvents, _ := s.db.ListK8sRuntimeEvents(r.Context(), clusterID, "", 500)
	benchRuns, _ := s.db.ListK8sBenchmarkRuns(r.Context(), clusterID, 50)
	scanRuns, _ := s.db.ListK8sSecurityScanRuns(r.Context(), clusterID, 200)
	summary := securityVulnSummary(vulns, exceptions, runtimeEvents, benchRuns, scanRuns)
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "generated_at": time.Now().UTC().Format(time.RFC3339Nano)})
}

func (s *Server) handleK8sSecurityVulnImages(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	vulns, err := s.db.ListK8sImageVulnerabilities(r.Context(), store.K8sVulnerabilityFilter{
		ClusterID: q.Get("cluster_id"), Namespace: q.Get("namespace"), Severity: q.Get("severity"),
		ImageDigest: q.Get("image_digest"), Fixable: q.Get("fixable"), Status: firstQuery(q.Get("status"), "open"),
		Limit: intParam(q.Get("limit"), 500),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_vuln_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns, "summary": securitySeverityCounts(vulns), "count": len(vulns)})
}

func (s *Server) handleK8sSecurityVulnWorkloads(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	vulns, err := s.db.ListK8sImageVulnerabilities(r.Context(), store.K8sVulnerabilityFilter{ClusterID: clusterID, Namespace: namespace, Status: "open", Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_vuln_failed")
		return
	}
	rows := map[string]map[string]any{}
	for _, v := range vulns {
		key := strings.Join([]string{v.ClusterID, v.Namespace, v.WorkloadKind, v.WorkloadName, v.ImageDigest}, "/")
		row := rows[key]
		if row == nil {
			row = map[string]any{
				"cluster_id": v.ClusterID, "namespace": v.Namespace, "workload_kind": v.WorkloadKind,
				"workload_name": v.WorkloadName, "image": v.Image, "image_digest": v.ImageDigest,
				"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "fixable": 0, "cves": []string{},
			}
			rows[key] = row
		}
		sec := strings.ToLower(analyzer.NormalizeSeverity(v.Severity))
		row[sec] = row[sec].(int) + 1
		if strings.TrimSpace(v.FixedVersion) != "" {
			row["fixable"] = row["fixable"].(int) + 1
		}
		cves := row["cves"].([]string)
		if len(cves) < 8 && !containsStringValue(cves, v.CVEID) {
			row["cves"] = append(cves, v.CVEID)
		}
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"workloads": out, "count": len(out)})
}

func (s *Server) handleK8sSecurityScans(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		runs, err := s.db.ListK8sSecurityScanRuns(r.Context(), r.URL.Query().Get("cluster_id"), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_scans_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"scans": securityScanRunViews(runs), "count": len(runs), "freshness": securityScanFreshness(runs)})
	case http.MethodPost:
		var in struct {
			ClusterID      string `json:"cluster_id"`
			Image          string `json:"image"`
			ImageDigest    string `json:"image_digest"`
			Scanner        string `json:"scanner"`
			SeverityPolicy string `json:"severity_policy"`
			Source         string `json:"source"`
		}
		if err := decodeJSONBody(r, &in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		run := store.K8sSecurityScanRun{
			ID: newID("k8sscan"), ClusterID: in.ClusterID, Source: firstNonEmpty(in.Source, "manual"),
			Scanner: firstNonEmpty(in.Scanner, "trivy"), TargetType: "image", TargetRef: in.Image,
			ImageDigest: in.ImageDigest, Status: "queued", Summary: map[string]any{"severity_policy": in.SeverityPolicy},
		}
		if err := s.db.UpsertK8sSecurityScanRun(r.Context(), run); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_scan_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.security.scan.request", run.ID, auditJSON(run))
		writeJSON(w, http.StatusCreated, map[string]any{"scan": run})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sSecurityScanByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/security/scans/"), "/")
	if id == "" || id == "import" {
		writeOpenAIError(w, http.StatusBadRequest, "scan id required", "invalid_request_error", "missing_scan_id")
		return
	}
	run, err := s.db.GetK8sSecurityScanRun(r.Context(), id)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "scan not found", "invalid_request_error", "scan_not_found")
		return
	}
	vulns, _ := s.db.ListK8sImageVulnerabilities(r.Context(), store.K8sVulnerabilityFilter{ImageDigest: run.ImageDigest, Limit: 1000})
	writeJSON(w, http.StatusOK, map[string]any{"scan": run, "vulnerabilities": vulns, "count": len(vulns)})
}

func (s *Server) handleK8sSecurityScansImport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "failed to read request body", "invalid_request_error", "body_read_failed")
		return
	}
	var in securityScanImportPayload
	if err := json.Unmarshal(body, &in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	securityApplyImportRequestDefaults(&in, r)
	raw := in.RawJSON
	if len(raw) == 0 {
		raw = in.Artifact
	}
	if len(raw) == 0 && securityLooksLikeScanArtifact(body) {
		raw = body
	}
	if len(raw) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "raw_json or artifact is required", "invalid_request_error", "missing_scan_artifact")
		return
	}
	securityEnrichImportPayload(&in, raw)
	norm, err := analyzer.NormalizeVulnerabilityScan(in.Scanner, raw, map[string]string{
		"scanner_version": in.ScannerVersion, "target_type": in.TargetType, "target_ref": in.TargetRef,
		"image": in.Image, "image_digest": in.ImageDigest,
	})
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "scan_parse_failed")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := store.K8sSecurityScanRun{
		ID: newID("k8sscan"), ClusterID: in.ClusterID, Source: firstNonEmpty(in.Source, "import"),
		Scanner: norm.Scanner, ScannerVersion: firstNonEmpty(in.ScannerVersion, norm.ScannerVersion),
		TargetType: firstNonEmpty(norm.TargetType, "image"), TargetRef: firstNonEmpty(norm.TargetRef, in.Image),
		ImageDigest: firstNonEmpty(in.ImageDigest, norm.ImageDigest), Status: firstNonEmpty(in.Status, "completed"),
		StartedAt: now, FinishedAt: now, RawArtifactRef: "sha256:" + shortHash(string(raw)), Summary: norm.Summary,
	}
	if err := s.db.UpsertK8sSecurityScanRun(r.Context(), run); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_scan_save_failed")
		return
	}
	vulns := s.securityStoreVulnsFromNormalized(r, run, in, norm.Findings)
	if err := s.db.ReplaceK8sImageVulnerabilitiesForDigest(r.Context(), run.ImageDigest, vulns); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_vuln_save_failed")
		return
	}
	s.auditAdmin(r, "k8s.security.scan.import", run.ID, auditJSON(map[string]any{"scanner": run.Scanner, "digest": run.ImageDigest, "findings": len(vulns)}))
	writeJSON(w, http.StatusCreated, map[string]any{"scan": run, "imported": len(vulns), "summary": norm.Summary})
}

func securityApplyImportRequestDefaults(in *securityScanImportPayload, r *http.Request) {
	q := r.URL.Query()
	in.ClusterID = firstNonEmpty(in.ClusterID, q.Get("cluster_id"))
	in.Namespace = firstNonEmpty(in.Namespace, q.Get("namespace"))
	in.WorkloadKind = firstNonEmpty(in.WorkloadKind, q.Get("workload_kind"))
	in.WorkloadName = firstNonEmpty(in.WorkloadName, q.Get("workload_name"))
	in.ContainerName = firstNonEmpty(in.ContainerName, q.Get("container_name"))
	in.Image = firstNonEmpty(in.Image, q.Get("image"))
	in.ImageDigest = firstNonEmpty(in.ImageDigest, q.Get("image_digest"))
	in.Source = firstNonEmpty(in.Source, q.Get("source"))
	in.Scanner = firstNonEmpty(in.Scanner, q.Get("scanner"))
	in.ScannerVersion = firstNonEmpty(in.ScannerVersion, q.Get("scanner_version"))
	in.TargetType = firstNonEmpty(in.TargetType, q.Get("target_type"))
	in.TargetRef = firstNonEmpty(in.TargetRef, q.Get("target_ref"))
	in.BuildID = firstNonEmpty(in.BuildID, q.Get("build_id"))
	in.GitSHA = firstNonEmpty(in.GitSHA, q.Get("git_sha"))
	in.Status = firstNonEmpty(in.Status, q.Get("status"))
}

func securityLooksLikeScanArtifact(raw []byte) bool {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return false
	}
	if strings.EqualFold(strAny(root["kind"]), "VulnerabilityReport") {
		return true
	}
	if root["Results"] != nil || root["matches"] != nil {
		return true
	}
	report := asMapAny(root["report"])
	return report["vulnerabilities"] != nil || report["artifact"] != nil
}

func securityLooksLikeSBOMArtifact(raw []byte) bool {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return false
	}
	if strings.EqualFold(strAny(root["bomFormat"]), "CycloneDX") {
		return true
	}
	if strings.HasPrefix(strings.ToUpper(strAny(root["spdxVersion"])), "SPDX-") {
		return true
	}
	return root["components"] != nil || root["packages"] != nil
}

func (s *Server) handleK8sSecuritySBOMs(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		sboms, err := s.db.ListK8sSBOMs(r.Context(), r.URL.Query().Get("image_digest"), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "sbom_list_failed")
			return
		}
		if len(sboms) == 1 && r.URL.Query().Get("packages") == "1" {
			pkgs, _ := s.db.ListK8sSBOMPackages(r.Context(), sboms[0].ID, 5000)
			sboms[0].Packages = pkgs
		}
		writeJSON(w, http.StatusOK, map[string]any{"sboms": sboms, "count": len(sboms)})
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "failed to read request body", "invalid_request_error", "body_read_failed")
			return
		}
		var in struct {
			Image       string          `json:"image"`
			ImageDigest string          `json:"image_digest"`
			Format      string          `json:"format"`
			Generator   string          `json:"generator"`
			ArtifactRef string          `json:"artifact_ref"`
			SBOM        json.RawMessage `json:"sbom"`
			RawJSON     json.RawMessage `json:"raw_json"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		q := r.URL.Query()
		in.Image = firstNonEmpty(in.Image, q.Get("image"))
		in.ImageDigest = firstNonEmpty(in.ImageDigest, q.Get("image_digest"))
		in.Generator = firstNonEmpty(in.Generator, q.Get("generator"))
		in.Format = firstNonEmpty(in.Format, q.Get("format"))
		in.ArtifactRef = firstNonEmpty(in.ArtifactRef, q.Get("artifact_ref"))
		raw := in.SBOM
		if len(raw) == 0 {
			raw = in.RawJSON
		}
		if len(raw) == 0 && securityLooksLikeSBOMArtifact(body) {
			raw = body
		}
		if len(raw) == 0 {
			writeOpenAIError(w, http.StatusBadRequest, "sbom is required", "invalid_request_error", "missing_sbom")
			return
		}
		norm, err := analyzer.NormalizeSBOM(raw, map[string]string{"image": in.Image, "image_digest": in.ImageDigest, "generator": in.Generator})
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "sbom_parse_failed")
			return
		}
		sbom := store.K8sSBOM{
			ID: newID("k8ssbom"), Image: norm.Image, ImageDigest: norm.ImageDigest, Format: firstNonEmpty(in.Format, norm.Format),
			Generator: norm.Generator, GeneratedAt: norm.GeneratedAt, FileHash: norm.FileHash, ArtifactRef: in.ArtifactRef,
			PackageCount: norm.PackageCount,
		}
		for _, p := range norm.Packages {
			sbom.Packages = append(sbom.Packages, store.SBOMPackage{ID: newID("k8ssbpkg"), PURL: p.PURL, Name: p.Name, Version: p.Version, Type: p.Type, License: p.License, Supplier: p.Supplier})
		}
		if err := s.db.UpsertK8sSBOM(r.Context(), sbom); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "sbom_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.security.sbom.upload", sbom.ID, auditJSON(map[string]any{"digest": sbom.ImageDigest, "packages": sbom.PackageCount}))
		writeJSON(w, http.StatusCreated, map[string]any{"sbom": sbom})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sSecurityVulnExceptions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		_, _ = s.db.ExpireK8sSecurityExceptions(r.Context(), time.Now().UTC().Format(time.RFC3339Nano))
		items, err := s.db.ListK8sVulnerabilityExceptions(r.Context(), r.URL.Query().Get("cluster_id"), intParam(r.URL.Query().Get("limit"), 200))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_exception_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"exceptions": securityExceptionViews(items), "count": len(items)})
	case http.MethodPost:
		var in store.K8sVulnerabilityException
		if err := decodeJSONBody(r, &in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.Reason) == "" || strings.TrimSpace(in.ExpiresAt) == "" || strings.TrimSpace(in.ScopeType) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "scope_type, reason and expires_at are required", "invalid_request_error", "invalid_exception")
			return
		}
		exp, err := time.Parse(time.RFC3339Nano, in.ExpiresAt)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "expires_at must be RFC3339", "invalid_request_error", "invalid_exception_expiry")
			return
		}
		if !exp.After(time.Now().UTC()) {
			writeOpenAIError(w, http.StatusBadRequest, "expires_at must be in the future", "invalid_request_error", "invalid_exception_expiry")
			return
		}
		in.ID = firstNonEmpty(in.ID, newID("k8ssecex"))
		in.CreatedBy = firstNonEmpty(in.CreatedBy, adminID(r))
		if err := s.db.CreateK8sVulnerabilityException(r.Context(), in); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_exception_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.security.exception.create", in.ID, auditJSON(in))
		writeJSON(w, http.StatusCreated, map[string]any{"exception": in})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sSecurityVulnExceptionByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/security/exceptions/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		writeOpenAIError(w, http.StatusBadRequest, "exception id and command required", "invalid_request_error", "invalid_exception_command")
		return
	}
	status := map[string]string{"approve": "approved", "revoke": "revoked", "reject": "rejected"}[parts[1]]
	if status == "" {
		writeOpenAIError(w, http.StatusNotFound, "unknown exception command", "invalid_request_error", "unknown_exception_command")
		return
	}
	if err := s.db.UpdateK8sVulnerabilityExceptionStatus(r.Context(), parts[0], status, adminID(r)); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_exception_update_failed")
		return
	}
	s.auditAdmin(r, "k8s.security.exception."+parts[1], parts[0], auditJSON(map[string]string{"status": status}))
	writeJSON(w, http.StatusOK, map[string]any{"id": parts[0], "status": status})
}

func (s *Server) handleK8sSecurityAdmissionEvaluate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		ClusterID  string   `json:"cluster_id"`
		Namespace  string   `json:"namespace"`
		Kind       string   `json:"kind"`
		Name       string   `json:"name"`
		Operation  string   `json:"operation"`
		Manifest   string   `json:"manifest"`
		Images     []string `json:"images"`
		RequestUID string   `json:"request_uid"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	images := append([]string{}, in.Images...)
	if strings.TrimSpace(in.Manifest) != "" {
		docImages, kind, ns, name := securityImagesFromManifest(in.Manifest)
		images = append(images, docImages...)
		in.Kind = firstNonEmpty(in.Kind, kind)
		in.Namespace = firstNonEmpty(in.Namespace, ns)
		in.Name = firstNonEmpty(in.Name, name)
	}
	decision, reason, results := s.evaluateSecurityAdmission(r, in.ClusterID, in.Namespace, images)
	record := store.K8sAdmissionDecision{
		ID: newID("k8sadm"), ClusterID: in.ClusterID, Namespace: in.Namespace, Kind: in.Kind, Name: in.Name,
		Operation: firstNonEmpty(in.Operation, "CREATE"), Decision: decision, Reason: reason, PolicyResults: results, RequestUID: in.RequestUID,
	}
	_ = s.db.CreateK8sAdmissionDecision(r.Context(), record)
	if decision == "deny" {
		s.auditAdmin(r, "k8s.security.admission.deny", record.ID, auditJSON(record))
	}
	writeJSON(w, http.StatusOK, map[string]any{"decision": decision, "reason": reason, "results": results, "record": record})
}

func (s *Server) handleK8sSecurityAdmissionReview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var review map[string]any
	if err := decodeJSONBody(r, &review); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	req := asMapAny(review["request"])
	obj := asMapAny(req["object"])
	raw, _ := yaml.Marshal(obj)
	images, kind, ns, name := securityImagesFromManifest(string(raw))
	clusterID := firstNonEmpty(r.URL.Query().Get("cluster_id"), strAny(req["cluster_id"]), strAny(req["cluster"]))
	ns = firstNonEmpty(strAny(req["namespace"]), ns)
	kind = firstNonEmpty(strAny(asMapAny(req["kind"])["kind"]), kind)
	name = firstNonEmpty(strAny(asMapAny(asMapAny(req["object"])["metadata"])["name"]), name)
	decision, reason, results := s.evaluateSecurityAdmission(r, clusterID, ns, images)
	uid := strAny(req["uid"])
	_ = s.db.CreateK8sAdmissionDecision(r.Context(), store.K8sAdmissionDecision{
		ID: newID("k8sadm"), ClusterID: clusterID, Namespace: ns, Kind: kind, Name: name, Operation: strAny(req["operation"]),
		Decision: decision, Reason: reason, PolicyResults: results, RequestUID: uid,
	})
	warnings := []string{}
	if decision == "warn" || decision == "approval_required" {
		warnings = append(warnings, reason)
	}
	status := map[string]any{"message": reason}
	if decision == "deny" {
		status["code"] = http.StatusForbidden
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"response": map[string]any{
			"uid": uid, "allowed": decision != "deny",
			"status":           status,
			"warnings":         warnings,
			"auditAnnotations": map[string]string{"clustara.io/security-decision": decision, "clustara.io/security-reason": reason},
		},
	})
}

func (s *Server) handleK8sSecurityAdmissionDecisions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rows, err := s.db.ListK8sAdmissionDecisions(r.Context(), r.URL.Query().Get("cluster_id"), intParam(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "admission_decisions_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": rows, "count": len(rows)})
}

func (s *Server) handleK8sSecurityRuntimeEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListK8sRuntimeEvents(r.Context(), r.URL.Query().Get("cluster_id"), r.URL.Query().Get("priority"), intParam(r.URL.Query().Get("limit"), 200))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "runtime_events_failed")
			return
		}
		events, correlation := s.securityRuntimeEventViews(r, rows)
		writeJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(rows), "correlation": correlation})
	case http.MethodPost:
		var raw map[string]any
		if err := decodeJSONBody(r, &raw); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		ev := securityRuntimeEventFromRaw(raw)
		ev.ID = newID("k8srun")
		if ev.CreatedAt == "" {
			ev.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if err := s.db.CreateK8sRuntimeEvent(r.Context(), ev); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "runtime_event_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.security.runtime.event", ev.ID, auditJSON(map[string]any{"rule": ev.Rule, "priority": ev.Priority, "pod": ev.Namespace + "/" + ev.Pod}))
		writeJSON(w, http.StatusCreated, map[string]any{"event": ev})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleK8sSecurityBenchmarkRuns(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		runs, err := s.db.ListK8sBenchmarkRuns(r.Context(), r.URL.Query().Get("cluster_id"), intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "benchmark_runs_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"runs": runs, "count": len(runs)})
	case http.MethodPost:
		var in struct {
			ClusterID string          `json:"cluster_id"`
			Tool      string          `json:"tool"`
			Version   string          `json:"benchmark_version"`
			RawJSON   json.RawMessage `json:"raw_json"`
			Result    json.RawMessage `json:"result"`
		}
		if err := decodeJSONBody(r, &in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		raw := in.RawJSON
		if len(raw) == 0 {
			raw = in.Result
		}
		norm, err := analyzer.NormalizeKubeBench(raw)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "benchmark_parse_failed")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		run := store.K8sBenchmarkRun{
			ID: newID("k8sbench"), ClusterID: in.ClusterID, Tool: firstNonEmpty(in.Tool, "kube-bench"),
			BenchmarkVersion: firstNonEmpty(in.Version, norm.BenchmarkVersion), Status: "completed",
			PassCount: norm.PassCount, FailCount: norm.FailCount, WarnCount: norm.WarnCount, StartedAt: now, FinishedAt: now,
		}
		results := []store.K8sBenchmarkResult{}
		for _, rr := range norm.Results {
			results = append(results, store.K8sBenchmarkResult{ID: newID("k8sbenchres"), ControlID: rr.ControlID, Section: rr.Section, Text: rr.Text, State: rr.State, Remediation: rr.Remediation, Scored: rr.Scored})
		}
		if err := s.db.CreateK8sBenchmarkRun(r.Context(), run, results); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "benchmark_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.security.benchmark.import", run.ID, auditJSON(map[string]any{"cluster_id": run.ClusterID, "fail": run.FailCount, "warn": run.WarnCount}))
		writeJSON(w, http.StatusCreated, map[string]any{"run": run, "results": len(results)})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

type securityBenchmarkJobOptions struct {
	Namespace      string            `json:"namespace"`
	JobName        string            `json:"job_name"`
	ServiceAccount string            `json:"service_account"`
	Image          string            `json:"image"`
	Benchmark      string            `json:"benchmark"`
	Args           []string          `json:"args"`
	NodeSelector   map[string]string `json:"node_selector"`
}

func (s *Server) handleK8sSecurityBenchmarkJobManifest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	opts := securityBenchmarkJobOptions{}
	if r.Method == http.MethodPost {
		if err := decodeJSONBody(r, &opts); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
	}
	q := r.URL.Query()
	opts.Namespace = firstNonEmpty(opts.Namespace, q.Get("namespace"), "kube-system")
	opts.JobName = firstNonEmpty(opts.JobName, q.Get("job_name"), "clustara-kube-bench")
	opts.ServiceAccount = firstNonEmpty(opts.ServiceAccount, q.Get("service_account"), "clustara-kube-bench")
	opts.Image = firstNonEmpty(opts.Image, q.Get("image"), "docker.io/aquasec/kube-bench:v0.8.0")
	opts.Benchmark = firstNonEmpty(opts.Benchmark, q.Get("benchmark"))
	if len(opts.Args) == 0 {
		opts.Args = []string{"--json"}
		if opts.Benchmark != "" {
			opts.Args = append(opts.Args, "--benchmark", opts.Benchmark)
		}
	}
	manifest := securityKubeBenchJobManifest(opts)
	warnings := []string{
		"Clustara는 이 manifest를 적용하거나 kube-bench를 직접 실행하지 않습니다. 별도 승인된 runner 또는 운영자가 적용하세요.",
		"이 Job은 노드와 컨트롤플레인 설정 파일을 읽기 위해 hostPath read-only mount와 hostPID를 사용합니다.",
		"운영 클러스터에서는 namespace, image mirror, ServiceAccount, NetworkPolicy, TTL을 내부 표준에 맞게 검토하세요.",
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest":    manifest,
		"warnings":    warnings,
		"apply_hint":  "kubectl apply -f kube-bench-job.yaml",
		"import_hint": "kubectl logs job/" + opts.JobName + " -n " + opts.Namespace + " | curl -X POST /admin/k8s/security/benchmarks/runs -d @-",
	})
}

func (s *Server) handleK8sSecurityBenchmarkResults(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	rows, err := s.db.ListK8sBenchmarkResults(r.Context(), r.URL.Query().Get("run_id"), intParam(r.URL.Query().Get("limit"), 500))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "benchmark_results_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": rows, "count": len(rows)})
}

func securityExceptionViews(items []store.K8sVulnerabilityException) []map[string]any {
	now := time.Now().UTC()
	out := make([]map[string]any, 0, len(items))
	for _, e := range items {
		status := e.Status
		daysRemaining := 0
		expiresSoon := false
		if t, err := time.Parse(time.RFC3339Nano, e.ExpiresAt); err == nil {
			hours := t.Sub(now).Hours()
			daysRemaining = int(hours / 24)
			if status == "approved" && t.Before(now) {
				status = "expired"
			}
			expiresSoon = status == "approved" && hours >= 0 && hours <= 7*24
		}
		out = append(out, map[string]any{
			"id": e.ID, "cluster_id": e.ClusterID, "namespace": e.Namespace, "workload": e.Workload,
			"scope_type": e.ScopeType, "scope_value": e.ScopeValue, "cve_id": e.CVEID, "severity": e.Severity,
			"reason": e.Reason, "ticket_url": e.TicketURL, "expires_at": e.ExpiresAt, "approved_by": e.ApprovedBy,
			"created_by": e.CreatedBy, "status": e.Status, "effective_status": status, "expires_soon": expiresSoon,
			"days_remaining": daysRemaining, "created_at": e.CreatedAt, "updated_at": e.UpdatedAt,
		})
	}
	return out
}

func securityKubeBenchJobManifest(opts securityBenchmarkJobOptions) string {
	ns := securityDNSName(opts.Namespace, "kube-system")
	name := securityDNSName(opts.JobName, "clustara-kube-bench")
	sa := securityDNSName(opts.ServiceAccount, "clustara-kube-bench")
	image := strings.TrimSpace(opts.Image)
	if image == "" {
		image = "docker.io/aquasec/kube-bench:v0.8.0"
	}
	args := opts.Args
	if len(args) == 0 {
		args = []string{"--json"}
	}
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n")
	b.WriteString("  name: " + sa + "\n  namespace: " + ns + "\n")
	b.WriteString("---\napiVersion: batch/v1\nkind: Job\nmetadata:\n")
	b.WriteString("  name: " + name + "\n  namespace: " + ns + "\n  labels:\n    app.kubernetes.io/name: kube-bench\n    app.kubernetes.io/managed-by: clustara\n")
	b.WriteString("spec:\n  backoffLimit: 0\n  ttlSecondsAfterFinished: 3600\n  template:\n    metadata:\n      labels:\n        app.kubernetes.io/name: kube-bench\n    spec:\n      serviceAccountName: " + sa + "\n      hostPID: true\n      restartPolicy: Never\n      tolerations:\n      - operator: Exists\n")
	if len(opts.NodeSelector) > 0 {
		keys := make([]string, 0, len(opts.NodeSelector))
		for k := range opts.NodeSelector {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("      nodeSelector:\n")
		for _, k := range keys {
			b.WriteString("        " + yamlScalar(k) + ": " + yamlScalar(opts.NodeSelector[k]) + "\n")
		}
	}
	b.WriteString("      containers:\n      - name: kube-bench\n        image: " + yamlScalar(image) + "\n        imagePullPolicy: IfNotPresent\n        command:\n        - kube-bench\n        args:\n")
	for _, arg := range args {
		b.WriteString("        - " + yamlScalar(arg) + "\n")
	}
	b.WriteString("        securityContext:\n          readOnlyRootFilesystem: true\n        volumeMounts:\n        - name: var-lib-etcd\n          mountPath: /var/lib/etcd\n          readOnly: true\n        - name: etc-kubernetes\n          mountPath: /etc/kubernetes\n          readOnly: true\n        - name: etc-systemd\n          mountPath: /etc/systemd\n          readOnly: true\n        - name: lib-systemd\n          mountPath: /lib/systemd\n          readOnly: true\n        - name: usr-bin\n          mountPath: /usr/local/mount-from-host/bin\n          readOnly: true\n      volumes:\n      - name: var-lib-etcd\n        hostPath:\n          path: /var/lib/etcd\n      - name: etc-kubernetes\n        hostPath:\n          path: /etc/kubernetes\n      - name: etc-systemd\n        hostPath:\n          path: /etc/systemd\n      - name: lib-systemd\n        hostPath:\n          path: /lib/systemd\n      - name: usr-bin\n        hostPath:\n          path: /usr/bin\n")
	return b.String()
}

func securityDNSName(in, fallback string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = fallback
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	if out == "" {
		return fallback
	}
	return out
}

func yamlScalar(v string) string {
	b, _ := yaml.Marshal(strings.TrimSpace(v))
	return strings.TrimSpace(string(b))
}

func securityEnrichImportPayload(in *securityScanImportPayload, raw json.RawMessage) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return
	}
	if strings.EqualFold(strAny(root["kind"]), "VulnerabilityReport") || asMapAny(root["report"])["vulnerabilities"] != nil {
		in.Scanner = firstNonEmpty(in.Scanner, "trivy-operator")
		in.Source = firstNonEmpty(in.Source, "trivy-operator")
		in.TargetType = firstNonEmpty(in.TargetType, "VulnerabilityReport")
	}
	meta := asMapAny(root["metadata"])
	labels := asMapAny(meta["labels"])
	report := asMapAny(root["report"])
	artifact := asMapAny(report["artifact"])
	scanner := asMapAny(report["scanner"])
	in.Namespace = firstNonEmpty(in.Namespace, strAny(meta["namespace"]))
	in.WorkloadKind = firstNonEmpty(in.WorkloadKind, strAny(labels["trivy-operator.resource.kind"]), strAny(labels["resource-spec-hash.kind"]))
	in.WorkloadName = firstNonEmpty(in.WorkloadName, strAny(labels["trivy-operator.resource.name"]))
	in.ContainerName = firstNonEmpty(in.ContainerName, strAny(labels["trivy-operator.container.name"]), strAny(labels["container.name"]))
	in.ImageDigest = firstNonEmpty(in.ImageDigest, strAny(artifact["digest"]))
	in.Image = firstNonEmpty(in.Image, securityImageFromArtifact(artifact))
	in.ScannerVersion = firstNonEmpty(in.ScannerVersion, strAny(scanner["version"]))
	if in.TargetRef == "" {
		in.TargetRef = firstNonEmpty(in.Image, strings.Trim(strings.TrimSpace(in.Namespace)+"/"+strings.TrimSpace(strAny(meta["name"])), "/"))
	}
}

func securityImageFromArtifact(artifact map[string]any) string {
	repo := strAny(artifact["repository"])
	tag := strAny(artifact["tag"])
	digest := strAny(artifact["digest"])
	switch {
	case repo != "" && digest != "":
		return repo + "@" + digest
	case repo != "" && tag != "":
		return repo + ":" + tag
	default:
		return firstNonEmpty(repo, digest)
	}
}

func securityScanRunViews(runs []store.K8sSecurityScanRun) []map[string]any {
	out := make([]map[string]any, 0, len(runs))
	now := time.Now().UTC()
	for _, r := range runs {
		ageHours := 0.0
		stale := false
		ts := firstNonEmpty(r.FinishedAt, r.UpdatedAt, r.CreatedAt)
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ageHours = now.Sub(t).Hours()
			stale = ageHours > 24
		}
		out = append(out, map[string]any{
			"id": r.ID, "cluster_id": r.ClusterID, "source": r.Source, "scanner": r.Scanner,
			"scanner_version": r.ScannerVersion, "target_type": r.TargetType, "target_ref": r.TargetRef,
			"image_digest": r.ImageDigest, "status": r.Status, "started_at": r.StartedAt, "finished_at": r.FinishedAt,
			"raw_artifact_ref": r.RawArtifactRef, "summary": r.Summary, "created_at": r.CreatedAt, "updated_at": r.UpdatedAt,
			"age_hours": ageHours, "stale": stale,
		})
	}
	return out
}

func securityScanFreshness(runs []store.K8sSecurityScanRun) map[string]any {
	out := map[string]any{"total": len(runs), "stale_24h": 0, "queued": 0, "running": 0, "completed": 0, "failed": 0, "by_source": map[string]int{}}
	bySource := out["by_source"].(map[string]int)
	now := time.Now().UTC()
	var latest time.Time
	for _, r := range runs {
		bySource[firstNonEmpty(r.Source, "unknown")]++
		switch strings.ToLower(r.Status) {
		case "queued":
			out["queued"] = out["queued"].(int) + 1
		case "running":
			out["running"] = out["running"].(int) + 1
		case "completed":
			out["completed"] = out["completed"].(int) + 1
		case "failed", "blocked":
			out["failed"] = out["failed"].(int) + 1
		}
		ts := firstNonEmpty(r.FinishedAt, r.UpdatedAt, r.CreatedAt)
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			if latest.IsZero() || t.After(latest) {
				latest = t
			}
			if now.Sub(t) > 24*time.Hour {
				out["stale_24h"] = out["stale_24h"].(int) + 1
			}
		}
	}
	if !latest.IsZero() {
		out["latest_at"] = latest.Format(time.RFC3339Nano)
		out["latest_age_hours"] = now.Sub(latest).Hours()
	}
	return out
}

func (s *Server) securityRuntimeEventViews(r *http.Request, events []store.K8sRuntimeEvent) ([]map[string]any, map[string]any) {
	out := make([]map[string]any, 0, len(events))
	corr := map[string]any{"events_with_vulns": 0, "critical": 0, "high": 0}
	for _, ev := range events {
		row := map[string]any{
			"id": ev.ID, "cluster_id": ev.ClusterID, "namespace": ev.Namespace, "pod": ev.Pod, "container": ev.Container,
			"image": ev.Image, "node": ev.Node, "rule": ev.Rule, "priority": ev.Priority, "output": ev.Output,
			"source": ev.Source, "event_time": ev.EventTime, "raw": ev.Raw, "created_at": ev.CreatedAt,
		}
		digest := securityDigestFromImageRef(ev.Image)
		if digest != "" {
			vulns, _ := s.db.ListK8sImageVulnerabilities(r.Context(), store.K8sVulnerabilityFilter{ClusterID: ev.ClusterID, ImageDigest: digest, Status: "open", Limit: 1000})
			counts := securitySeverityCounts(vulns)
			row["image_digest"] = digest
			row["vulnerability_summary"] = counts
			if len(vulns) > 0 {
				corr["events_with_vulns"] = corr["events_with_vulns"].(int) + 1
				corr["critical"] = corr["critical"].(int) + counts["Critical"].(int)
				corr["high"] = corr["high"].(int) + counts["High"].(int)
			}
		}
		out = append(out, row)
	}
	return out, corr
}

func securityDigestFromImageRef(image string) string {
	image = strings.TrimSpace(image)
	if i := strings.Index(image, "@sha256:"); i >= 0 {
		return image[i+1:]
	}
	if strings.HasPrefix(image, "sha256:") {
		return image
	}
	return ""
}

func (s *Server) securityStoreVulnsFromNormalized(r *http.Request, run store.K8sSecurityScanRun, in securityScanImportPayload, findings []analyzer.VulnerabilityFinding) []store.K8sImageVulnerability {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	impact := s.securityDigestImpact(r, run.ClusterID, run.ImageDigest)
	out := make([]store.K8sImageVulnerability, 0, len(findings))
	for _, f := range findings {
		ns, wkKind, wkName, container := in.Namespace, in.WorkloadKind, in.WorkloadName, in.ContainerName
		if ns == "" && len(impact) > 0 {
			ns = impact[0]["namespace"]
			wkKind = firstNonEmpty(wkKind, impact[0]["kind"])
			wkName = firstNonEmpty(wkName, impact[0]["name"])
			container = firstNonEmpty(container, impact[0]["container"])
		}
		out = append(out, store.K8sImageVulnerability{
			ID: newID("k8svuln"), ScanRunID: run.ID, ClusterID: run.ClusterID, Namespace: ns, WorkloadKind: wkKind, WorkloadName: wkName,
			ContainerName: container, Image: firstNonEmpty(f.Image, in.Image, run.TargetRef), ImageDigest: run.ImageDigest,
			CVEID: f.CVEID, Severity: f.Severity, PackageName: f.PackageName, InstalledVersion: f.InstalledVersion,
			FixedVersion: f.FixedVersion, CVSS: f.CVSS, EPSS: f.EPSS, KEV: f.KEV, Status: "open", FirstSeenAt: now, LastSeenAt: now,
		})
	}
	return out
}

func (s *Server) securityDigestImpact(r *http.Request, clusterID, digest string) []map[string]string {
	if clusterID == "" || digest == "" {
		return nil
	}
	items, _ := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Pod", Limit: 10000})
	out := []map[string]string{}
	for _, it := range items {
		for _, c := range securityPodContainers(it) {
			if strings.Contains(c["image_id"], digest) || strings.Contains(c["image"], digest) {
				out = append(out, map[string]string{"namespace": it.Namespace, "kind": "Pod", "name": it.Name, "container": c["name"]})
			}
		}
	}
	return out
}

func securityPodContainers(it store.K8sInventoryItem) []map[string]string {
	out := []map[string]string{}
	images := map[string]string{}
	for _, raw := range asSliceAny(it.Spec["containers"]) {
		m := asMapAny(raw)
		images[strAny(m["name"])] = strAny(m["image"])
	}
	for _, raw := range asSliceAny(it.StatusObject["containerStatuses"]) {
		m := asMapAny(raw)
		name := strAny(m["name"])
		out = append(out, map[string]string{"name": name, "image": firstNonEmpty(strAny(m["image"]), images[name]), "image_id": strAny(m["imageID"])})
	}
	if len(out) == 0 {
		for name, image := range images {
			out = append(out, map[string]string{"name": name, "image": image})
		}
	}
	return out
}

func securitySeverityCounts(vulns []store.K8sImageVulnerability) map[string]any {
	out := map[string]any{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0, "fixable": 0, "total": len(vulns)}
	for _, v := range vulns {
		sec := analyzer.NormalizeSeverity(v.Severity)
		out[sec] = out[sec].(int) + 1
		if strings.TrimSpace(v.FixedVersion) != "" {
			out["fixable"] = out["fixable"].(int) + 1
		}
	}
	return out
}

func securityVulnSummary(vulns []store.K8sImageVulnerability, exceptions []store.K8sVulnerabilityException, runtimeEvents []store.K8sRuntimeEvent, benchRuns []store.K8sBenchmarkRun, scanRuns []store.K8sSecurityScanRun) map[string]any {
	base := securitySeverityCounts(vulns)
	approved := 0
	expiring := 0
	now := time.Now().UTC()
	for _, e := range exceptions {
		if e.Status == "approved" {
			approved++
			if t, err := time.Parse(time.RFC3339Nano, e.ExpiresAt); err == nil && t.Sub(now) <= 7*24*time.Hour {
				expiring++
			}
		}
	}
	benchFail := 0
	benchWarn := 0
	if len(benchRuns) > 0 {
		benchFail = benchRuns[0].FailCount
		benchWarn = benchRuns[0].WarnCount
	}
	base["exceptions"] = len(exceptions)
	base["approved_exceptions"] = approved
	base["exceptions_expiring_7d"] = expiring
	base["runtime_events"] = len(runtimeEvents)
	base["benchmark_fail"] = benchFail
	base["benchmark_warn"] = benchWarn
	base["scan_freshness"] = securityScanFreshness(scanRuns)
	return base
}

func securityImagesFromManifest(text string) ([]string, string, string, string) {
	images := []string{}
	kind := ""
	ns := ""
	name := ""
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, it := range x {
				walk(it)
			}
		case map[string]any:
			if img := strAny(x["image"]); img != "" {
				images = append(images, img)
			}
			for _, it := range x {
				walk(it)
			}
		}
	}
	dec := yaml.NewDecoder(strings.NewReader(text))
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if len(doc) == 0 {
			continue
		}
		kind = firstNonEmpty(kind, strAny(doc["kind"]))
		md := asMapAny(doc["metadata"])
		ns = firstNonEmpty(ns, strAny(md["namespace"]))
		name = firstNonEmpty(name, strAny(md["name"]))
		walk(doc)
	}
	return images, kind, ns, name
}

func (s *Server) evaluateSecurityAdmission(r *http.Request, clusterID, namespace string, images []string) (string, string, []map[string]any) {
	decision := "allow"
	reason := "policy passed"
	results := []map[string]any{}
	exceptions, _ := s.db.ListK8sVulnerabilityExceptions(r.Context(), clusterID, 1000)
	for _, image := range images {
		pinned := strings.Contains(image, "@sha256:")
		if strings.HasSuffix(strings.ToLower(image), ":latest") {
			results = append(results, map[string]any{"rule": "disallow_latest_tag", "image": image, "decision": "deny", "reason": "latest tag"})
			decision, reason = securityStricterDecision(decision, reason, "deny", "latest tag image is denied")
		}
		if !pinned {
			results = append(results, map[string]any{"rule": "require_image_digest", "image": image, "decision": "deny", "reason": "digest not pinned"})
			decision, reason = securityStricterDecision(decision, reason, "deny", "image digest is required")
		}
		digest := ""
		if i := strings.Index(image, "@sha256:"); i >= 0 {
			digest = image[i+1:]
		}
		if digest != "" {
			vulns, _ := s.db.ListK8sImageVulnerabilities(r.Context(), store.K8sVulnerabilityFilter{ClusterID: clusterID, ImageDigest: digest, Status: "open", Limit: 1000})
			hasSBOM := false
			sboms, _ := s.db.ListK8sSBOMs(r.Context(), digest, 1)
			hasSBOM = len(sboms) > 0
			if !hasSBOM {
				results = append(results, map[string]any{"rule": "require_sbom", "image": image, "decision": "warn", "reason": "SBOM not linked"})
				decision, reason = securityStricterDecision(decision, reason, "warn", "SBOM not linked")
			}
			for _, v := range vulns {
				if analyzer.SeverityRank(v.Severity) >= 4 && !securityExceptionCovers(exceptions, digest, v.CVEID, namespace) {
					results = append(results, map[string]any{"rule": "deny_critical_vulnerability", "image": image, "cve": v.CVEID, "decision": "deny"})
					decision, reason = securityStricterDecision(decision, reason, "deny", "critical vulnerability without active exception")
				} else if analyzer.SeverityRank(v.Severity) >= 3 {
					results = append(results, map[string]any{"rule": "warn_high_vulnerability", "image": image, "cve": v.CVEID, "decision": "approval_required"})
					decision, reason = securityStricterDecision(decision, reason, "approval_required", "high vulnerability requires approval")
				}
			}
		}
	}
	if len(results) == 0 {
		results = append(results, map[string]any{"rule": "security_image_policy", "decision": "allow"})
	}
	return decision, reason, results
}

func securityStricterDecision(current, currentReason, next, nextReason string) (string, string) {
	rank := func(v string) int {
		switch strings.ToLower(v) {
		case "deny", "blocked":
			return 4
		case "approval_required":
			return 3
		case "warn", "audit":
			return 2
		case "allow":
			return 1
		default:
			return 0
		}
	}
	if rank(next) > rank(current) {
		return next, nextReason
	}
	return current, currentReason
}

func securityExceptionCovers(items []store.K8sVulnerabilityException, digest, cve, namespace string) bool {
	now := time.Now().UTC()
	for _, e := range items {
		if e.Status != "approved" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, e.ExpiresAt); err == nil && t.Before(now) {
			continue
		}
		if e.CVEID != "" && e.CVEID != cve {
			continue
		}
		if e.Namespace != "" && e.Namespace != namespace {
			continue
		}
		if e.ScopeType == "image_digest" && e.ScopeValue != "" && e.ScopeValue != digest {
			continue
		}
		return true
	}
	return false
}

func securityRuntimeEventFromRaw(raw map[string]any) store.K8sRuntimeEvent {
	out := store.K8sRuntimeEvent{
		ClusterID: firstNonEmpty(strAny(raw["cluster_id"]), strAny(raw["cluster"])),
		Rule:      firstNonEmpty(strAny(raw["rule"]), strAny(raw["rule_name"])),
		Priority:  firstNonEmpty(strAny(raw["priority"]), strAny(raw["severity"])),
		Output:    firstNonEmpty(strAny(raw["output"]), strAny(raw["message"])),
		Source:    firstNonEmpty(strAny(raw["source"]), "falco"),
		EventTime: firstNonEmpty(strAny(raw["time"]), strAny(raw["event_time"]), time.Now().UTC().Format(time.RFC3339Nano)),
		Raw:       raw,
	}
	k8s := asMapAny(raw["k8s"])
	out.Namespace = firstNonEmpty(strAny(raw["namespace"]), strAny(raw["k8s.ns.name"]), strAny(k8s["ns.name"]), strAny(k8s["namespace"]))
	out.Pod = firstNonEmpty(strAny(raw["pod"]), strAny(raw["k8s.pod.name"]), strAny(k8s["pod.name"]), strAny(k8s["pod"]))
	out.Container = firstNonEmpty(strAny(raw["container"]), strAny(raw["container.name"]), strAny(raw["k8s.container.name"]), strAny(k8s["container.name"]), strAny(k8s["container"]))
	out.Image = firstNonEmpty(strAny(raw["image"]), strAny(raw["container.image"]), strAny(raw["container.image.repository"]), strAny(k8s["container.image"]), strAny(k8s["image"]))
	out.Node = firstNonEmpty(strAny(raw["node"]), strAny(raw["k8s.node.name"]), strAny(k8s["node.name"]), strAny(k8s["node"]))
	return out
}
