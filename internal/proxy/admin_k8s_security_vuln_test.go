package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestK8sSecurityVulnerabilityImportAdmissionAndEvidence(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "k8s-security-vuln.ndjson"))
	logger.Start()
	defer logger.Stop(t.Context())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	importResp := postJSON(t, srv.URL+"/admin/k8s/security/scans/import", "", map[string]any{
		"cluster_id":    "c1",
		"namespace":     "prod",
		"workload_kind": "Deployment",
		"workload_name": "api",
		"container":     "app",
		"image":         "registry.example.com/app:1.0.0",
		"image_digest":  "sha256:abc",
		"scanner":       "trivy",
		"raw_json": map[string]any{
			"ArtifactName": "registry.example.com/app:1.0.0",
			"Results": []any{map[string]any{
				"Target": "alpine",
				"Vulnerabilities": []any{map[string]any{
					"VulnerabilityID":  "CVE-2026-0001",
					"PkgName":          "openssl",
					"InstalledVersion": "1.0",
					"FixedVersion":     "1.1",
					"Severity":         "CRITICAL",
				}},
			}},
		},
	})
	defer importResp.Body.Close()
	if importResp.StatusCode != http.StatusCreated {
		t.Fatalf("scan import status=%d", importResp.StatusCode)
	}
	var imported struct {
		Imported int `json:"imported"`
	}
	if err := json.NewDecoder(importResp.Body).Decode(&imported); err != nil {
		t.Fatal(err)
	}
	if imported.Imported != 1 {
		t.Fatalf("imported findings=%d, want 1", imported.Imported)
	}

	listResp, err := http.Get(srv.URL + "/admin/k8s/security/vuln/images?cluster_id=c1&severity=Critical")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	var listed struct {
		Count           int                           `json:"count"`
		Vulnerabilities []store.K8sImageVulnerability `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if listResp.StatusCode != http.StatusOK || listed.Count != 1 || listed.Vulnerabilities[0].CVEID != "CVE-2026-0001" {
		t.Fatalf("vuln list mismatch status=%d out=%+v", listResp.StatusCode, listed)
	}

	evalResp := postJSON(t, srv.URL+"/admin/k8s/security/admission/evaluate", "", map[string]any{
		"cluster_id": "c1",
		"namespace":  "prod",
		"images":     []string{"registry.example.com/app@sha256:abc"},
	})
	defer evalResp.Body.Close()
	var eval struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(evalResp.Body).Decode(&eval); err != nil {
		t.Fatal(err)
	}
	if eval.Decision != "deny" {
		t.Fatalf("critical vuln should deny, got %+v", eval)
	}

	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	exResp := postJSON(t, srv.URL+"/admin/k8s/security/exceptions", "", map[string]any{
		"cluster_id":  "c1",
		"namespace":   "prod",
		"scope_type":  "image_digest",
		"scope_value": "sha256:abc",
		"cve_id":      "CVE-2026-0001",
		"severity":    "Critical",
		"reason":      "temporary vendor patch window",
		"ticket_url":  "https://tickets.example.com/SEC-1",
		"expires_at":  expires,
	})
	defer exResp.Body.Close()
	if exResp.StatusCode != http.StatusCreated {
		t.Fatalf("exception create status=%d", exResp.StatusCode)
	}
	var exOut struct {
		Exception store.K8sVulnerabilityException `json:"exception"`
	}
	if err := json.NewDecoder(exResp.Body).Decode(&exOut); err != nil {
		t.Fatal(err)
	}
	approveResp := postJSON(t, srv.URL+"/admin/k8s/security/exceptions/"+exOut.Exception.ID+"/approve", "", map[string]any{})
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("exception approve status=%d", approveResp.StatusCode)
	}
	evalResp2 := postJSON(t, srv.URL+"/admin/k8s/security/admission/evaluate", "", map[string]any{
		"cluster_id": "c1",
		"namespace":  "prod",
		"images":     []string{"registry.example.com/app@sha256:abc"},
	})
	defer evalResp2.Body.Close()
	var eval2 struct {
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(evalResp2.Body).Decode(&eval2); err != nil {
		t.Fatal(err)
	}
	if eval2.Decision == "deny" {
		t.Fatalf("approved exception should remove hard deny, got %+v", eval2)
	}

	rt := postJSON(t, srv.URL+"/admin/k8s/security/runtime/events", "", map[string]any{
		"cluster_id":         "c1",
		"rule":               "Terminal shell in container",
		"priority":           "High",
		"output":             "shell spawned",
		"k8s.ns.name":        "prod",
		"k8s.pod.name":       "api-1",
		"k8s.container.name": "app",
		"image":              "registry.example.com/app@sha256:abc",
	})
	rt.Body.Close()
	if rt.StatusCode != http.StatusCreated {
		t.Fatalf("runtime event status=%d", rt.StatusCode)
	}
	rtList, err := http.Get(srv.URL + "/admin/k8s/security/runtime/events?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	defer rtList.Body.Close()
	var rtOut struct {
		Correlation map[string]float64 `json:"correlation"`
	}
	if err := json.NewDecoder(rtList.Body).Decode(&rtOut); err != nil {
		t.Fatal(err)
	}
	if rtOut.Correlation["events_with_vulns"] < 1 || rtOut.Correlation["critical"] < 1 {
		t.Fatalf("runtime event should correlate to critical vulnerable image: %+v", rtOut.Correlation)
	}

	bench := postJSON(t, srv.URL+"/admin/k8s/security/benchmarks/runs", "", map[string]any{
		"cluster_id": "c1",
		"raw_json": map[string]any{
			"Controls": []any{map[string]any{
				"id": "1", "text": "control plane",
				"tests": []any{map[string]any{
					"test_number": "1.1.1", "test_desc": "secure kube-apiserver", "status": "FAIL", "remediation": "set secure flags", "scored": true,
				}},
			}},
		},
	})
	defer bench.Body.Close()
	if bench.StatusCode != http.StatusCreated {
		t.Fatalf("benchmark import status=%d", bench.StatusCode)
	}
}

func TestK8sSecurityImportsTrivyOperatorVulnerabilityReport(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "k8s-trivy-operator.ndjson"))
	logger.Start()
	defer logger.Stop(t.Context())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/admin/k8s/security/scans/import", "", map[string]any{
		"cluster_id": "c2",
		"raw_json": map[string]any{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]any{
				"name":      "replicaset-api-app",
				"namespace": "prod",
				"labels": map[string]any{
					"trivy-operator.resource.kind":  "ReplicaSet",
					"trivy-operator.resource.name":  "api-756f",
					"trivy-operator.container.name": "app",
				},
			},
			"report": map[string]any{
				"scanner": map[string]any{"name": "Trivy", "version": "0.50.0"},
				"artifact": map[string]any{
					"repository": "registry.example.com/api",
					"tag":        "2.0.0",
					"digest":     "sha256:def",
				},
				"vulnerabilities": []any{map[string]any{
					"vulnerabilityID":  "CVE-2026-0002",
					"resource":         "glibc",
					"installedVersion": "2.35",
					"fixedVersion":     "2.36",
					"severity":         "HIGH",
					"score":            8.1,
				}},
			},
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("trivy operator import status=%d", resp.StatusCode)
	}
	var out struct {
		Scan     store.K8sSecurityScanRun `json:"scan"`
		Imported int                      `json:"imported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Imported != 1 || out.Scan.Scanner != "trivy-operator" || out.Scan.ImageDigest != "sha256:def" {
		t.Fatalf("operator scan mismatch: %+v", out)
	}
	listResp, err := http.Get(srv.URL + "/admin/k8s/security/vuln/images?cluster_id=c2&severity=High")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	var listed struct {
		Vulnerabilities []store.K8sImageVulnerability `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Vulnerabilities) != 1 ||
		listed.Vulnerabilities[0].Namespace != "prod" ||
		listed.Vulnerabilities[0].WorkloadKind != "ReplicaSet" ||
		listed.Vulnerabilities[0].ContainerName != "app" {
		t.Fatalf("operator vulnerability context mismatch: %+v", listed.Vulnerabilities)
	}

	evalResp := postJSON(t, srv.URL+"/admin/k8s/security/admission/evaluate", "", map[string]any{
		"cluster_id": "c2",
		"namespace":  "prod",
		"images":     []string{"registry.example.com/api@sha256:def"},
	})
	defer evalResp.Body.Close()
	var eval struct {
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(evalResp.Body).Decode(&eval); err != nil {
		t.Fatal(err)
	}
	if eval.Decision != "approval_required" {
		t.Fatalf("high vulnerability should require approval, got %+v", eval)
	}
}

func TestK8sSecurityImportsRawScannerArtifactBody(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "k8s-raw-scan.ndjson"))
	logger.Start()
	defer logger.Stop(t.Context())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	raw := `{
		"ArtifactName": "registry.example.com/direct:3.0.0",
		"Results": [{
			"Target": "busybox",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2026-0003",
				"PkgName": "busybox",
				"InstalledVersion": "1.36",
				"FixedVersion": "1.37",
				"Severity": "HIGH"
			}]
		}]
	}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/admin/k8s/security/scans/import?cluster_id=c3&namespace=prod&scanner=trivy&image=registry.example.com/direct:3.0.0&image_digest=sha256:raw&container_name=app", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("raw scan import status=%d", resp.StatusCode)
	}
	var imported struct {
		Scan     store.K8sSecurityScanRun `json:"scan"`
		Imported int                      `json:"imported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&imported); err != nil {
		t.Fatal(err)
	}
	if imported.Imported != 1 || imported.Scan.ClusterID != "c3" || imported.Scan.ImageDigest != "sha256:raw" {
		t.Fatalf("raw import mismatch: %+v", imported)
	}
}

func TestK8sSecurityAdmissionReviewAndExpiredExceptionView(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "k8s-admission-review.ndjson"))
	logger.Start()
	defer logger.Stop(t.Context())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	importResp := postJSON(t, srv.URL+"/admin/k8s/security/scans/import", "", map[string]any{
		"cluster_id":   "c4",
		"image_digest": "sha256:deny",
		"scanner":      "trivy",
		"raw_json": map[string]any{"Results": []any{map[string]any{"Vulnerabilities": []any{map[string]any{
			"VulnerabilityID": "CVE-2026-0004", "PkgName": "openssl", "Severity": "CRITICAL",
		}}}}},
	})
	importResp.Body.Close()
	if importResp.StatusCode != http.StatusCreated {
		t.Fatalf("import status=%d", importResp.StatusCode)
	}

	review := map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]any{
			"uid":       "review-1",
			"operation": "CREATE",
			"namespace": "prod",
			"kind":      map[string]any{"kind": "Pod"},
			"object": map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "deny-me", "namespace": "prod"},
				"spec":       map[string]any{"containers": []any{map[string]any{"name": "app", "image": "registry.example.com/app@sha256:deny"}}},
			},
		},
	}
	reviewResp := postJSON(t, srv.URL+"/admin/k8s/security/admission/review?cluster_id=c4", "", review)
	defer reviewResp.Body.Close()
	var out struct {
		Response struct {
			UID     string            `json:"uid"`
			Allowed bool              `json:"allowed"`
			Status  map[string]any    `json:"status"`
			Audit   map[string]string `json:"auditAnnotations"`
		} `json:"response"`
	}
	if err := json.NewDecoder(reviewResp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Response.UID != "review-1" || out.Response.Allowed || out.Response.Audit["clustara.io/security-decision"] != "deny" {
		t.Fatalf("admission review mismatch: %+v", out.Response)
	}

	_ = db.CreateK8sVulnerabilityException(t.Context(), store.K8sVulnerabilityException{
		ID: "expired-ex", ClusterID: "c4", ScopeType: "image_digest", ScopeValue: "sha256:deny",
		CVEID: "CVE-2026-0004", Reason: "expired", ExpiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano), Status: "approved",
	})
	exResp, err := http.Get(srv.URL + "/admin/k8s/security/exceptions?cluster_id=c4")
	if err != nil {
		t.Fatal(err)
	}
	defer exResp.Body.Close()
	var exOut struct {
		Exceptions []map[string]any `json:"exceptions"`
	}
	if err := json.NewDecoder(exResp.Body).Decode(&exOut); err != nil {
		t.Fatal(err)
	}
	if len(exOut.Exceptions) == 0 || exOut.Exceptions[0]["effective_status"] != "expired" {
		t.Fatalf("expired exception should be surfaced: %+v", exOut.Exceptions)
	}
}

func TestK8sSecurityBenchmarkJobManifest(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "k8s-bench-manifest.ndjson"))
	logger.Start()
	defer logger.Stop(t.Context())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/admin/k8s/security/benchmarks/job-manifest", "", map[string]any{
		"namespace": "kube-system", "job_name": "Clustara Kube Bench", "image": "registry.local/kube-bench:v1",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("job manifest status=%d", resp.StatusCode)
	}
	var out struct {
		Manifest string   `json:"manifest"`
		Warnings []string `json:"warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Manifest, "kind: Job") || !strings.Contains(out.Manifest, "name: clustara-kube-bench") || !strings.Contains(out.Manifest, "registry.local/kube-bench:v1") {
		t.Fatalf("unexpected job manifest:\n%s", out.Manifest)
	}
	if len(out.Warnings) == 0 {
		t.Fatalf("expected safety warnings")
	}
}

func TestK8sSecurityRawSBOMUploadAndMultiDocAdmission(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "k8s-sbom-multidoc.ndjson"))
	logger.Start()
	defer logger.Stop(t.Context())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	sbomRaw := `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"openssl","version":"3.0.0","purl":"pkg:apk/openssl@3.0.0"}]}`
	sbomReq, err := http.NewRequest(http.MethodPost, srv.URL+"/admin/k8s/security/sboms?image=registry.example.com/multi:1&image_digest=sha256:multi&generator=syft", strings.NewReader(sbomRaw))
	if err != nil {
		t.Fatal(err)
	}
	sbomReq.Header.Set("Content-Type", "application/json")
	sbomResp, err := http.DefaultClient.Do(sbomReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sbomResp.Body.Close()
	if sbomResp.StatusCode != http.StatusCreated {
		t.Fatalf("raw sbom upload status=%d", sbomResp.StatusCode)
	}
	var sbomOut struct {
		SBOM store.K8sSBOM `json:"sbom"`
	}
	if err := json.NewDecoder(sbomResp.Body).Decode(&sbomOut); err != nil {
		t.Fatal(err)
	}
	if sbomOut.SBOM.PackageCount != 1 || sbomOut.SBOM.ImageDigest != "sha256:multi" {
		t.Fatalf("raw sbom mismatch: %+v", sbomOut.SBOM)
	}

	importResp := postJSON(t, srv.URL+"/admin/k8s/security/scans/import", "", map[string]any{
		"cluster_id":   "c5",
		"image_digest": "sha256:multi",
		"scanner":      "trivy",
		"raw_json": map[string]any{"Results": []any{map[string]any{"Vulnerabilities": []any{map[string]any{
			"VulnerabilityID": "CVE-2026-0005", "PkgName": "openssl", "Severity": "HIGH",
		}}}}},
	})
	importResp.Body.Close()
	if importResp.StatusCode != http.StatusCreated {
		t.Fatalf("import status=%d", importResp.StatusCode)
	}
	manifest := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
  namespace: prod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    spec:
      containers:
      - name: app
        image: registry.example.com/multi@sha256:multi
`
	evalResp := postJSON(t, srv.URL+"/admin/k8s/security/admission/evaluate", "", map[string]any{
		"cluster_id": "c5",
		"manifest":   manifest,
	})
	defer evalResp.Body.Close()
	var eval struct {
		Decision string           `json:"decision"`
		Results  []map[string]any `json:"results"`
	}
	if err := json.NewDecoder(evalResp.Body).Decode(&eval); err != nil {
		t.Fatal(err)
	}
	if eval.Decision != "approval_required" {
		t.Fatalf("multi-doc high vulnerability should require approval, got %+v", eval)
	}
}
