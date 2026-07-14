package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

func newSecurityIngestAuthServer(t *testing.T) (*store.SQLStore, *httptest.Server) {
	t.Helper()
	db := openTestStore(t)
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()); db.Close() })
	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.Auth.AdminToken = "admin-secret"
	s, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return db, srv
}

func postSecurityArtifact(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSecurityArtifactImportAcceptsScopedAPIKey(t *testing.T) {
	db, srv := newSecurityIngestAuthServer(t)
	secret := "vc_sk_ci_security_import"
	if err := db.UpsertAPIKey(context.Background(), store.APIKeyRecord{ID: "key_ci_scan", Name: "trivy-ci", KeyHash: hashProxyKey(secret), Status: "active", Role: "service_account", Scopes: []string{"security:scan"}}); err != nil {
		t.Fatal(err)
	}
	trivy := `{"ArtifactName":"registry.example/app:1","Results":[{"Target":"app","Vulnerabilities":[]}]}`
	resp := postSecurityArtifact(t, srv.URL+"/admin/k8s/security/scans/import?scanner=trivy&image=registry.example/app:1", secret, trivy)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("scoped Trivy import status=%d body=%s", resp.StatusCode, body)
	}
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`
	resp = postSecurityArtifact(t, srv.URL+"/admin/k8s/security/sboms?image=registry.example/app:1&generator=trivy", secret, sbom)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("scoped SBOM import status=%d body=%s", resp.StatusCode, body)
	}
}

func TestSecurityArtifactImportReturns401Vs403Accurately(t *testing.T) {
	db, srv := newSecurityIngestAuthServer(t)
	wrongScope := "vc_sk_ci_read_only"
	if err := db.UpsertAPIKey(context.Background(), store.APIKeyRecord{ID: "key_ci_read", Name: "read-only", KeyHash: hashProxyKey(wrongScope), Status: "active", Scopes: []string{"security:read"}}); err != nil {
		t.Fatal(err)
	}
	body := `{"ArtifactName":"app","Results":[]}`
	for _, tc := range []struct {
		token string
		want  int
	}{{"unknown-token", http.StatusUnauthorized}, {wrongScope, http.StatusForbidden}, {"", http.StatusUnauthorized}} {
		resp := postSecurityArtifact(t, srv.URL+"/admin/k8s/security/scans/import?scanner=trivy", tc.token, body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("token=%q status=%d want=%d", tc.token, resp.StatusCode, tc.want)
		}
	}
}
