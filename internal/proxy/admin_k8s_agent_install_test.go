package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestAgentInstallManifestUsesSameReleaseImageAndScopedToken(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://upstream.invalid", "secret")
	cfg.Auth.AdminToken = "admin-secret"
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	clusterID := "k8scl_agent_install"
	if err := db.UpsertK8sCluster(context.Background(), store.K8sCluster{ID: clusterID, Name: "remote", ServerURL: "https://k8s.test", AuthMode: "token", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"cluster_id": clusterID, "clustara_url": "https://clustara.example.com"})
	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/admin/k8s/agent/install-manifest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, b)
	}
	var result struct {
		Manifest string `json:"manifest"`
		Image    string `json:"image"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ghcr.io/hkjang/clustara:" + AppVersion, `command: ["/app/clustara-agent"]`, clusterID, "https://clustara.example.com", "clustara_agent_v1."} {
		if !strings.Contains(result.Manifest, want) {
			t.Fatalf("manifest missing %q", want)
		}
	}
	if strings.Contains(result.Manifest, "admin-secret") {
		t.Fatal("manifest must not expose the administrator token")
	}
}

func TestAgentScopedTokenIsBoundToCluster(t *testing.T) {
	cfg := testConfig("http://upstream.invalid", "secret")
	server := &Server{cfg: cfg}
	token := server.issueAgentToken("cluster-a", time.Now().Add(time.Hour))
	if !server.verifyAgentToken(token, "cluster-a") {
		t.Fatal("issued token should verify for its cluster")
	}
	if server.verifyAgentToken(token, "cluster-b") {
		t.Fatal("agent token must not authorize another cluster")
	}
	if server.verifyAgentToken(server.issueAgentToken("cluster-a", time.Now().Add(-time.Second)), "cluster-a") {
		t.Fatal("expired agent token must be rejected")
	}
}
