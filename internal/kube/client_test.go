package kube

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseKubeconfigReadsFileBackedCertificates(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	writeTestFile(t, caPath, "ca-pem")
	writeTestFile(t, certPath, "client-cert-pem")
	writeTestFile(t, keyPath, "client-key-pem")

	raw := `apiVersion: v1
kind: Config
clusters:
- name: minikube
  cluster:
    server: https://127.0.0.1:52893
    certificate-authority: ` + filepath.ToSlash(caPath) + `
users:
- name: minikube
  user:
    client-certificate: ` + filepath.ToSlash(certPath) + `
    client-key: ` + filepath.ToSlash(keyPath) + `
contexts:
- name: minikube
  context:
    cluster: minikube
    user: minikube
current-context: minikube
`

	cfg, err := parseKubeconfig(raw, "")
	if err != nil {
		t.Fatalf("parseKubeconfig returned error: %v", err)
	}
	if cfg.ServerURL != "https://127.0.0.1:52893" {
		t.Fatalf("ServerURL = %q", cfg.ServerURL)
	}
	if string(cfg.CACertPEM) != "ca-pem" {
		t.Fatalf("CACertPEM = %q", string(cfg.CACertPEM))
	}
	if string(cfg.ClientCertPEM) != "client-cert-pem" {
		t.Fatalf("ClientCertPEM = %q", string(cfg.ClientCertPEM))
	}
	if string(cfg.ClientKeyPEM) != "client-key-pem" {
		t.Fatalf("ClientKeyPEM = %q", string(cfg.ClientKeyPEM))
	}
}

func TestSummarizeStatusDaemonSetUsesDaemonSetCounters(t *testing.T) {
	obj := map[string]any{
		"status": map[string]any{
			"desiredNumberScheduled": float64(1),
			"numberReady":            float64(1),
			"numberAvailable":        float64(1),
			// These Deployment fields are absent on DaemonSet status in real clusters.
			"readyReplicas":     float64(0),
			"availableReplicas": float64(0),
		},
	}

	if got := summarizeStatus("DaemonSet", obj); got != "Available 1/1" {
		t.Fatalf("summarizeStatus(DaemonSet) = %q", got)
	}
}

func TestHTTPClientPodLogs(t *testing.T) {
	var gotPath, gotQuery, gotAuth string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("hello\nerror line\n"))
	}))
	defer api.Close()
	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := client.PodLogs(context.Background(), "default", "api-1", PodLogOptions{
		Container: "app", Previous: true, TailLines: 50, SinceSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if body != "hello\nerror line\n" {
		t.Fatalf("body = %q", body)
	}
	if gotPath != "/api/v1/namespaces/default/pods/api-1/log" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{"container=app", "previous=true", "tailLines=50", "sinceSeconds=300"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}

func TestHTTPClientPodLogsStream(t *testing.T) {
	var gotPath, gotQuery string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("line 1\nline 2\n"))
	}))
	defer api.Close()
	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := client.PodLogsStream(context.Background(), "default", "api-1", PodLogOptions{Container: "app", TailLines: 25})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	gotBody, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != "line 1\nline 2\n" {
		t.Fatalf("body = %q", string(gotBody))
	}
	if gotPath != "/api/v1/namespaces/default/pods/api-1/log" {
		t.Fatalf("path = %q", gotPath)
	}
	for _, want := range []string{"container=app", "follow=true", "tailLines=25"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
}

func writeTestFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
