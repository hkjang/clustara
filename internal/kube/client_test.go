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

func TestHTTPClientCollectNodeMetrics(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/metrics.k8s.io/v1beta1/nodes" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"worker-1"},"timestamp":"2026-07-10T01:02:03Z","usage":{"cpu":"1250m","memory":"2Gi"}}]}`))
	}))
	defer api.Close()
	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := client.CollectNodeMetrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 || metrics[0].ResourceName != "worker-1" || metrics[0].CPUMillicores != 1250 || metrics[0].MemoryBytes != 2*(1<<30) {
		t.Fatalf("unexpected node metrics: %+v", metrics)
	}
}

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

func TestHTTPClientListFollowsContinueTokens(t *testing.T) {
	requests := []string{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continue") == "" {
			_, _ = w.Write([]byte(`{"metadata":{"continue":"next-page"},"items":[{"metadata":{"name":"p1"}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"metadata":{},"items":[{"metadata":{"name":"p2"}}]}`))
	}))
	defer api.Close()
	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	items, err := client.list(context.Background(), "/api/v1/pods")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items across pages, got %d", len(items))
	}
	if len(requests) != 2 {
		t.Fatalf("expected 2 paginated requests, got %d (%v)", len(requests), requests)
	}
	if !strings.Contains(requests[0], "limit=500") || strings.Contains(requests[0], "continue=") {
		t.Fatalf("unexpected first query: %q", requests[0])
	}
	if !strings.Contains(requests[1], "continue=next-page") {
		t.Fatalf("second query should carry continue token, got %q", requests[1])
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

func TestHTTPClientPodExecFallback(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	var gotCommand []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "websocket disabled in test", http.StatusBadRequest)
			return
		}
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCommand = r.URL.Query()["command"]
		_, _ = w.Write([]byte("exec ok\n"))
	}))
	defer api.Close()
	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.PodExec(context.Background(), "default", "api-1", PodExecOptions{
		Container: "app", Command: "ls /app",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/namespaces/default/pods/api-1/exec" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if strings.Join(gotCommand, " ") != "ls /app" {
		t.Fatalf("command query = %+v", gotCommand)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if res.Stdout != "exec ok\n" || res.ExitCode != 0 {
		t.Fatalf("unexpected exec result: %+v", res)
	}
}

func writeTestFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
