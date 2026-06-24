package kube

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type capturedReq struct {
	method, path, body, contentType string
}

func executorTestServer(t *testing.T, captured *capturedReq) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.body = string(b)
		captured.contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
}

func newExecClient(t *testing.T, url string) *HTTPClient {
	t.Helper()
	c, err := NewHTTPClient(HTTPClientConfig{ServerURL: url, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExecutorScale(t *testing.T) {
	var cap capturedReq
	srv := executorTestServer(t, &cap)
	defer srv.Close()
	c := newExecClient(t, srv.URL)
	if err := c.Scale(context.Background(), "Deployment", "default", "api", 5); err != nil {
		t.Fatal(err)
	}
	if cap.method != http.MethodPatch || cap.path != "/apis/apps/v1/namespaces/default/deployments/api/scale" {
		t.Fatalf("scale request wrong: %+v", cap)
	}
	if !strings.Contains(cap.body, `"replicas":5`) || !strings.Contains(cap.contentType, "merge-patch") {
		t.Fatalf("scale body/content-type wrong: %+v", cap)
	}
}

func TestExecutorRolloutRestart(t *testing.T) {
	var cap capturedReq
	srv := executorTestServer(t, &cap)
	defer srv.Close()
	c := newExecClient(t, srv.URL)
	if err := c.RolloutRestart(context.Background(), "StatefulSet", "ns", "db"); err != nil {
		t.Fatal(err)
	}
	if cap.path != "/apis/apps/v1/namespaces/ns/statefulsets/db" || !strings.Contains(cap.body, "restartedAt") {
		t.Fatalf("rollout restart wrong: %+v", cap)
	}
}

func TestExecutorCordonAndDelete(t *testing.T) {
	var cap capturedReq
	srv := executorTestServer(t, &cap)
	defer srv.Close()
	c := newExecClient(t, srv.URL)

	if err := c.SetCordon(context.Background(), "node-1", true); err != nil {
		t.Fatal(err)
	}
	if cap.path != "/api/v1/nodes/node-1" || !strings.Contains(cap.body, `"unschedulable":true`) {
		t.Fatalf("cordon wrong: %+v", cap)
	}

	if err := c.DeletePod(context.Background(), "default", "p1"); err != nil {
		t.Fatal(err)
	}
	if cap.method != http.MethodDelete || cap.path != "/api/v1/namespaces/default/pods/p1" {
		t.Fatalf("delete pod wrong: %+v", cap)
	}
}

func TestExecutorScaleRejectsBadKind(t *testing.T) {
	c := newExecClient(t, "http://unused.invalid")
	if err := c.Scale(context.Background(), "Pod", "default", "p", 3); err == nil {
		t.Fatal("scale should reject non-workload kind")
	}
}
