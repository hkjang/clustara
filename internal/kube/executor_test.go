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

func TestExecutorRolloutRestartCarriesAuditAnnotations(t *testing.T) {
	var cap capturedReq
	srv := executorTestServer(t, &cap)
	defer srv.Close()
	c := newExecClient(t, srv.URL)
	err := c.RolloutRestartWithMetadata(context.Background(), "Deployment", "prod", "api", RolloutRestartMetadata{
		RestartedAt: "2026-07-27T06:45:30Z", RestartedBy: "user-1", ActionID: "action-1", Reason: "config refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"clustara.io/restartedAt", "kubectl.kubernetes.io/restartedAt", "clustara.io/restartedBy", "clustara.io/actionId", "clustara.io/reason", "action-1", "user-1"} {
		if !strings.Contains(cap.body, want) {
			t.Fatalf("patch missing %q: %s", want, cap.body)
		}
	}
}

func TestExecutorRollbackDeploymentTemplate(t *testing.T) {
	var cap capturedReq
	srv := executorTestServer(t, &cap)
	defer srv.Close()
	c := newExecClient(t, srv.URL)
	template := map[string]any{
		"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
		"spec":     map[string]any{"containers": []any{map[string]any{"name": "api", "image": "api:v1"}}},
	}
	if err := c.RollbackDeploymentTemplate(context.Background(), "prod", "api", template, RolloutRestartMetadata{
		RestartedAt: "2026-07-27T07:00:00Z", RestartedBy: "root", ActionID: "rollout-1",
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/apis/apps/v1/namespaces/prod/deployments/api", `"image":"api:v1"`, `"clustara.io/restartedAt":null`, `"clustara.io/rollbackBy":"root"`} {
		if !strings.Contains(cap.path+" "+cap.body, want) {
			t.Fatalf("rollback patch missing %q: %+v", want, cap)
		}
	}
	if _, exists := template["metadata"].(map[string]any)["annotations"]; exists {
		t.Fatal("rollback must not mutate the persisted template snapshot")
	}
}

func TestExecutorAcceptsWorkloadKindAliases(t *testing.T) {
	tests := []struct {
		kind string
		path string
	}{
		{"deployment", "/apis/apps/v1/namespaces/ns/deployments/api"},
		{"deployments", "/apis/apps/v1/namespaces/ns/deployments/api"},
		{"deployment.apps", "/apis/apps/v1/namespaces/ns/deployments/api"},
		{"apps/v1 Deployment", "/apis/apps/v1/namespaces/ns/deployments/api"},
		{"statefulsets", "/apis/apps/v1/namespaces/ns/statefulsets/api"},
		{"daemonset.apps", "/apis/apps/v1/namespaces/ns/daemonsets/api"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			var cap capturedReq
			srv := executorTestServer(t, &cap)
			defer srv.Close()
			c := newExecClient(t, srv.URL)
			if err := c.RolloutRestart(context.Background(), tt.kind, "ns", "api"); err != nil {
				t.Fatal(err)
			}
			if cap.path != tt.path {
				t.Fatalf("path = %s, want %s", cap.path, tt.path)
			}
		})
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

	if err := c.DeletePod(context.Background(), "Pod", "default", "p1"); err != nil {
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

func TestExecutorRolloutRestartRejectsPodWithGuidance(t *testing.T) {
	c := newExecClient(t, "http://unused.invalid")
	err := c.RolloutRestart(context.Background(), "Pod", "default", "p")
	if err == nil || !strings.Contains(err.Error(), "owner Deployment/StatefulSet/DaemonSet") {
		t.Fatalf("pod rollout restart should explain owner target guidance, got %v", err)
	}
}

func TestExecutorAcceptsKubectlShortNames(t *testing.T) {
	// "sts" and "ds" have their own cases in normalizeWorkloadKind, so the executor is meant to
	// accept them: ResourceKind is free-form request input and kubectl short names are what an
	// operator (or the Ops Agent) types.
	tests := []struct{ kind, path string }{
		{"sts", "/apis/apps/v1/namespaces/ns/statefulsets/api"},
		{"ds", "/apis/apps/v1/namespaces/ns/daemonsets/api"},
		{"deploy", "/apis/apps/v1/namespaces/ns/deployments/api"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			var cap capturedReq
			srv := executorTestServer(t, &cap)
			defer srv.Close()
			c := newExecClient(t, srv.URL)
			if err := c.RolloutRestart(context.Background(), tt.kind, "ns", "api"); err != nil {
				t.Fatal(err)
			}
			if cap.path != tt.path {
				t.Fatalf("path = %s, want %s", cap.path, tt.path)
			}
		})
	}
}

func TestExecutorScaleRejectsDaemonSet(t *testing.T) {
	// apps/v1 DaemonSet has no /scale subresource, so the request can only 404 — and it does so
	// after the whole request → impact → approval workflow has already completed.
	var cap capturedReq
	srv := executorTestServer(t, &cap)
	defer srv.Close()
	c := newExecClient(t, srv.URL)
	err := c.Scale(context.Background(), "DaemonSet", "ns", "fluentd", 3)
	if err == nil {
		t.Fatal("scale should reject DaemonSet up front")
	}
	if !strings.Contains(err.Error(), "DaemonSet") {
		t.Fatalf("error should name the kind, got %v", err)
	}
	if cap.method != "" {
		t.Fatalf("rejected scale must not reach the API server, got %+v", cap)
	}
}

// TestExecutorDeletePodRejectsNonPodKind covers the target this URL always addresses. The action
// request carries a free-form resource_kind, so a record approved as "Deployment/web delete_pod"
// used to issue DELETE /api/v1/namespaces/{ns}/pods/web — a different object than the approver
// reviewed, with the deletion recorded against the Deployment's name in the audit trail.
func TestExecutorDeletePodRejectsNonPodKind(t *testing.T) {
	for _, kind := range []string{"Deployment", "StatefulSet", "Node", "Service"} {
		t.Run(kind, func(t *testing.T) {
			var cap capturedReq
			srv := executorTestServer(t, &cap)
			defer srv.Close()
			c := newExecClient(t, srv.URL)
			err := c.DeletePod(context.Background(), kind, "prod", "web")
			if err == nil {
				t.Fatalf("delete pod must reject kind %q", kind)
			}
			if !strings.Contains(err.Error(), kind) {
				t.Fatalf("error should name the requested kind, got %v", err)
			}
			if cap.method != "" {
				t.Fatalf("rejected delete must not reach the API server, got %s %s", cap.method, cap.path)
			}
		})
	}
	// The Pod spellings a stored request actually carries still go through.
	for _, kind := range []string{"Pod", "pods", "po", "v1/Pod", ""} {
		var cap capturedReq
		srv := executorTestServer(t, &cap)
		c := newExecClient(t, srv.URL)
		if err := c.DeletePod(context.Background(), kind, "prod", "web"); err != nil {
			t.Fatalf("kind %q should be accepted as a Pod: %v", kind, err)
		}
		if cap.method != http.MethodDelete || cap.path != "/api/v1/namespaces/prod/pods/web" {
			t.Fatalf("kind %q: wrong request %+v", kind, cap)
		}
		srv.Close()
	}
}

func TestExecutorRejectsBlankTarget(t *testing.T) {
	// A blank name does not produce a 404: it produces the resource *collection* URL, and the
	// Kubernetes API serves DELETE on a Pod collection as deletecollection — every Pod in the
	// namespace. Nothing may be sent for a target the caller did not name.
	cases := []struct {
		name string
		call func(*HTTPClient) error
	}{
		{"delete pod without name", func(c *HTTPClient) error { return c.DeletePod(context.Background(), "Pod", "prod", "  ") }},
		{"delete pod without namespace", func(c *HTTPClient) error { return c.DeletePod(context.Background(), "Pod", "", "api-0") }},
		{"scale without name", func(c *HTTPClient) error { return c.Scale(context.Background(), "Deployment", "prod", "", 0) }},
		{"restart without name", func(c *HTTPClient) error { return c.RolloutRestart(context.Background(), "Deployment", "prod", " ") }},
		{"cordon without node", func(c *HTTPClient) error { return c.SetCordon(context.Background(), " ", true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cap capturedReq
			srv := executorTestServer(t, &cap)
			defer srv.Close()
			c := newExecClient(t, srv.URL)
			if err := tc.call(c); err == nil {
				t.Fatal("blank target must be rejected")
			}
			if cap.method != "" {
				t.Fatalf("blank target must not reach the API server, got %s %s", cap.method, cap.path)
			}
		})
	}
}
