package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"clustara/internal/store"
)

// TestK8sActionExecuteRefusesTargetKindMismatch covers the gap between the approved record and the
// object the executor touches. Each executable action addresses one fixed resource type — delete_pod
// deletes the Pod named resource_name, cordon patches the Node named resource_name — while
// resource_kind is free input that nothing checked. An action recorded, reviewed and approved as
// "Deployment/web delete_pod" therefore executed as a delete of the *Pod* named web, and the audit
// trail attributed that deletion to the Deployment.
func TestK8sActionExecuteRefusesTargetKindMismatch(t *testing.T) {
	var mu sync.Mutex
	var mutations []string
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			mu.Lock()
			mutations = append(mutations, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer kubeAPI.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "kind-mismatch-cluster", "server_url": kubeAPI.URL, "auth_mode": "token", "token": "test-token",
	})
	defer resp.Body.Close()
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		id, action, kind, name string
	}{
		{"act_kind_delete", "delete_pod", "Deployment", "web"},
		{"act_kind_cordon", "cordon", "Pod", "api-7d9-xyz"},
	}
	for _, tc := range cases {
		if err := db.InsertK8sActionRequest(context.Background(), store.K8sActionRequest{
			ID: tc.id, ClusterID: created.Cluster.ID, Namespace: "default", ResourceKind: tc.kind, ResourceName: tc.name,
			Action: tc.action, RiskLevel: "high", Status: "approved", RequestedBy: "dev", ApprovedBy: "approver",
			DryRunDiff: tc.action + " " + tc.name, IdempotencyKey: "idem-" + tc.id, CommandHash: "hash-" + tc.id,
		}); err != nil {
			t.Fatal(err)
		}
		resp := postJSON(t, proxy.URL+"/admin/k8s/actions/"+tc.id+"/execute", "", map[string]any{})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("%s on kind %s must not execute, got 200 %s", tc.action, tc.kind, body)
		}
		if !strings.Contains(string(body), "kind") {
			t.Fatalf("%s on kind %s: failure should explain the target mismatch, got %s", tc.action, tc.kind, body)
		}
		act, err := db.GetK8sActionRequest(context.Background(), tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if act.Status != "failed" {
			t.Fatalf("%s on kind %s should be recorded as failed, got %q", tc.action, tc.kind, act.Status)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(mutations) != 0 {
		t.Fatalf("a kind-mismatched action must not reach the Kubernetes API, got %v", mutations)
	}
}
