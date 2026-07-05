package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestSecurityPosture(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod-1", Status: "ready", LastConnectedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
		ID: "pod1", ClusterID: "c1", Kind: "Pod", Namespace: "prod", Name: "api-1", HealthScore: 70, RiskLevel: "medium",
		Spec: map[string]any{
			"hostNetwork": true,
			"containers": []any{map[string]any{
				"name": "api", "image": "nginx:latest",
				"securityContext": map[string]any{"privileged": true, "allowPrivilegeEscalation": true},
			}},
		},
		StatusObject: map[string]any{"containerStatuses": []any{map[string]any{"image": "nginx:latest", "imageID": "docker-pullable://nginx@sha256:abc"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sSecurityFinding(ctx, store.K8sSecurityFinding{
		ID: "finding1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Pod", ResourceName: "api-1",
		Rule: "runtime-threat", Severity: "critical", Status: "open",
	}); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "secops.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/security/posture")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Clusters []securityClusterPosture `json:"clusters"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(out.Clusters) != 1 {
		t.Fatalf("posture mismatch status=%d out=%+v", resp.StatusCode, out)
	}
	row := out.Clusters[0]
	if row.CriticalFindings != 1 || row.Privileged != 1 || row.MutableImages != 1 || row.Recommendation == "" {
		t.Fatalf("posture row mismatch: %+v", row)
	}
}
