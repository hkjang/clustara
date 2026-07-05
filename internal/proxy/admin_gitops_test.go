package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"clustara/internal/store"
)

func TestGitOpsOverview(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod-1", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	nextID := 0
	newTestStackID := func(prefix string) string {
		nextID++
		return prefix + "_test_" + strconv.Itoa(nextID)
	}
	stack := store.K8sApplicationStack{
		ID: "stack1", Name: "payments", ClusterID: "c1", Namespace: "prod", SourceType: "git",
		Manifest: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\n", ManifestHash: "hash1",
		GitRepo: "https://git.local/platform/payments.git", GitBranch: "main", GitPath: "deploy/prod",
		SyncPolicy: "approval", Status: "applied", CreatedBy: "tester",
	}
	if _, _, err := db.UpsertK8sStack(ctx, stack, newTestStackID); err != nil {
		t.Fatal(err)
	}
	stack.Manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\nspec:\n  replicas: 2\n"
	stack.ManifestHash = "hash2"
	if _, _, err := db.UpsertK8sStack(ctx, stack, newTestStackID); err != nil {
		t.Fatal(err)
	}
	if err := db.SetK8sStackStatus(ctx, "stack1", "drifted"); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sStackApplyHistory(ctx, store.K8sStackApplyHistory{
		ID: "hist1", StackID: "stack1", Operation: "apply", RevisionNo: 2, ClusterID: "c1", Status: "failed", Failed: 1, Actor: "tester",
	}); err != nil {
		t.Fatal(err)
	}

	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "gitops.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/gitops/overview?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/gitops/overview = %d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Summary gitOpsOverviewSummary `json:"summary"`
		Stacks  []gitOpsStackPosture  `json:"stacks"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary.Stacks != 1 || out.Summary.GitConnected != 1 || out.Summary.Drifted != 1 || out.Summary.ApplyFailures != 1 || out.Summary.RollbackReady != 1 {
		t.Fatalf("summary mismatch: %+v", out.Summary)
	}
	if len(out.Stacks) != 1 || out.Stacks[0].RiskLevel != "high" || out.Stacks[0].RecommendedAction != "rollback_candidate_available" {
		t.Fatalf("stack posture mismatch: %+v", out.Stacks)
	}
}
