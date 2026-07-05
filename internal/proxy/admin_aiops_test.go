package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

func TestAIOpsProblems(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	for _, inc := range []store.K8sIncident{
		{DedupKey: "d1", ClusterID: "c1", Namespace: "prod", Kind: "Pod", Name: "api-1", Condition: "CrashLoopBackOff", Severity: "high", Title: "api crash", Evidence: []string{"BackOff", "exit 1"}},
		{DedupKey: "d2", ClusterID: "c1", Namespace: "prod", Kind: "Pod", Name: "api-2", Condition: "CrashLoopBackOff", Severity: "medium", Title: "api crash", Evidence: []string{"BackOff"}},
	} {
		if _, _, err := db.UpsertK8sIncidentByKey(ctx, inc, func(prefix string) string { return prefix + "_" + inc.DedupKey }); err != nil {
			t.Fatal(err)
		}
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "aiops.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/problems")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Problems []aiopsProblem `json:"problems"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(out.Problems) != 1 {
		t.Fatalf("problem response mismatch status=%d out=%+v", resp.StatusCode, out)
	}
	p := out.Problems[0]
	if p.IncidentCount != 2 || p.Severity != "high" || p.Confidence <= 0 || len(p.AffectedResources) != 2 {
		t.Fatalf("problem rollup mismatch: %+v", p)
	}
}
