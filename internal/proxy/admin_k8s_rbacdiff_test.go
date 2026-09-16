package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/store"
)

// A Role whose latest revision dropped its resourceNames is reported as an expansion, and the
// entry names the cluster the UI's YAML deep link keys on; a Role that only narrowed "*" to a
// concrete resource is not reported at all.
func TestK8sRBACDiffReportsCoverageNotStringDifference(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	ctx := context.Background()
	rule := func(resources []any, verbs []any, names []any) map[string]any {
		r := map[string]any{"apiGroups": []any{""}, "resources": resources, "verbs": verbs}
		if names != nil {
			r["resourceNames"] = names
		}
		return r
	}
	seed := func(cluster, name string, from, to map[string]any) {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID: cluster + "/" + name, ClusterID: cluster, Kind: "Role", Namespace: "payments", Name: name,
			Spec: map[string]any{"rules": []any{to}},
		}); err != nil {
			t.Fatal(err)
		}
		for i, spec := range []map[string]any{from, to} {
			if _, err := db.RecordK8sRevision(ctx, store.K8sResourceRevision{
				ClusterID: cluster, Kind: "Role", Namespace: "payments", Name: name,
				Spec:       map[string]any{"rules": []any{spec}},
				ObservedAt: fmt.Sprintf("2026-09-1%dT00:00:00Z", i),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	seed("c-prod", "cert-reader",
		rule([]any{"secrets"}, []any{"get"}, []any{"tls-cert"}),
		rule([]any{"secrets"}, []any{"get"}, nil))
	seed("c-dr", "narrowed",
		rule([]any{"*"}, []any{"get"}, nil),
		rule([]any{"configmaps"}, []any{"get"}, nil))

	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "rbacdiff.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/admin/k8s/rbac-diff")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Entries []rbacDiffEntry `json:"entries"`
		Count   int             `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || body.Count != 1 || len(body.Entries) != 1 {
		t.Fatalf("expected exactly the resourceNames drop reported, status=%d body=%+v", resp.StatusCode, body)
	}
	e := body.Entries[0]
	if e.ClusterID != "c-prod" || e.Name != "cert-reader" {
		t.Fatalf("entry should name the cluster it came from, got %+v", e)
	}
	if len(e.Added) != 1 || e.Added[0] != "|secrets|get" || len(e.Risky) != 1 {
		t.Fatalf("expected the unrestricted secrets/get as a risky addition, got %+v", e)
	}
}
