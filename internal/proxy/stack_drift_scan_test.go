package proxy

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"clustara/internal/store"

	_ "modernc.org/sqlite"
)

const driftStackManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  replicas: 1
`

// Drift is decided by absence: a declared resource that is not in the fetched
// inventory is reported "missing", and Synced is false whenever any is. The
// inventory error was discarded, so a failed fetch produced an empty inventory
// and reported every declared resource as missing — a database problem rendered
// as "the whole stack is gone".
//
// The remediation this screen invites is re-applying the manifest, so a false
// "missing" provokes a real write to the cluster.
func TestDriftRefusesWhenTheInventoryCannotBeRead(t *testing.T) {
	db, srv, dbPath := newDriftServer(t)
	seedDriftStack(t, db)
	failInventoryReads(t, dbPath)

	resp, err := http.Get(srv.URL + "/admin/k8s/stacks/stack_drift/drift")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("drift answered 200 with an unreadable inventory; every declared resource would read " +
			"as missing and the operator would re-apply a stack that is already deployed")
	}
}

// Truncation must be surfaced, since "missing" under a partial view can mean
// "present but outside the window".
func TestDriftReportsAPartialInventory(t *testing.T) {
	db, srv, _ := newDriftServer(t)
	seedDriftStack(t, db)
	ctx := context.Background()

	original := driftScanBudget
	driftScanBudget = 1
	t.Cleanup(func() { driftScanBudget = original })

	for _, name := range []string{"api", "web"} {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID: "inv_" + name, ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: name,
		}); err != nil {
			t.Fatal(err)
		}
	}

	scan, _ := getJSON(t, srv.URL+"/admin/k8s/stacks/stack_drift/drift")["scan"].(map[string]any)
	if scan == nil {
		t.Fatal("the drift response carries no scan block")
	}
	if scan["status"] != "partial" {
		t.Fatalf("status = %v with 2 rows over a budget of 1: a 'missing' verdict from a partial "+
			"window can name resources that are actually deployed: %v", scan["status"], scan)
	}
}

// The healthy path stays clean.
func TestDriftReportsCompleteWhenItFits(t *testing.T) {
	db, srv, _ := newDriftServer(t)
	seedDriftStack(t, db)
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{
		ID: "inv_api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api",
	}); err != nil {
		t.Fatal(err)
	}
	body := getJSON(t, srv.URL+"/admin/k8s/stacks/stack_drift/drift")
	scan, _ := body["scan"].(map[string]any)
	if scan["status"] != "checked" {
		t.Fatalf("status = %v for a drift scan that fit inside the budget: %v", scan["status"], scan)
	}
	drift, _ := body["drift"].(map[string]any)
	if drift["synced"] != true {
		t.Fatalf("the declared Deployment is present in the inventory but drift reports %v", drift)
	}
}

func seedDriftStack(t *testing.T, db *store.SQLStore) {
	t.Helper()
	if _, _, err := db.UpsertK8sStack(context.Background(), store.K8sApplicationStack{
		ID: "stack_drift", Name: "drift", ClusterID: "c1", Namespace: "prod",
		SourceType: "manifest", Manifest: driftStackManifest, Status: "saved",
	}, func(p string) string { return p + "_x" }); err != nil {
		t.Fatal(err)
	}
}

func failInventoryReads(t *testing.T, dbPath string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Dropping the table makes the SELECT fail the way a real read failure would.
	if _, err := raw.Exec(`DROP TABLE k8s_inventory`); err != nil {
		t.Fatalf("drop inventory: %v", err)
	}
}

func newDriftServer(t *testing.T) (*store.SQLStore, *httptest.Server, string) {
	t.Helper()
	server, db, dbPath := newServiceUnwindStore(t)
	srv := httptest.NewServer(server.Routes())
	t.Cleanup(srv.Close)
	return db, srv, dbPath
}
