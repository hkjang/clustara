package proxy

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"clustara/internal/config"
	"clustara/internal/store"

	_ "modernc.org/sqlite"
)

// Creating a service instance writes a stack, then the instance, then the
// credential reference. Neither table constrains the service's identity —
// UpsertK8sStack mints a fresh id whenever it is called without one, and
// instances carry only non-unique indexes — so a failure at the credential step
// used to return 500 with a live instance already written.
//
// That 500 invites the one response that makes it worse: a retry, which leaves a
// second stack and a second instance alongside the first, with nothing marking
// the first as dead.
func TestServiceInstanceIsMarkedFailedWhenTheCredentialCannotBeSaved(t *testing.T) {
	srv, db, dbPath := newServiceUnwindStore(t)
	ctx := context.Background()

	instance := store.K8sServiceInstance{
		ID: "svcinst_1", ClusterID: "c1", Namespace: "prod", Name: "postgres",
		Status: "validating", CreatedBy: "tester",
	}
	if err := db.UpsertK8sServiceInstance(ctx, instance); err != nil {
		t.Fatal(err)
	}

	failCredentialWrites(t, dbPath)
	credErr := db.UpsertK8sServiceCredential(ctx, store.K8sServiceCredential{
		ID: "svccred_svcinst_1", ServiceInstanceID: instance.ID, SecretName: "pg", Namespace: "prod",
	})
	if credErr == nil {
		t.Fatal("the injected failure did not take effect")
	}

	srv.unwindServiceInstanceCreate(
		httptest.NewRequest("POST", "/admin/k8s/services/instances", nil),
		instance, "k8sstack_1", true, credErr)

	got, err := db.GetK8sServiceInstance(ctx, instance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" {
		t.Fatalf("instance status = %q, want failed: a leftover instance that still reads as live "+
			"is indistinguishable from a real service", got.Status)
	}
}

// The identity facts the unwind exists for. If either of these ever gains a
// uniqueness constraint the compensation can be replaced with a real upsert, and
// this test is where that shows up.
func TestServiceIdentityIsUnconstrained(t *testing.T) {
	_, db, _ := newServiceUnwindStore(t)
	ctx := context.Background()

	for _, id := range []string{"svcinst_a", "svcinst_b"} {
		if err := db.UpsertK8sServiceInstance(ctx, store.K8sServiceInstance{
			ID: id, ClusterID: "c1", Namespace: "prod", Name: "postgres", Status: "validating",
		}); err != nil {
			t.Fatalf("two instances of the same service must be storable today (%s): %v", id, err)
		}
	}

	first, _, err := db.UpsertK8sStack(ctx, store.K8sApplicationStack{
		Name: "postgres", ClusterID: "c1", Namespace: "prod", SourceType: "manifest", Manifest: "a",
	}, func(p string) string { return p + "_1" })
	if err != nil {
		t.Fatal(err)
	}
	second, isNew, err := db.UpsertK8sStack(ctx, store.K8sApplicationStack{
		Name: "postgres", ClusterID: "c1", Namespace: "prod", SourceType: "manifest", Manifest: "a",
	}, func(p string) string { return p + "_2" })
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("UpsertK8sStack reused the id; the retry-duplicates-a-stack reasoning no longer holds")
	}
	if !isNew {
		t.Fatal("the second call reported an existing stack; it minted a new id")
	}
}

func failCredentialWrites(t *testing.T, dbPath string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER fail_cred BEFORE INSERT ON k8s_service_credentials
		BEGIN SELECT RAISE(ABORT, 'injected credential failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
}

// newServiceUnwindStore returns a server, its store, and the store's file path so
// a trigger can inject the credential-write failure this unwind exists for.
func newServiceUnwindStore(t *testing.T) (*Server, *store.SQLStore, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "gateway.db")
	db, err := store.Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger := store.NewAsyncLogger(db, 8, filepath.Join(dir, "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })
	srv, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv, db, dbPath
}
