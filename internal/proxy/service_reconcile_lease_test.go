package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/store"
)

func serviceReconcileLeaseFixture(t *testing.T) (*Server, *store.SQLStore, store.K8sServiceInstance) {
	t.Helper()
	ctx := context.Background()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	instance := store.K8sServiceInstance{
		ID: "svc-1", ClusterID: "c1", Namespace: "prod", Name: "postgres-main",
		Status: "validating",
	}
	if err := db.UpsertK8sServiceInstance(ctx, instance); err != nil {
		t.Fatal(err)
	}
	return server, db, instance
}

// The periodic worker leases every persisting reconcile. The operator-triggered
// endpoint persists too, so it has to contend for the same lease — otherwise a
// scheduler tick and an operator sync reconcile the same instance at once and
// write each other's stale health.
func TestOperatorReconcileContendsForTheWorkerLease(t *testing.T) {
	ctx := context.Background()
	server, db, instance := serviceReconcileLeaseFixture(t)

	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	url := ts.URL + "/admin/k8s/services/instances/" + instance.ID + "/reconcile"

	// Simulate the worker holding the lease for this instance.
	held, err := db.TryAcquireK8sServiceReconcileLease(ctx, instance.ID, "worker-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("fixture could not take the lease")
	}

	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("reconcile during a held lease returned %d: %s", resp.StatusCode, body)
	}

	// Once the worker is done the operator's sync is admitted again. The
	// reconcile itself needs a full service-platform fixture to succeed, so the
	// assertion here is about admission, not about the reconcile result.
	if err := db.ReleaseK8sServiceReconcileLease(ctx, instance.ID, "worker-owner"); err != nil {
		t.Fatal(err)
	}
	resp, err = http.Post(url, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		t.Fatalf("reconcile was still rejected after the lease was released: %s", body)
	}
}

// The lease has to be released when the request finishes — including when the
// reconcile itself fails — or one operator sync would block the instance until
// the TTL expired.
func TestOperatorReconcileReleasesItsLease(t *testing.T) {
	ctx := context.Background()
	server, db, instance := serviceReconcileLeaseFixture(t)

	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	url := ts.URL + "/admin/k8s/services/instances/" + instance.ID + "/reconcile"

	for i := 0; i < 3; i++ {
		resp, err := http.Post(url, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusConflict {
			t.Fatalf("reconcile %d was rejected, so a previous request kept its lease: %s", i, body)
		}
	}

	// The worker must be able to take the lease straight after.
	acquired, err := db.TryAcquireK8sServiceReconcileLease(ctx, instance.ID, "worker-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("the operator request left its lease behind; the worker is locked out until the TTL")
	}
}

// The API path must not reuse the worker's runtime owner: the lease lets the
// same owner re-acquire, so sharing the id would hand out a lease the worker is
// actively holding.
func TestServiceReconcileLeaseOwnersAreDistinctPerCall(t *testing.T) {
	ctx := context.Background()
	server, _, instance := serviceReconcileLeaseFixture(t)

	first, releaseFirst, err := server.acquireServiceReconcileLease(ctx, instance.ID)
	if err != nil || !first {
		t.Fatalf("first acquire = %v err=%v, want it granted", first, err)
	}
	second, _, err := server.acquireServiceReconcileLease(ctx, instance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("a second concurrent acquire was granted; the owner id is being reused")
	}
	releaseFirst()

	third, releaseThird, err := server.acquireServiceReconcileLease(ctx, instance.ID)
	if err != nil || !third {
		t.Fatalf("acquire after release = %v err=%v, want it granted", third, err)
	}
	releaseThird()
}
