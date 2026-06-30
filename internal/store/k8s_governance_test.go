package store

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func openGovTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "gov.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSecurityExceptionLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openGovTestStore(t)
	e := K8sSecurityException{ID: "x1", ClusterID: "c1", Namespace: "p", Workload: "Deployment/api", Finding: "privileged", ExpiresAt: "2099-01-01T00:00:00Z"}
	if err := db.CreateK8sSecurityException(ctx, e); err != nil {
		t.Fatal(err)
	}
	// pending → approved ok.
	if err := db.UpdateK8sSecurityExceptionStatus(ctx, "x1", "approved", "ops"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// approved → approved (invalid).
	if err := db.UpdateK8sSecurityExceptionStatus(ctx, "x1", "approved", "ops"); err != ErrInvalidTransition {
		t.Fatalf("re-approve should be invalid transition, got %v", err)
	}
	// missing id.
	if err := db.UpdateK8sSecurityExceptionStatus(ctx, "nope", "approved", "ops"); err != ErrNotFound {
		t.Fatalf("missing should be ErrNotFound, got %v", err)
	}
	list, _ := db.ListK8sSecurityExceptions(ctx, "c1", 10)
	if len(list) != 1 || list[0].Status != "approved" || list[0].ApprovedBy != "ops" {
		t.Fatalf("list wrong: %+v", list)
	}
	// expiry: an approved exception past expiry flips to expired.
	e2 := K8sSecurityException{ID: "x2", ClusterID: "c1", Workload: "w", Status: "approved", ExpiresAt: "2000-01-01T00:00:00Z"}
	_ = db.CreateK8sSecurityException(ctx, e2)
	n, _ := db.ExpireK8sSecurityExceptions(ctx, "2024-01-01T00:00:00Z")
	if n != 1 {
		t.Fatalf("expected 1 expired, got %d", n)
	}
}

func TestImagePromotionLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openGovTestStore(t)
	p := K8sImagePromotion{ID: "p1", ClusterID: "c1", Repository: "app/web", Digest: "sha256:abc", SourceEnv: "stage", TargetEnv: "prod"}
	if err := db.CreateK8sImagePromotion(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateK8sImagePromotionStatus(ctx, "p1", "approved", "ops"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := db.UpdateK8sImagePromotionStatus(ctx, "p1", "promoted", "ops"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	// promoted is terminal → further transition invalid.
	if err := db.UpdateK8sImagePromotionStatus(ctx, "p1", "approved", "ops"); err != ErrInvalidTransition {
		t.Fatalf("post-promoted should be invalid: %v", err)
	}
	list, _ := db.ListK8sImagePromotions(ctx, "c1", 10)
	if len(list) != 1 || list[0].Status != "promoted" {
		t.Fatalf("list wrong: %+v", list)
	}
}
