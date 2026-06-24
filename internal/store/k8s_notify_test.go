package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
)

func TestShouldSendK8sNotificationDedup(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "noti.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	window := 6 * time.Hour

	// First fire -> send.
	ok, err := db.ShouldSendK8sNotification(ctx, "c1|rca/x", now, window)
	if err != nil || !ok {
		t.Fatalf("first send should be allowed, ok=%v err=%v", ok, err)
	}
	// Within window -> suppressed.
	ok, _ = db.ShouldSendK8sNotification(ctx, "c1|rca/x", now.Add(time.Hour), window)
	if ok {
		t.Fatal("within window should be suppressed")
	}
	// After window -> send again.
	ok, _ = db.ShouldSendK8sNotification(ctx, "c1|rca/x", now.Add(7*time.Hour), window)
	if !ok {
		t.Fatal("after window should be allowed again")
	}
	// Different key -> independent.
	ok, _ = db.ShouldSendK8sNotification(ctx, "c1|rca/y", now.Add(time.Hour), window)
	if !ok {
		t.Fatal("different key should be allowed")
	}
}
