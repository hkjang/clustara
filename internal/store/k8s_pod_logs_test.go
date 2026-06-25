package store

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func TestK8sPodLogQueries(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "podlogs.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertK8sPodLogQuery(ctx, K8sPodLogQuery{
		ID: "q1", ClusterID: "c1", Namespace: "prod", Pod: "api-1", Container: "app",
		Previous: true, Stream: true, TailLines: 200, SinceSeconds: 300, Query: "Exception",
		RequestedBy: "admin_x", Masked: true, LineCount: 10, ErrorCount: 2, WarnCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListK8sPodLogQueries(ctx, "c1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	got := rows[0]
	if !got.Previous || !got.Stream || !got.Masked || got.Container != "app" || got.Query != "Exception" || got.ErrorCount != 2 {
		t.Fatalf("unexpected row: %+v", got)
	}
}
