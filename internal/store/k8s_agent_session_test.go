package store

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func openAgentSessionTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "agentsess.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestK8sAgentSessionAndMessages(t *testing.T) {
	ctx := context.Background()
	db := openAgentSessionTestStore(t)

	sess := K8sAgentSession{ID: "s1", UserID: "u1", Route: "#/k8s-pods", Context: `{"cluster_id":"c1","pod":"web-1"}`}
	if err := db.CreateK8sAgentSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetK8sAgentSession(ctx, "s1")
	if err != nil || got.Route != "#/k8s-pods" || got.Context == "" {
		t.Fatalf("get session: %+v %v", got, err)
	}

	// Append user + agent turns.
	if err := db.AppendK8sAgentMessage(ctx, K8sAgentMessage{ID: "m1", SessionID: "s1", Role: "user", Content: "왜 죽었어?", Intent: "pod"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendK8sAgentMessage(ctx, K8sAgentMessage{ID: "m2", SessionID: "s1", Role: "agent", Content: "OOMKilled", Intent: "pod", Evidence: `["RCA..."]`, LLMAvailable: true}); err != nil {
		t.Fatal(err)
	}
	msgs, err := db.ListK8sAgentMessages(ctx, "s1", 100)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d (%v)", len(msgs), err)
	}
	// Ordered user→agent; llm_available round-trips.
	if msgs[0].Role != "user" || msgs[1].Role != "agent" || !msgs[1].LLMAvailable {
		t.Fatalf("message order/flags wrong: %+v", msgs)
	}

	// Context update bumps the snapshot.
	if err := db.UpdateK8sAgentSessionContext(ctx, "s1", "#/k8s-incidents", `{"incident_id":"i9"}`); err != nil {
		t.Fatal(err)
	}
	got2, _ := db.GetK8sAgentSession(ctx, "s1")
	if got2.Route != "#/k8s-incidents" || got2.Context != `{"incident_id":"i9"}` {
		t.Fatalf("context update failed: %+v", got2)
	}

	if _, err := db.GetK8sAgentSession(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("missing session should be ErrNotFound, got %v", err)
	}
}
