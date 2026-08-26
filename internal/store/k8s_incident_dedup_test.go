package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func incidentDraft(key string) K8sIncident {
	return K8sIncident{
		DedupKey: key, ClusterID: "c1", Namespace: "prod", Kind: "Pod", Name: "api",
		Condition: "CrashLoopBackOff", Severity: "high", Title: "crashloop",
	}
}

func idFactory() func(string) string {
	var mu sync.Mutex
	n := 0
	return func(prefix string) string {
		mu.Lock()
		defer mu.Unlock()
		n++
		return fmt.Sprintf("%s_%d", prefix, n)
	}
}

// dedup_key exists so a recurring failure refreshes one open incident instead of
// spawning a new one each scan. It carried only a non-unique index, and the upsert
// decided on a SELECT before inserting, so two syncs of the same cluster could both
// find nothing open and both insert. Measured before the fix: six open incidents for
// one key under eight concurrent writers, each reported as newly created and so each
// alerted on.
func TestIncidentDedupKeyOpensExactlyOneIncidentUnderConcurrency(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	const racers = 8
	newID := idFactory()

	for round := 0; round < 10; round++ {
		key := fmt.Sprintf("pod/prod/api/CrashLoopBackOff/%d", round)
		var mu sync.Mutex
		created := 0
		var start, done sync.WaitGroup
		start.Add(1)
		for i := 0; i < racers; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				_, isNew, err := db.UpsertK8sIncidentByKey(ctx, incidentDraft(key), newID)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					t.Errorf("upsert failed: %v", err)
					return
				}
				if isNew {
					created++
				}
			}()
		}
		start.Done()
		done.Wait()
		if created != 1 {
			t.Fatalf("round %d: %d writers reported opening a new incident, want exactly 1", round, created)
		}
	}

	open, err := db.ListK8sIncidents(ctx, K8sIncidentFilter{ClusterID: "c1", Status: "open", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 10 {
		t.Fatalf("expected one open incident per key (10), got %d", len(open))
	}
}

// The ordinary path must still refresh the open incident in place, keeping its id and
// opened_at, and a resolved incident must not block a later recurrence.
func TestIncidentDedupKeyRefreshesThenReopensAfterResolve(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	newID := idFactory()

	first, isNew, err := db.UpsertK8sIncidentByKey(ctx, incidentDraft("k"), newID)
	if err != nil || !isNew {
		t.Fatalf("first upsert: isNew=%v err=%v", isNew, err)
	}
	again, isNew, err := db.UpsertK8sIncidentByKey(ctx, incidentDraft("k"), newID)
	if err != nil || isNew || again != first {
		t.Fatalf("second upsert must refresh in place: id=%s isNew=%v err=%v", again, isNew, err)
	}
	if err := db.ResolveK8sIncident(ctx, first); err != nil {
		t.Fatal(err)
	}
	reopened, isNew, err := db.UpsertK8sIncidentByKey(ctx, incidentDraft("k"), newID)
	if err != nil || !isNew || reopened == first {
		t.Fatalf("a recurrence after resolve must open a new incident: id=%s isNew=%v err=%v", reopened, isNew, err)
	}
}

// Upgrading a database that already accumulated duplicates must collapse them onto
// the earliest open incident rather than failing to create the unique index — a
// failed migration would stop the gateway from starting.
func TestIncidentDedupMigrationCollapsesExistingDuplicates(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()

	// Insert duplicates directly, bypassing the upsert, to mimic rows written by an
	// older build.
	if _, err := db.db.ExecContext(ctx, db.bind(`DROP INDEX IF EXISTS idx_k8s_incidents_open_dedup_key`)); err != nil {
		t.Fatal(err)
	}
	for i, at := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"} {
		if _, err := db.db.ExecContext(ctx, db.bind(`INSERT INTO k8s_incidents
			(id, dedup_key, cluster_id, namespace, kind, name, condition, severity, status, title, evidence_json, opened_at, updated_at, resolved_at)
			VALUES (?, 'dup', 'c1', 'prod', 'Pod', 'api', 'CrashLoopBackOff', 'high', 'open', 'crashloop', '[]', ?, ?, '')`),
			fmt.Sprintf("old_%d", i), at, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.migrateK8sIncidentOpenDedupKey(ctx); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	open, err := db.ListK8sIncidents(ctx, K8sIncidentFilter{ClusterID: "c1", Status: "open", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("migration left %d open incidents for one key, want 1", len(open))
	}
	if open[0].ID != "old_0" {
		t.Errorf("migration kept %s; the earliest incident should survive to preserve opened_at", open[0].ID)
	}
	// Running it again must be a no-op, not an error.
	if err := db.migrateK8sIncidentOpenDedupKey(ctx); err != nil {
		t.Fatalf("migration is not idempotent: %v", err)
	}
}
