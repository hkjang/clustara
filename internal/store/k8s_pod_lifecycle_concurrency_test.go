package store

import (
	"context"
	"sync"
	"testing"
)

func lifecyclePodItem(phase, observed string) K8sInventoryItem {
	return K8sInventoryItem{
		Kind: "Pod", ClusterID: "c1", Namespace: "prod", Name: "api", UID: "uid-1",
		ObservedAt: observed, CreationTimestamp: "2026-01-01T00:00:00Z",
		Spec:         map[string]any{"nodeName": "n1"},
		StatusObject: map[string]any{"phase": phase},
	}
}

// A pod is observed by both the watch agent and the periodic snapshot. Both read the
// same current_state, both compute the same MAX(sequence_no)+1, and the insert had no
// conflict clause — so the loser got a unique-constraint error. Both collectors abort
// their entire batch on an ObservePodLifecycle error, so one racing pod stopped the
// rest of the cluster's inventory from being ingested at all.
func TestConcurrentPodObservationDoesNotFailTheBatch(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	const racers = 8

	if err := db.ObservePodLifecycle(ctx, lifecyclePodItem("Running", "2026-01-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var failures []error
	var start, done sync.WaitGroup
	start.Add(1)
	for i := 0; i < racers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			if err := db.ObservePodLifecycle(ctx, lifecyclePodItem("Failed", "2026-01-01T00:01:00Z")); err != nil {
				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}()
	}
	start.Done()
	done.Wait()

	if len(failures) > 0 {
		t.Fatalf("%d of %d concurrent observations failed, which aborts the collector batch: %v", len(failures), racers, failures[0])
	}

	// The same transition observed many times must be recorded once: CREATED, Running, Failed.
	trans, err := db.ListK8sPodTransitions(ctx, "c1", "uid-1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(trans) != 3 {
		states := []string{}
		for _, tr := range trans {
			states = append(states, tr.PreviousState+"->"+tr.CurrentState)
		}
		t.Fatalf("expected 3 transitions, got %d: %v", len(trans), states)
	}
	seen := map[int64]bool{}
	for _, tr := range trans {
		if seen[tr.SequenceNo] {
			t.Errorf("duplicate sequence_no %d", tr.SequenceNo)
		}
		seen[tr.SequenceNo] = true
	}
}

// Distinct state changes must each be recorded, in order — the dedup must key on the
// transition, not collapse a pod's history.
func TestSequentialPodStateChangesAreAllRecorded(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()

	steps := []struct{ phase, at string }{
		{"Pending", "2026-01-01T00:00:00Z"},
		{"Running", "2026-01-01T00:01:00Z"},
		{"Failed", "2026-01-01T00:02:00Z"},
		{"Running", "2026-01-01T00:03:00Z"},
	}
	for _, st := range steps {
		if err := db.ObservePodLifecycle(ctx, lifecyclePodItem(st.phase, st.at)); err != nil {
			t.Fatalf("observe %s: %v", st.phase, err)
		}
		// Observing the same state again must not append anything.
		if err := db.ObservePodLifecycle(ctx, lifecyclePodItem(st.phase, st.at)); err != nil {
			t.Fatalf("re-observe %s: %v", st.phase, err)
		}
	}
	trans, err := db.ListK8sPodTransitions(ctx, "c1", "uid-1", 100)
	if err != nil {
		t.Fatal(err)
	}
	// CREATED plus one per distinct state change.
	if len(trans) < 4 {
		t.Fatalf("state history was collapsed: %d transitions", len(trans))
	}
	seen := map[int64]bool{}
	for _, tr := range trans {
		if seen[tr.SequenceNo] {
			t.Fatalf("duplicate sequence_no %d in %d transitions", tr.SequenceNo, len(trans))
		}
		seen[tr.SequenceNo] = true
	}
}
