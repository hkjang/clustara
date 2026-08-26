package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"clustara/internal/config"
)

func openGuardTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(context.Background(), config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    filepath.Join(t.TempDir(), "guard.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TakeOIDCFlowState documents that it consumes a login state atomically, but it read
// the row and then deleted it unconditionally, so two callbacks arriving together
// both scanned the row and both reported found=true. Single use has to be decided by
// the delete — only the caller that actually removed the row has consumed it.
func TestOIDCFlowStateIsConsumedExactlyOnceUnderConcurrency(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	const racers = 8

	for round := 0; round < 25; round++ {
		if err := db.SaveOIDCFlowState(ctx, "state-1", "nonce-1", "verifier-1", time.Now()); err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		consumed := 0
		var start sync.WaitGroup
		var done sync.WaitGroup
		start.Add(1)
		for i := 0; i < racers; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				nonce, verifier, found, err := db.TakeOIDCFlowState(ctx, "state-1")
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					t.Errorf("take failed: %v", err)
					return
				}
				if found {
					consumed++
					if nonce != "nonce-1" || verifier != "verifier-1" {
						t.Errorf("consumer got wrong payload: %q/%q", nonce, verifier)
					}
				}
			}()
		}
		start.Done()
		done.Wait()
		if consumed != 1 {
			t.Fatalf("round %d: state consumed %d times, want exactly 1", round, consumed)
		}
	}
}

func TestOIDCFlowStateSecondTakeAndExpiryReturnNotFound(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()

	if err := db.SaveOIDCFlowState(ctx, "s", "n", "v", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := db.TakeOIDCFlowState(ctx, "s"); err != nil || !found {
		t.Fatalf("first take: found=%v err=%v", found, err)
	}
	if _, _, found, err := db.TakeOIDCFlowState(ctx, "s"); err != nil || found {
		t.Fatalf("second take must not find the state: found=%v err=%v", found, err)
	}
	if _, _, found, err := db.TakeOIDCFlowState(ctx, "never-saved"); err != nil || found {
		t.Fatalf("unknown state: found=%v err=%v", found, err)
	}
	// Older than the 10-minute TTL.
	if err := db.SaveOIDCFlowState(ctx, "old", "n", "v", time.Now().Add(-11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := db.TakeOIDCFlowState(ctx, "old"); err != nil || found {
		t.Fatalf("expired state must not be usable: found=%v err=%v", found, err)
	}
}

// The notification suppression window had the same shape: read the last send time,
// then write unconditionally. Two callers in the same instant both saw an expired
// window and both sent — the duplicate the window exists to prevent.
func TestNotificationSuppressionAdmitsOneSenderUnderConcurrency(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	const racers = 8
	now := time.Now().UTC()

	var mu sync.Mutex
	sent := 0
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := 0; i < racers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			ok, err := db.ShouldSendK8sNotification(ctx, "dedup-key", now, 5*time.Minute)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("dedup check failed: %v", err)
				return
			}
			if ok {
				sent++
			}
		}()
	}
	start.Done()
	done.Wait()
	if sent != 1 {
		t.Fatalf("notification admitted %d senders, want exactly 1", sent)
	}
}

// The window must still expire, and a different key must not be suppressed.
func TestNotificationSuppressionExpiresAndIsPerKey(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC()

	if ok, err := db.ShouldSendK8sNotification(ctx, "k1", base, time.Minute); err != nil || !ok {
		t.Fatalf("first send: ok=%v err=%v", ok, err)
	}
	if ok, err := db.ShouldSendK8sNotification(ctx, "k1", base.Add(30*time.Second), time.Minute); err != nil || ok {
		t.Fatalf("inside the window must be suppressed: ok=%v err=%v", ok, err)
	}
	if ok, err := db.ShouldSendK8sNotification(ctx, "k1", base.Add(2*time.Minute), time.Minute); err != nil || !ok {
		t.Fatalf("after the window must send again: ok=%v err=%v", ok, err)
	}
	if ok, err := db.ShouldSendK8sNotification(ctx, "k2", base, time.Minute); err != nil || !ok {
		t.Fatalf("a different key must not be suppressed: ok=%v err=%v", ok, err)
	}
}
