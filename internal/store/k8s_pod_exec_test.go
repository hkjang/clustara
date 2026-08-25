package store

import (
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
)

func openK8sPodExecTimestampTestStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := Open(t.Context(), config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    filepath.Join(t.TempDir(), "k8s-pod-exec.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return db
}

func createReadyK8sPodExecTimestampSession(t *testing.T, db *SQLStore, id string) {
	t.Helper()
	err := db.CreateK8sPodExecSession(t.Context(), &K8sPodExecSession{
		ID: id, ClusterID: "cluster-1", Namespace: "default", Pod: "api-0",
		Command: "/bin/sh", RequestedBy: "usr_operator", Status: "ready",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestK8sTerminalTicketExactSecondExpiryBoundaries(t *testing.T) {
	db := openK8sPodExecTimestampTestStore(t)
	ctx := t.Context()
	clientIP := "192.0.2.10"
	userAgentHash := "ua-hash"
	// Keep creation in the real present while evaluating expiry at a deterministic
	// future exact-second boundary.
	exactSecond := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	justAfter := exactSecond.Add(500 * time.Millisecond)

	t.Run("ticket cleanup", func(t *testing.T) {
		for ticket, expiresAt := range map[string]time.Time{
			"cleanup-expired": exactSecond,
			"cleanup-live":    exactSecond.Add(time.Minute),
		} {
			if err := db.CreateK8sTerminalTicket(ctx, ticket, K8sTerminalTicket{
				SessionID: ticket, AdminID: "usr_operator", ClientIP: clientIP,
				UserAgentHash: userAgentHash, ExpiresAt: expiresAt,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.deleteExpiredK8sTerminalTickets(ctx, justAfter); err != nil {
			t.Fatal(err)
		}
		var expiredCount, liveCount int
		if err := db.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM k8s_terminal_tickets WHERE ticket_hash = ?`,
			terminalTicketHash("cleanup-expired"),
		).Scan(&expiredCount); err != nil {
			t.Fatal(err)
		}
		if err := db.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM k8s_terminal_tickets WHERE ticket_hash = ?`,
			terminalTicketHash("cleanup-live"),
		).Scan(&liveCount); err != nil {
			t.Fatal(err)
		}
		if expiredCount != 0 || liveCount != 1 {
			t.Fatalf("cleanup boundary expired=%d live=%d, want 0/1", expiredCount, liveCount)
		}
	})

	t.Run("ticket expiry", func(t *testing.T) {
		createReadyK8sPodExecTimestampSession(t, db, "session-ticket-expiry")
		if err := db.CreateK8sTerminalTicket(ctx, "ticket-expired", K8sTerminalTicket{
			SessionID: "session-ticket-expiry", AdminID: "usr_operator",
			ClientIP: clientIP, UserAgentHash: userAgentHash, ExpiresAt: exactSecond,
		}); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := db.consumeK8sTerminalTicketAndClaimSessionAt(
			ctx, "session-ticket-expiry", "ticket-expired", clientIP, userAgentHash, justAfter,
		); err != nil || ok {
			t.Fatalf("exact-second expired ticket accepted: ok=%v err=%v", ok, err)
		}
	})

	t.Run("bound token expiry", func(t *testing.T) {
		createReadyK8sPodExecTimestampSession(t, db, "session-token-expiry")
		if err := db.CreateK8sTerminalTicket(ctx, "token-expired", K8sTerminalTicket{
			SessionID: "session-token-expiry", AdminID: "usr_operator",
			AuthExpiresAt: exactSecond, ClientIP: clientIP, UserAgentHash: userAgentHash,
			ExpiresAt: exactSecond.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := db.consumeK8sTerminalTicketAndClaimSessionAt(
			ctx, "session-token-expiry", "token-expired", clientIP, userAgentHash, justAfter,
		); err != nil || ok {
			t.Fatalf("ticket outlived exact-second token expiry: ok=%v err=%v", ok, err)
		}
	})

	t.Run("internal auth session expiry", func(t *testing.T) {
		createReadyK8sPodExecTimestampSession(t, db, "session-auth-expiry")
		if err := db.CreateAuthUser(ctx, AuthUser{
			ID: "usr_operator", Email: "operator@example.com", PasswordHash: "unused", Status: "active",
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.InsertAuthSession(ctx, "auth-exact-second", "usr_operator", clientIP, "terminal-test", exactSecond); err != nil {
			t.Fatal(err)
		}
		if err := db.CreateK8sTerminalTicket(ctx, "auth-session-expired", K8sTerminalTicket{
			SessionID: "session-auth-expiry", AdminID: "usr_operator", AuthSessionID: "auth-exact-second",
			AuthExpiresAt: exactSecond.Add(time.Minute), ClientIP: clientIP, UserAgentHash: userAgentHash,
			ExpiresAt: exactSecond.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := db.consumeK8sTerminalTicketAndClaimSessionAt(
			ctx, "session-auth-expiry", "auth-session-expired", clientIP, userAgentHash, justAfter,
		); err != nil || ok {
			t.Fatalf("ticket outlived exact-second auth session expiry: ok=%v err=%v", ok, err)
		}
	})
}

func TestRecoverStaleK8sPodExecSessionExactSecondBoundary(t *testing.T) {
	db := openK8sPodExecTimestampTestStore(t)
	createReadyK8sPodExecTimestampSession(t, db, "session-stale-boundary")
	if _, err := db.MarkK8sPodExecSessionConnecting(
		t.Context(), "session-stale-boundary", "usr_operator", "claim-1",
	); err != nil {
		t.Fatal(err)
	}
	exactSecond := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := db.db.ExecContext(t.Context(),
		`UPDATE k8s_pod_exec_sessions SET updated_at = ? WHERE id = ?`,
		exactSecond.Format(time.RFC3339Nano), "session-stale-boundary",
	); err != nil {
		t.Fatal(err)
	}
	recovered, err := db.RecoverStaleK8sPodExecSessionConnection(
		t.Context(), "session-stale-boundary", exactSecond.Add(500*time.Millisecond),
	)
	if err != nil || !recovered {
		t.Fatalf("chronologically stale exact-second session was not recovered: recovered=%v err=%v", recovered, err)
	}
}

func TestK8sPodExecTimePredicateDialects(t *testing.T) {
	sqlite := (&SQLStore{dialect: "sqlite"}).k8sPodExecTimePredicate("expires_at", ">")
	if sqlite != "julianday(NULLIF(expires_at, '')) > julianday(?)" {
		t.Fatalf("unexpected SQLite predicate: %s", sqlite)
	}

	postgresStore := &SQLStore{dialect: "postgres"}
	postgres := postgresStore.bind(postgresStore.k8sPodExecTimePredicate("auth.expires_at", "<="))
	if postgres != "CAST(NULLIF(auth.expires_at, '') AS TIMESTAMPTZ) <= CAST($1 AS TIMESTAMPTZ)" {
		t.Fatalf("unexpected PostgreSQL predicate: %s", postgres)
	}
}
