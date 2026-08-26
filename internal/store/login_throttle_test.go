package store

import (
	"context"
	"testing"
	"time"
)

// login_attempts was written on every login and read by nothing, so the data a
// brute-force throttle needs was already being collected and never used.
func TestLoginFailureCountsPerIPAndAccount(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	since := time.Now().UTC().Add(-15 * time.Minute)

	for i := 0; i < 3; i++ {
		if err := db.InsertLoginAttempt(ctx, "victim@example.com", false, "198.51.100.7", "ua", "invalid_credentials"); err != nil {
			t.Fatal(err)
		}
	}
	// A different account from the same IP still counts against that IP.
	if err := db.InsertLoginAttempt(ctx, "other@example.com", false, "198.51.100.7", "ua", "invalid_credentials"); err != nil {
		t.Fatal(err)
	}
	// A different IP must not.
	if err := db.InsertLoginAttempt(ctx, "victim@example.com", false, "203.0.113.9", "ua", "invalid_credentials"); err != nil {
		t.Fatal(err)
	}

	byIP, byUser, err := db.LoginFailureCounts(ctx, "victim@example.com", "198.51.100.7", since)
	if err != nil {
		t.Fatal(err)
	}
	if byIP != 4 {
		t.Errorf("per-IP failures = %d, want 4", byIP)
	}
	if byUser != 4 {
		t.Errorf("per-account failures = %d, want 4", byUser)
	}
}

// A user who mistypes and then gets in must not stay throttled, so account
// failures are counted only since that account's last success.
func TestLoginFailureCountsResetAfterSuccess(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	since := time.Now().UTC().Add(-15 * time.Minute)

	for i := 0; i < 5; i++ {
		if err := db.InsertLoginAttempt(ctx, "user@example.com", false, "198.51.100.7", "ua", "invalid_credentials"); err != nil {
			t.Fatal(err)
		}
	}
	if _, byUser, err := db.LoginFailureCounts(ctx, "user@example.com", "", since); err != nil || byUser != 5 {
		t.Fatalf("before success: byUser=%d err=%v", byUser, err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := db.InsertLoginAttempt(ctx, "user@example.com", true, "198.51.100.7", "ua", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := db.InsertLoginAttempt(ctx, "user@example.com", false, "198.51.100.7", "ua", "invalid_credentials"); err != nil {
		t.Fatal(err)
	}
	_, byUser, err := db.LoginFailureCounts(ctx, "user@example.com", "", since)
	if err != nil {
		t.Fatal(err)
	}
	if byUser != 1 {
		t.Errorf("after a successful login only later failures count: byUser=%d, want 1", byUser)
	}
}

// Attempts older than the window must fall out of the count.
func TestLoginFailureCountsRespectWindow(t *testing.T) {
	db := openGuardTestStore(t)
	ctx := context.Background()
	if err := db.InsertLoginAttempt(ctx, "user@example.com", false, "198.51.100.7", "ua", "invalid_credentials"); err != nil {
		t.Fatal(err)
	}
	byIP, byUser, err := db.LoginFailureCounts(ctx, "user@example.com", "198.51.100.7", time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if byIP != 0 || byUser != 0 {
		t.Errorf("attempts before the window must not count: byIP=%d byUser=%d", byIP, byUser)
	}
}
