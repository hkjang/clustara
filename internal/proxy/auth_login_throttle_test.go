package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/store"
)

func newThrottleTestServer(t *testing.T, maxPerIP int) *httptest.Server {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	t.Cleanup(func() { logger.Stop(context.Background()) })

	cfg := testConfig("http://example.invalid", "secret")
	cfg.Auth.Enabled = true
	cfg.Auth.JWTSecret = "test-jwt-secret"
	cfg.Auth.AccessTokenTTL = 15 * time.Minute
	cfg.Auth.RefreshTokenTTL = time.Hour
	cfg.Auth.APIKeyPrefix = "vc_sk_"
	cfg.Auth.ServiceKeyPrefix = "vc_sa_"
	cfg.Auth.BootstrapEmail = "root@example.com"
	cfg.Auth.BootstrapPassword = "correct-password"
	cfg.Auth.LoginThrottleWindow = 15 * time.Minute
	cfg.Auth.LoginThrottleMaxPerIP = maxPerIP
	cfg.Auth.LoginThrottleMaxPerUser = 0

	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	t.Cleanup(srv.Close)
	return srv
}

// /auth/login recorded every failed attempt and then let the next one through, so
// password guessing was bounded only by how fast bcrypt would answer. The throttle
// must reject further attempts from a source that has been failing — including one
// carrying the correct password, which is what proves it is a real gate and not
// just a different error message.
func TestLoginThrottleBlocksAfterRepeatedFailures(t *testing.T) {
	proxy := newThrottleTestServer(t, 3)

	for i := 0; i < 3; i++ {
		resp := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "wrong"})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, resp.StatusCode)
		}
	}

	blocked := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "correct-password"})
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a throttled source must be refused even with the correct password, got %d", blocked.StatusCode)
	}
	if blocked.Header.Get("Retry-After") == "" {
		t.Error("a throttled response must tell the caller how long to wait")
	}
}

// Normal use must be unaffected: failures below the limit still allow a correct
// password through.
func TestLoginBelowThrottleLimitStillSucceeds(t *testing.T) {
	proxy := newThrottleTestServer(t, 5)

	for i := 0; i < 2; i++ {
		resp := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "wrong"})
		resp.Body.Close()
	}
	ok := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "correct-password"})
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("a correct password below the limit must succeed, got %d", ok.StatusCode)
	}
}

// A zero window disables the throttle entirely, so a deployment that has not
// configured it behaves exactly as before.
func TestLoginThrottleDisabledWhenUnconfigured(t *testing.T) {
	proxy := newThrottleTestServer(t, 0)
	for i := 0; i < 4; i++ {
		resp := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "wrong"})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, resp.StatusCode)
		}
	}
	ok := postJSON(t, proxy.URL+"/auth/login", "", map[string]string{"email": "root@example.com", "password": "correct-password"})
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("with no per-IP limit configured login must still work, got %d", ok.StatusCode)
	}
}
