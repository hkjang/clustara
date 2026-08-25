package config

import (
	"strings"
	"testing"
	"time"
)

func clearOperationalConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"CLUSTARA_ENV", "APP_ENV", "STRICT_CONFIG", "CLUSTARA_STRICT_CONFIG",
		"GATEWAY_SECRET", "ADMIN_TOKEN", "ADMIN_READONLY_TOKEN",
		"AUTH_ENABLED", "AUTH_JWT_SECRET", "MODEL_PRICING_KRW_PER_1M",
		"SSO_KEYCLOAK_ENABLED", "SSO_KEYCLOAK_ISSUER_URL", "SSO_KEYCLOAK_CLIENT_ID",
		"WORKER_OWNER_ID", "WORKER_SHUTDOWN_TIMEOUT",
		"K8S_ROLLOUT_RECONCILER_ENABLED", "K8S_ROLLOUT_RECONCILER_INTERVAL",
		"K8S_ROLLOUT_RECONCILER_LEASE_TTL", "K8S_ROLLOUT_RECONCILER_BATCH_SIZE",
		"K8S_ROLLOUT_RECONCILER_MAX_BACKOFF",
		"K8S_TERMINAL_REAPER_ENABLED", "K8S_TERMINAL_REAPER_INTERVAL",
		"K8S_TERMINAL_REAPER_BATCH_SIZE", "K8S_TERMINAL_REAPER_MAX_BACKOFF",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadHTTPDefaultsAndPort(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("GATEWAY_SECRET", "test-secret")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Fatalf("ListenAddr = %q, want :9090", cfg.ListenAddr)
	}
	if cfg.HTTP.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s", cfg.HTTP.ReadHeaderTimeout)
	}
	if cfg.HTTP.ReadTimeout != 60*time.Second {
		t.Fatalf("ReadTimeout = %s", cfg.HTTP.ReadTimeout)
	}
	if cfg.HTTP.WriteTimeout != 10*time.Minute {
		t.Fatalf("WriteTimeout = %s", cfg.HTTP.WriteTimeout)
	}
	if cfg.HTTP.IdleTimeout != 120*time.Second {
		t.Fatalf("IdleTimeout = %s", cfg.HTTP.IdleTimeout)
	}
	if cfg.HTTP.MaxHeaderBytes != 1<<20 {
		t.Fatalf("MaxHeaderBytes = %d", cfg.HTTP.MaxHeaderBytes)
	}
}

func TestLoadRejectsDefaultGatewaySecretInProduction(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("CLUSTARA_ENV", "production")
	t.Setenv("GATEWAY_SECRET", "")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	_, err := Load()
	if err == nil {
		t.Fatal("expected production default GATEWAY_SECRET rejection")
	}
	if !strings.Contains(err.Error(), "GATEWAY_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsDefaultGatewaySecretInStrictMode(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("STRICT_CONFIG", "true")
	t.Setenv("GATEWAY_SECRET", "")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	_, err := Load()
	if err == nil {
		t.Fatal("expected strict mode default GATEWAY_SECRET rejection")
	}
	if !strings.Contains(err.Error(), "GATEWAY_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsOpenAdminInProduction(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("CLUSTARA_ENV", "production")
	t.Setenv("GATEWAY_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	_, err := Load()
	if err == nil {
		t.Fatal("expected production admin auth guard rejection")
	}
	if !strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsWeakAdminTokenInProduction(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("CLUSTARA_ENV", "production")
	t.Setenv("GATEWAY_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("ADMIN_TOKEN", "dev-admin")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	_, err := Load()
	if err == nil {
		t.Fatal("expected weak ADMIN_TOKEN rejection")
	}
	if !strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAllowsStrongLegacyAdminTokenInProduction(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("CLUSTARA_ENV", "production")
	t.Setenv("GATEWAY_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("ADMIN_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	if _, err := Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsKeycloakWithoutCoreAuth(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("GATEWAY_SECRET", "test-secret")
	t.Setenv("SSO_KEYCLOAK_ENABLED", "true")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	_, err := Load()
	if err == nil {
		t.Fatal("expected Keycloak without core auth to be rejected")
	}
	if !strings.Contains(err.Error(), "AUTH_ENABLED=true") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAllowsKeycloakWithCoreAuth(t *testing.T) {
	clearOperationalConfigEnv(t)
	t.Setenv("GATEWAY_SECRET", "test-secret")
	t.Setenv("SSO_KEYCLOAK_ENABLED", "true")
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_JWT_SECRET", "test-jwt-secret")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")

	if _, err := Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func loadWithWorkerEnv(t *testing.T, env map[string]string) (Config, error) {
	t.Helper()
	clearOperationalConfigEnv(t)
	t.Setenv("GATEWAY_SECRET", "test-secret")
	t.Setenv("MODEL_PRICING_KRW_PER_1M", "{}")
	for key, value := range env {
		t.Setenv(key, value)
	}
	return Load()
}

func TestLoadWorkerDefaults(t *testing.T) {
	cfg, err := loadWithWorkerEnv(t, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	workers := cfg.Workers
	if !workers.RolloutReconcilerEnabled || !workers.TerminalReaperEnabled {
		t.Fatal("durable K8s workers must default to enabled")
	}
	if workers.RolloutInterval != 5*time.Second || workers.RolloutLeaseTTL != time.Minute {
		t.Fatalf("rollout interval/lease = %s/%s, want 5s/1m", workers.RolloutInterval, workers.RolloutLeaseTTL)
	}
	if workers.RolloutBatchSize != 100 || workers.TerminalReaperBatchSize != 250 {
		t.Fatalf("batch sizes = %d/%d, want 100/250", workers.RolloutBatchSize, workers.TerminalReaperBatchSize)
	}
	if workers.TerminalReaperInterval != 30*time.Second {
		t.Fatalf("terminal reaper interval = %s, want 30s", workers.TerminalReaperInterval)
	}
	if workers.ShutdownTimeout != 15*time.Second {
		t.Fatalf("shutdown timeout = %s, want 15s", workers.ShutdownTimeout)
	}
	// The lease owner has to differ per replica; hostname+pid is the derived default.
	if workers.OwnerID == "" || !strings.Contains(workers.OwnerID, "-") {
		t.Fatalf("OwnerID = %q, want a derived hostname-pid identity", workers.OwnerID)
	}
}

func TestLoadKeepsExplicitWorkerOwnerID(t *testing.T) {
	cfg, err := loadWithWorkerEnv(t, map[string]string{"WORKER_OWNER_ID": "replica-3"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Workers.OwnerID != "replica-3" {
		t.Fatalf("OwnerID = %q, want replica-3", cfg.Workers.OwnerID)
	}
}

// A lease shorter than one tick lets a second replica adopt a rollout the
// current owner is still driving, which double-executes the patch.
func TestLoadRejectsRolloutLeaseShorterThanInterval(t *testing.T) {
	_, err := loadWithWorkerEnv(t, map[string]string{
		"K8S_ROLLOUT_RECONCILER_INTERVAL":  "30s",
		"K8S_ROLLOUT_RECONCILER_LEASE_TTL": "10s",
	})
	if err == nil || !strings.Contains(err.Error(), "LEASE_TTL") {
		t.Fatalf("expected a lease TTL error, got %v", err)
	}
}

func TestLoadRejectsInvalidWorkerTimings(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"zero rollout interval", map[string]string{"K8S_ROLLOUT_RECONCILER_INTERVAL": "0s"}, "INTERVAL"},
		{"zero rollout batch", map[string]string{"K8S_ROLLOUT_RECONCILER_BATCH_SIZE": "0"}, "BATCH_SIZE"},
		{"backoff below interval", map[string]string{"K8S_ROLLOUT_RECONCILER_MAX_BACKOFF": "1s"}, "MAX_BACKOFF"},
		{"zero reaper interval", map[string]string{"K8S_TERMINAL_REAPER_INTERVAL": "0s"}, "K8S_TERMINAL_REAPER_INTERVAL"},
		{"zero reaper batch", map[string]string{"K8S_TERMINAL_REAPER_BATCH_SIZE": "0"}, "K8S_TERMINAL_REAPER_BATCH_SIZE"},
		{"negative shutdown timeout", map[string]string{"WORKER_SHUTDOWN_TIMEOUT": "-1s"}, "WORKER_SHUTDOWN_TIMEOUT"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadWithWorkerEnv(t, tc.env); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// Disabling a worker must also disable its validation, so an operator can turn
// it off without first fixing timings they no longer use.
func TestLoadSkipsValidationForDisabledWorkers(t *testing.T) {
	cfg, err := loadWithWorkerEnv(t, map[string]string{
		"K8S_ROLLOUT_RECONCILER_ENABLED":   "false",
		"K8S_ROLLOUT_RECONCILER_INTERVAL":  "0s",
		"K8S_ROLLOUT_RECONCILER_LEASE_TTL": "0s",
		"K8S_TERMINAL_REAPER_ENABLED":      "false",
		"K8S_TERMINAL_REAPER_INTERVAL":     "0s",
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Workers.RolloutReconcilerEnabled || cfg.Workers.TerminalReaperEnabled {
		t.Fatal("workers should be disabled")
	}
}
