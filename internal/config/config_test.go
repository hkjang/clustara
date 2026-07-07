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
