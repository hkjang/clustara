package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/config"
	"clustara/internal/store"
)

func TestOpsStatusReportsConfigAndDisk(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	cfg := testConfig("http://upstream.invalid", "secret")
	// Force the insecure default secret + raw prompt logging so the snapshot flags them.
	cfg.Secret.GatewaySecret = config.DefaultGatewaySecret
	cfg.Logging.RawPrompts = true

	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/admin/ops/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var got OpsStatus
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}

	if !got.Security.DevSecret {
		t.Error("expected dev_secret=true when GATEWAY_SECRET is the default")
	}
	if !got.Security.RawPromptsLogged {
		t.Error("expected raw_prompts_logged=true")
	}
	if !got.Security.PricingConfigured {
		t.Error("expected pricing_configured=true (testConfig sets a price)")
	}
	if got.Security.AuthEnabled {
		t.Error("expected auth_enabled=false")
	}
	if got.Disk.Path == "" {
		t.Error("expected a disk path to be reported")
	}
	if got.Disk.Available && got.Disk.TotalBytes == 0 {
		t.Error("disk reported available but total bytes is zero")
	}
	if got.GeneratedAt == "" {
		t.Error("expected generated_at timestamp")
	}
}

func TestOpsWorkersExposeWorkerHealthAndAliases(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	cfg := testConfig("http://upstream.invalid", "secret")
	retention := store.NewRetentionWorker(db, config.RetentionConfig{RequestDays: 7})
	server, err := NewServer(cfg, db, logger, retention)
	if err != nil {
		t.Fatal(err)
	}
	alerts := NewAlertWorker(db, server.MetricsHandle(), time.Second)
	server.AttachAlertWorker(alerts)
	alerts.Start()
	defer alerts.Stop()

	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(proxy.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("%s expected 200, got %d: %s", path, resp.StatusCode, body)
		}
		resp.Body.Close()
	}

	for _, path := range []string{"/admin/ops/workers", "/admin/workers"} {
		resp, err := http.Get(proxy.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("%s expected 200, got %d: %s", path, resp.StatusCode, body)
		}
		var got struct {
			Overall string         `json:"overall"`
			Workers []workerStatus `json:"workers"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		seen := map[string]workerStatus{}
		for _, w := range got.Workers {
			seen[w.Name] = w
		}
		if seen["async_logger"].Capacity != 32 {
			t.Fatalf("async_logger capacity not exposed: %+v", seen["async_logger"])
		}
		if !seen["alert_worker"].Running {
			t.Fatalf("alert_worker should be attached and running: %+v", seen["alert_worker"])
		}
		if _, ok := seen["clickhouse_fact_queue"]; !ok {
			t.Fatalf("clickhouse_fact_queue missing from workers: %+v", got.Workers)
		}
	}
}
