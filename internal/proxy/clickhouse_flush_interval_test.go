package proxy

import (
	"testing"
	"time"

	"clustara/internal/config"
)

// clickhouse.flush_interval is an admin-editable runtime setting, so the fact
// loop must read it from the overlay rather than from the boot config.
func TestChFlushIntervalUsesRuntimeOverlay(t *testing.T) {
	server := &Server{cfg: config.Config{ClickHouse: config.ClickHouseConfig{FlushInterval: 30 * time.Second}}}
	if got := server.chFlushInterval(); got != 30*time.Second {
		t.Fatalf("boot config interval = %s, want 30s", got)
	}

	overlay := config.ClickHouseConfig{FlushInterval: 2 * time.Second}
	server.chRuntime.Store(&overlay)
	if got := server.chFlushInterval(); got != 2*time.Second {
		t.Fatalf("admin-changed interval = %s, want 2s", got)
	}
}

func TestChFlushIntervalFallsBackToDefault(t *testing.T) {
	server := &Server{}
	if got := server.chFlushInterval(); got != defaultClickHouseFlushInterval {
		t.Fatalf("unset interval = %s, want the %s default", got, defaultClickHouseFlushInterval)
	}
	cleared := config.ClickHouseConfig{FlushInterval: 0}
	server.chRuntime.Store(&cleared)
	if got := server.chFlushInterval(); got != defaultClickHouseFlushInterval {
		t.Fatalf("cleared interval = %s, want the %s default", got, defaultClickHouseFlushInterval)
	}
}

func TestResyncFlushTicker(t *testing.T) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	if got, changed := resyncFlushTicker(ticker, time.Hour, time.Hour); changed || got != time.Hour {
		t.Fatalf("unchanged interval = (%s, %v), want (1h, false)", got, changed)
	}
	// A cleared setting must not reach Ticker.Reset, which panics on <= 0.
	if got, changed := resyncFlushTicker(ticker, time.Hour, 0); changed || got != time.Hour {
		t.Fatalf("non-positive interval = (%s, %v), want (1h, false)", got, changed)
	}
	if got, changed := resyncFlushTicker(ticker, time.Hour, 50*time.Millisecond); !changed || got != 50*time.Millisecond {
		t.Fatalf("changed interval = (%s, %v), want (50ms, true)", got, changed)
	}
	// The reset must actually take effect, not just be recorded.
	select {
	case <-ticker.C:
	case <-time.After(3 * time.Second):
		t.Fatal("ticker did not fire on the shortened interval")
	}
}

func TestResyncFlushTickerToleratesNilTicker(t *testing.T) {
	if got, changed := resyncFlushTicker(nil, time.Minute, time.Second); changed || got != time.Minute {
		t.Fatalf("nil ticker = (%s, %v), want (1m, false)", got, changed)
	}
}
