package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// postNotifyConfig posts a notification config patch and returns the status and raw body so a
// rejection can be asserted on (postJSON leaves the status to the caller).
func postNotifyConfig(t *testing.T, f *notifyScanFixture, body map[string]any) (int, string) {
	t.Helper()
	resp := postJSON(t, f.proxy.URL+"/admin/k8s/notify/config", "", body)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// notifyConfig reads back the stored notification config through GET.
func notifyConfig(t *testing.T, f *notifyScanFixture) map[string]any {
	t.Helper()
	return getJSON(t, f.proxy.URL+"/admin/k8s/notify/config")
}

// scanResult runs one notify scan and returns the whole decoded response: the fixture's scan()
// only reports the counters, while quiet-hours suppression is reported in "suppressed".
func scanResult(t *testing.T, f *notifyScanFixture) map[string]any {
	t.Helper()
	resp := postJSON(t, f.proxy.URL+"/admin/k8s/notify/scan", "", map[string]any{})
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode scan body %s: %v", raw, err)
	}
	return out
}

// Saving a quiet_hours window the scan can never honour used to return 200 and be echoed back by
// GET, so an operator who typed "25-30" was told the config was saved while night-time
// notifications kept going out. The write must reject exactly what inQuietHours reads as "never
// quiet", and a rejected write must leave the previously stored window in place.
func TestK8sNotifyConfigRejectsQuietHoursTheScanCannotHonour(t *testing.T) {
	f := newNotifyScanFixture(t)
	if code, body := postNotifyConfig(t, f, map[string]any{"quiet_hours": "22-08"}); code != http.StatusOK {
		t.Fatalf("valid quiet hours must be accepted: %d %s", code, body)
	}
	for _, bad := range []string{"25-30", "22", "abc-8", "-5", "22-", "22-22", "8:00-18:00"} {
		code, body := postNotifyConfig(t, f, map[string]any{"quiet_hours": bad})
		if code != http.StatusBadRequest {
			t.Errorf("quiet_hours %q suppresses nothing and must be rejected, got %d %s", bad, code, body)
		}
		if !strings.Contains(body, "invalid_quiet_hours") {
			t.Errorf("quiet_hours %q must be rejected with code invalid_quiet_hours, got %s", bad, body)
		}
		if got := notifyConfig(t, f)["quiet_hours"]; got != "22-08" {
			t.Errorf("rejected quiet_hours %q must leave the stored window intact, GET returned %v", bad, got)
		}
	}
	for _, good := range []string{"0-6", "23-0", "22-08", ""} {
		if code, body := postNotifyConfig(t, f, map[string]any{"quiet_hours": good}); code != http.StatusOK {
			t.Fatalf("quiet_hours %q must stay acceptable: %d %s", good, code, body)
		}
		if got := notifyConfig(t, f)["quiet_hours"]; got != good {
			t.Fatalf("quiet_hours %q was stored as %v", good, got)
		}
	}
}

// team_channels was only checked with json.Valid, so a JSON array or scalar was stored and then
// failed inside resolveTeamChannel's map unmarshal — every team silently routed to the default
// channel. The write must accept only what the read path can use.
func TestK8sNotifyConfigRejectsTeamChannelsResolveCannotRead(t *testing.T) {
	f := newNotifyScanFixture(t)
	const valid = `{"core":"#core-alerts"}`
	if code, body := postNotifyConfig(t, f, map[string]any{"team_channels": valid}); code != http.StatusOK {
		t.Fatalf("a team→channel object must be accepted: %d %s", code, body)
	}
	for _, bad := range []string{`[1,2]`, `"x"`, `3`, `null`, `{"core":3}`} {
		code, body := postNotifyConfig(t, f, map[string]any{"team_channels": bad})
		if code != http.StatusBadRequest {
			t.Errorf("team_channels %s is not a team→channel object and must be rejected, got %d %s", bad, code, body)
		}
		if !strings.Contains(body, "invalid_team_channels") {
			t.Errorf("team_channels %s must be rejected with code invalid_team_channels, got %s", bad, body)
		}
		if got := notifyConfig(t, f)["team_channels"]; got != valid {
			t.Errorf("rejected team_channels %s must leave the stored map intact, GET returned %v", bad, got)
		}
		if got := resolveTeamChannel(bad, "core"); got != "" {
			t.Errorf("read path already cannot use team_channels %s, resolveTeamChannel returned %q", bad, got)
		}
	}
	if code, body := postNotifyConfig(t, f, map[string]any{"team_channels": `{}`}); code != http.StatusOK {
		t.Fatalf("an empty object must stay acceptable: %d %s", code, body)
	}
	// A rejected field must not leave the request half applied: quiet_hours was written before
	// team_channels was checked, so a bad map still changed the quiet window.
	if code, _ := postNotifyConfig(t, f, map[string]any{"quiet_hours": "1-2", "team_channels": `[1,2]`}); code != http.StatusBadRequest {
		t.Fatalf("a bad team_channels must reject the whole request, got %d", code)
	}
	if got := notifyConfig(t, f)["quiet_hours"]; got != "" {
		t.Fatalf("a rejected request must not apply quiet_hours, GET returned %v", got)
	}
}

// End to end through Server.Routes: a window saved over the current hour actually suppresses the
// scan, a rejected window leaves that suppression in place, and clearing the window lets the
// finding through to Mattermost.
func TestK8sNotifyConfigQuietHoursSuppressesScan(t *testing.T) {
	f := newNotifyScanFixture(t)
	f.setFlags(t, map[string]string{"mattermost_enabled": "true", "mattermost_webhook_url": f.hookURL})

	// Covers the previous, current and next hour so an hour rollover mid-test cannot flake, and
	// wraps past midnight around hour 0/23 like a real "22-08" window.
	h := time.Now().Hour()
	window := fmt.Sprintf("%d-%d", (h+23)%24, (h+2)%24)
	if code, body := postNotifyConfig(t, f, map[string]any{"quiet_hours": window}); code != http.StatusOK {
		t.Fatalf("quiet hours %q must be accepted: %d %s", window, code, body)
	}
	if out := scanResult(t, f); out["suppressed"] != "quiet_hours" {
		t.Fatalf("scan inside the saved quiet window must be suppressed, got %v", out)
	}

	if code, body := postNotifyConfig(t, f, map[string]any{"quiet_hours": "25-30"}); code != http.StatusBadRequest {
		t.Fatalf("out-of-range quiet hours must be rejected: %d %s", code, body)
	}
	if out := scanResult(t, f); out["suppressed"] != "quiet_hours" {
		t.Fatalf("a rejected quiet_hours must not drop the stored window, scan returned %v", out)
	}
	if got := notifyConfig(t, f)["quiet_hours"]; got != window {
		t.Fatalf("stored window must survive the rejection, GET returned %v", got)
	}

	if code, body := postNotifyConfig(t, f, map[string]any{"quiet_hours": ""}); code != http.StatusOK {
		t.Fatalf("an empty quiet_hours must disable the window: %d %s", code, body)
	}
	if sent, _ := f.scan(t); sent != 1 {
		t.Fatalf("clearing quiet hours must let the privileged workload notify, sent=%d", sent)
	}
	select {
	case d := <-f.received:
		if !strings.Contains(d.Text, "Privileged 워크로드") {
			t.Fatalf("unexpected notification: %+v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected the finding to be delivered once quiet hours are cleared")
	}
}
