package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// differentHourZone returns an IANA zone whose current hour is at least 3 hours away from the
// server's local hour, so a quiet window built around one clock provably excludes the other. The
// margin leaves room for the 3-hour window below plus an hour rollover mid-test.
func differentHourZone(t *testing.T, now time.Time) (*time.Location, int) {
	t.Helper()
	local := now.Hour()
	for _, name := range []string{
		"Asia/Seoul", "UTC", "America/New_York", "Europe/Berlin", "Pacific/Auckland",
		"Asia/Kolkata", "America/Los_Angeles", "Pacific/Kiritimati", "Etc/GMT+12", "Asia/Kathmandu",
	} {
		loc, err := time.LoadLocation(name)
		if err != nil {
			continue
		}
		h := now.In(loc).Hour()
		d := local - h
		if d < 0 {
			d = -d
		}
		if d > 12 {
			d = 24 - d
		}
		if d >= 3 {
			return loc, h
		}
	}
	t.Fatalf("no candidate IANA zone reads an hour far enough from the server's local hour %d", local)
	return nil, 0
}

// quietWindowAround builds a 3-hour "HH-HH" window covering the hour before, the hour itself and
// the hour after, so an hour rollover during the test cannot move the scan out of it.
func quietWindowAround(hour int) string {
	return fmt.Sprintf("%d-%d", (hour+23)%24, (hour+2)%24)
}

// Quiet hours were judged with time.Now().Hour() — the clock of the container the gateway happens
// to run in, which in a closed-network image without tzdata is UTC. An operator in Seoul who saves
// "22-08" then gets the opposite of what they asked for: alerts fire all night and are suppressed
// through the working day. The window must be judged in the timezone the operator configured.
func TestK8sNotifyScanJudgesQuietHoursInTheConfiguredTimezone(t *testing.T) {
	f := newNotifyScanFixture(t)
	f.setFlags(t, map[string]string{"mattermost_enabled": "true", "mattermost_webhook_url": f.hookURL})

	now := time.Now()
	loc, zoneHour := differentHourZone(t, now)

	// A window that is quiet in the configured zone but never in the server's local time.
	if code, body := postNotifyConfig(t, f, map[string]any{
		"quiet_hours": quietWindowAround(zoneHour), "timezone": loc.String(),
	}); code != http.StatusOK {
		t.Fatalf("quiet hours in zone %s must be accepted: %d %s", loc, code, body)
	}
	out := scanResult(t, f)
	if out["suppressed"] != "quiet_hours" {
		t.Fatalf("hour %d is inside the quiet window in the configured zone %s (server local hour %d), so the scan must be suppressed, got %v",
			zoneHour, loc, now.Hour(), out)
	}
	if out["timezone"] != loc.String() {
		t.Errorf("the scan must report which clock it judged the window on, got %v", out["timezone"])
	}

	// The converse: a window around the server's local hour must no longer suppress anything once
	// the scan is told to use the configured zone, and the finding must reach Mattermost.
	if code, body := postNotifyConfig(t, f, map[string]any{
		"quiet_hours": quietWindowAround(now.Hour()), "timezone": loc.String(),
	}); code != http.StatusOK {
		t.Fatalf("quiet hours around the local hour must be accepted: %d %s", code, body)
	}
	if sent, _ := f.scan(t); sent != 1 {
		t.Fatalf("a window that is quiet only in the server's local time must not suppress a scan judged in zone %s, sent=%d", loc, sent)
	}
	select {
	case d := <-f.received:
		if !strings.Contains(d.Text, "Privileged 워크로드") {
			t.Fatalf("unexpected notification: %+v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected the finding to be delivered when the configured zone is outside the quiet window")
	}
}

// An empty timezone must keep the behaviour every scan had before the setting existed: the server's
// local clock. Changing that silently would move every already-configured quiet window.
func TestK8sNotifyScanDefaultsQuietHoursToServerLocalTime(t *testing.T) {
	f := newNotifyScanFixture(t)
	f.setFlags(t, map[string]string{"mattermost_enabled": "true", "mattermost_webhook_url": f.hookURL})

	if code, body := postNotifyConfig(t, f, map[string]any{
		"quiet_hours": quietWindowAround(time.Now().Hour()), "timezone": "",
	}); code != http.StatusOK {
		t.Fatalf("an empty timezone must be accepted: %d %s", code, body)
	}
	if out := scanResult(t, f); out["suppressed"] != "quiet_hours" {
		t.Fatalf("with no timezone configured the window must still be judged on the server's local clock, got %v", out)
	}
}

// The write must reject exactly what the read path cannot load, the same contract quiet_hours and
// team_channels already follow: a stored zone the scan cannot resolve would silently fall back to
// the server clock, which is the bug this setting exists to fix.
func TestK8sNotifyConfigRejectsTimezoneTheScanCannotLoad(t *testing.T) {
	f := newNotifyScanFixture(t)
	if code, body := postNotifyConfig(t, f, map[string]any{"timezone": "Asia/Seoul"}); code != http.StatusOK {
		t.Fatalf("a real IANA zone must be accepted: %d %s", code, body)
	}
	for _, bad := range []string{"Not/AZone", "KST", "+09:00", "Asia/Seoul/extra", "../../etc/passwd"} {
		code, body := postNotifyConfig(t, f, map[string]any{"timezone": bad})
		if code != http.StatusBadRequest {
			t.Errorf("timezone %q cannot be loaded and must be rejected, got %d %s", bad, code, body)
		}
		if !strings.Contains(body, "invalid_timezone") {
			t.Errorf("timezone %q must be rejected with code invalid_timezone, got %s", bad, body)
		}
		if got := notifyConfig(t, f)["timezone"]; got != "Asia/Seoul" {
			t.Errorf("rejected timezone %q must leave the stored zone intact, GET returned %v", bad, got)
		}
	}
	for _, good := range []string{"UTC", "America/New_York", ""} {
		if code, body := postNotifyConfig(t, f, map[string]any{"timezone": good}); code != http.StatusOK {
			t.Fatalf("timezone %q must stay acceptable: %d %s", good, code, body)
		}
		if got := notifyConfig(t, f)["timezone"]; got != good {
			t.Fatalf("timezone %q was stored as %v", good, got)
		}
	}
	// A rejected zone must not leave the request half applied.
	if code, _ := postNotifyConfig(t, f, map[string]any{"quiet_hours": "1-2", "timezone": "Not/AZone"}); code != http.StatusBadRequest {
		t.Fatalf("a bad timezone must reject the whole request, got %d", code)
	}
	if got := notifyConfig(t, f)["quiet_hours"]; got != "" {
		t.Fatalf("a rejected request must not apply quiet_hours, GET returned %v", got)
	}
}
