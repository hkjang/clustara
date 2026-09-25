package proxy

import "testing"

func TestInQuietHours(t *testing.T) {
	cases := []struct {
		spec string
		hour int
		want bool
	}{
		{"22-08", 23, true},  // wraps midnight
		{"22-08", 2, true},   // wraps midnight
		{"22-08", 12, false}, // daytime
		{"22-08", 8, false},  // end exclusive
		{"09-18", 10, true},  // same-day window
		{"09-18", 20, false},
		{"", 3, false},      // unset
		{"bad", 3, false},   // invalid
		{"08-08", 8, false}, // empty window
		{"23-0", 23, true},  // wraps to midnight
		{"23-0", 0, false},  // end exclusive
		{"0-6", 0, true},    // from midnight
		{"0-6", 6, false},
		// Specs the POST handler now rejects may already sit in the flag; reading stays lenient so
		// they keep their current meaning instead of silencing or unsilencing anything.
		{"25-30", 3, false}, // out of range window covers no hour
		{"-5", 3, false},    // missing start
		{"22-", 23, false},  // missing end
		{"abc-8", 3, false}, // non-numeric
		{"22-24", 23, true}, // stored before validation: still suppresses 22:00-24:00
		{"22-24", 21, false},
		{" 22 - 8 ", 23, true}, // padded
	}
	for _, c := range cases {
		if got := inQuietHours(c.spec, c.hour); got != c.want {
			t.Errorf("inQuietHours(%q,%d)=%v want %v", c.spec, c.hour, got, c.want)
		}
	}
}

// parseQuietHours is the one place a quiet window spec is read; inQuietHours and the POST handler
// must agree on what the two numbers are (the handler adds the range check the reader stays
// lenient about).
func TestParseQuietHours(t *testing.T) {
	cases := []struct {
		spec       string
		start, end int
		ok         bool
	}{
		{"22-08", 22, 8, true},
		{"0-6", 0, 6, true},
		{"23-0", 23, 0, true},
		{" 22 - 8 ", 22, 8, true},
		{"08-08", 8, 8, true},     // parses; inQuietHours treats it as no window
		{"25-30", 25, 30, true},   // parses; the range check belongs to validateQuietHours
		{"", 0, 0, false},         // unset
		{"22", 0, 0, false},       // no separator
		{"-5", 0, 0, false},       // missing start
		{"22-", 0, 0, false},      // missing end
		{"abc-8", 0, 0, false},    // non-numeric start
		{"22-08-09", 0, 0, false}, // three fields
	}
	for _, c := range cases {
		start, end, ok := parseQuietHours(c.spec)
		if ok != c.ok || start != c.start || end != c.end {
			t.Errorf("parseQuietHours(%q)=(%d,%d,%v) want (%d,%d,%v)", c.spec, start, end, ok, c.start, c.end, c.ok)
		}
	}
}

// validateQuietHours guards the write path: a spec that inQuietHours would read as "never quiet"
// must be rejected instead of stored, since the operator is told the config was saved.
func TestValidateQuietHours(t *testing.T) {
	for _, good := range []string{"", "   ", "22-08", "0-6", "23-0", " 22 - 8 "} {
		if err := validateQuietHours(good); err != nil {
			t.Errorf("validateQuietHours(%q) = %v, want accepted", good, err)
		}
	}
	for _, bad := range []string{"25-30", "22", "abc-8", "-5", "22-", "22-22", "8:00-18:00", "-1-5"} {
		if err := validateQuietHours(bad); err == nil {
			t.Errorf("validateQuietHours(%q) = nil, want rejected", bad)
		}
	}
	// These specs suppress nothing at any hour, which is why refusing to store them cannot change
	// what an operator observes — they only ever meant "no quiet hours".
	for _, bad := range []string{"25-30", "22", "abc-8", "-5", "22-", "22-22", "8:00-18:00", "-1-5"} {
		for hour := 0; hour < 24; hour++ {
			if inQuietHours(bad, hour) {
				t.Fatalf("validateQuietHours rejects %q but inQuietHours honours it at hour %d", bad, hour)
			}
		}
	}
}

func TestResolveTeamChannel(t *testing.T) {
	j := `{"core":"#core-alerts","data":"#data-ops"}`
	if got := resolveTeamChannel(j, "core"); got != "#core-alerts" {
		t.Errorf("core -> %q", got)
	}
	if got := resolveTeamChannel(j, "unknown"); got != "" {
		t.Errorf("unknown team should map to empty, got %q", got)
	}
	if got := resolveTeamChannel("", "core"); got != "" {
		t.Errorf("empty config should map to empty, got %q", got)
	}
	if got := resolveTeamChannel("not json", "core"); got != "" {
		t.Errorf("invalid json should map to empty, got %q", got)
	}
}

func TestK8sDeepLink(t *testing.T) {
	link := k8sDeepLink("https://gw.example.com/", "c1", "default", "Deployment", "api")
	want := "https://gw.example.com/admin#/k8s-timeline?"
	if len(link) < len(want) || link[:len(want)] != want {
		t.Fatalf("deep link prefix wrong: %s", link)
	}
	for _, sub := range []string{"cluster_id=c1", "namespace=default", "name=api", "kind=Deployment"} {
		if !containsSubstr(link, sub) {
			t.Errorf("deep link missing %q: %s", sub, link)
		}
	}
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
