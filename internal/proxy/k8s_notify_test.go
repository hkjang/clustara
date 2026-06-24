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
	}
	for _, c := range cases {
		if got := inQuietHours(c.spec, c.hour); got != c.want {
			t.Errorf("inQuietHours(%q,%d)=%v want %v", c.spec, c.hour, got, c.want)
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
