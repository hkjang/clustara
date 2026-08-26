package proxy

import (
	"testing"

	"clustara/internal/store"
)

// A policy gate that never ran must not be reported as a gate that passed. When the
// policy set cannot be loaded the analyser sees an empty rule list and returns
// denied=false with no violations; recording that verbatim made the change look
// policy-validated. The brief must say "unavailable" instead.
func TestManifestBriefDistinguishesUnavailablePolicyFromChecked(t *testing.T) {
	cases := []struct {
		name   string
		policy map[string]any
		want   string
	}{
		{"gate ran and passed", map[string]any{"denied": false, "violations": []any{}}, "checked"},
		{"gate ran and denied", map[string]any{"denied": true}, "denied"},
		{"gate could not run", map[string]any{"status": "unavailable", "error": "database is closed"}, "unavailable"},
	}
	for _, c := range cases {
		req := store.K8sManifestChangeRequest{Validation: map[string]any{"policy": c.policy}}
		brief := manifestChangeBrief(req, map[string]any{"status": "passed"})
		decision, ok := brief["decision"].(map[string]any)
		if !ok {
			t.Fatalf("%s: brief has no decision map: %+v", c.name, brief)
		}
		if got := asStr(decision["policy"]); got != c.want {
			t.Errorf("%s: policy gate reported %q, want %q", c.name, got, c.want)
		}
	}
}

// A request with no validation recorded at all must read as not_run, never as
// checked.
func TestManifestBriefReportsNotRunWithoutValidation(t *testing.T) {
	brief := manifestChangeBrief(store.K8sManifestChangeRequest{}, map[string]any{"status": "passed"})
	decision, ok := brief["decision"].(map[string]any)
	if !ok {
		t.Fatalf("brief has no decision map: %+v", brief)
	}
	if got := asStr(decision["policy"]); got != "not_run" {
		t.Errorf("policy gate reported %q, want not_run", got)
	}
}
