package proxy

import "testing"

func TestManifestSecretPayloadGuidanceExplainsSafeNextActions(t *testing.T) {
	g := manifestSecretPayloadGuidance("create")
	if g["why_blocked"] == "" {
		t.Fatal("why_blocked must be present")
	}
	allowed, ok := g["allowed_here"].([]string)
	if !ok || len(allowed) == 0 {
		t.Fatalf("allowed_here = %#v", g["allowed_here"])
	}
	next, ok := g["next_actions"].([]string)
	if !ok || len(next) < 3 {
		t.Fatalf("next_actions = %#v", g["next_actions"])
	}
}
