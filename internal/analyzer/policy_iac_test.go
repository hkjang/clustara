package analyzer

import (
	"strings"
	"testing"
)

func TestExportKyverno(t *testing.T) {
	policies := []Policy{
		{ID: "1", Name: "특권 금지", RuleType: "disallow_privileged", Action: "Deny", Enabled: true},
		{ID: "2", Name: "limits", RuleType: "require_resource_limits", Action: "Warn", Enabled: true},
		{ID: "3", Name: "off", RuleType: "disallow_host_path", Action: "Deny", Enabled: false}, // skipped
	}
	out := ExportKyverno(policies)
	if !strings.Contains(out, "kind: ClusterPolicy") {
		t.Fatalf("missing ClusterPolicy header:\n%s", out)
	}
	// A Deny policy is present → enforce.
	if !strings.Contains(out, "validationFailureAction: Enforce") {
		t.Fatalf("expected Enforce action:\n%s", out)
	}
	if !strings.Contains(out, "disallow-privileged") || !strings.Contains(out, "require-resource-limits") {
		t.Fatalf("missing rule names:\n%s", out)
	}
	if strings.Contains(out, "disallow-host-path") {
		t.Fatalf("disabled policy should be skipped:\n%s", out)
	}
}

func TestExportRegoRoundTrip(t *testing.T) {
	policies := []Policy{
		{ID: "1", Name: "x", RuleType: "disallow_privileged", Action: "Deny", Enabled: true},
		{ID: "2", Name: "y", RuleType: "disallow_wildcard_rbac", Action: "Warn", Enabled: true},
	}
	rego := ExportRego(policies)
	if !strings.Contains(rego, "package clustara.guardrails") || !strings.Contains(rego, "deny[msg]") {
		t.Fatalf("rego shape wrong:\n%s", rego)
	}
	// Round-trip: exported Rego carries annotations → import recognizes both exactly.
	imported, _ := ImportPolicyText(rego)
	got := map[string]string{}
	for _, ip := range imported {
		got[ip.RuleType] = ip.Match
	}
	if got["disallow_privileged"] != "annotation" || got["disallow_wildcard_rbac"] != "annotation" {
		t.Fatalf("round-trip should match by annotation, got %+v", got)
	}
}

func TestImportHeuristic(t *testing.T) {
	// A foreign Kyverno-ish doc with no Clustara annotations → heuristic keyword match.
	doc := `
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest
spec:
  rules:
  - name: require-image-tag
    validate:
      message: "An image tag is required; :latest is not allowed"
      pattern:
        spec:
          containers:
          - image: "!*:latest"
`
	imported, warnings := ImportPolicyText(doc)
	found := false
	for _, ip := range imported {
		if ip.RuleType == "disallow_latest_tag" {
			if ip.Match != "heuristic" {
				t.Fatalf("expected heuristic match, got %q", ip.Match)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("should heuristically recognize disallow_latest_tag, got %+v", imported)
	}
	if len(warnings) == 0 {
		t.Fatalf("heuristic match should produce a warning")
	}
}

func TestImportNoMatch(t *testing.T) {
	imported, warnings := ImportPolicyText("some unrelated yaml: true")
	if len(imported) != 0 {
		t.Fatalf("expected no matches, got %+v", imported)
	}
	if len(warnings) == 0 {
		t.Fatalf("expected a 'nothing recognized' warning")
	}
}
