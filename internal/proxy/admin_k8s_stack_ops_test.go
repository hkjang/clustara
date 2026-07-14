package proxy

import (
	"testing"

	"clustara/internal/analyzer"
)

func TestDiffStackResources(t *testing.T) {
	src := []analyzer.StackResource{
		{Kind: "Deployment", Namespace: "prod", Name: "web"},
		{Kind: "Service", Namespace: "prod", Name: "web-svc"},
		{Kind: "ConfigMap", Namespace: "prod", Name: "cfg"},
	}
	target := []analyzer.StackResource{
		{Kind: "Deployment", Namespace: "prod", Name: "web"},
		{Kind: "Ingress", Namespace: "prod", Name: "old-ing"},
	}
	diff := diffStackResources(src, target)
	if len(diff.Common) != 1 || diff.Common[0] != "Deployment/prod/web" {
		t.Fatalf("common wrong: %+v", diff.Common)
	}
	if len(diff.Added) != 2 {
		t.Fatalf("added = %+v, want 2 (Service, ConfigMap)", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0] != "Ingress/prod/old-ing" {
		t.Fatalf("removed wrong: %+v", diff.Removed)
	}
}

func TestResolveStackTargets(t *testing.T) {
	docs := []map[string]any{
		{"kind": "Deployment", "apiVersion": "apps/v1", "metadata": map[string]any{"name": "web", "namespace": "prod"}},
		{"kind": "Service", "apiVersion": "v1", "metadata": map[string]any{"name": "svc"}}, // no namespace → default
		{"metadata": map[string]any{"name": "noop"}},                                       // no kind → skipped
	}
	targets := resolveStackTargets(docs, "fallback-ns")
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[1].Namespace != "fallback-ns" {
		t.Fatalf("expected default namespace fallback, got %q", targets[1].Namespace)
	}
}

func TestStackApplyApprovalGateAllowsReadOnlyDryRun(t *testing.T) {
	if stackApplyNeedsApproval(true, true, false) {
		t.Fatal("approval-required stack must still allow a non-mutating server-side dry-run")
	}
	if !stackApplyNeedsApproval(true, false, false) {
		t.Fatal("real apply must remain blocked until explicitly confirmed")
	}
	if stackApplyNeedsApproval(true, false, true) || stackApplyNeedsApproval(false, false, false) {
		t.Fatal("confirmed or policy-allowed apply must pass the approval gate")
	}
}
