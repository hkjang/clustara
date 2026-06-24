package analyzer

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func secByRule(fs []SecFinding, rule string) (SecFinding, bool) {
	for _, f := range fs {
		if f.Rule == rule {
			return f, true
		}
	}
	return SecFinding{}, false
}

func deployWithPodSpec(ns, name string, podSpec map[string]any) store.K8sInventoryItem {
	return store.K8sInventoryItem{Kind: "Deployment", Namespace: ns, Name: name,
		Spec: map[string]any{"template": map[string]any{"spec": podSpec}}}
}

func TestAnalyzeSecurityPodSecurityLevels(t *testing.T) {
	items := []store.K8sInventoryItem{
		// privileged: hostNetwork + privileged container
		deployWithPodSpec("default", "priv", map[string]any{
			"hostNetwork": true,
			"containers":  []any{map[string]any{"name": "c", "image": "x:1", "securityContext": map[string]any{"privileged": true}}},
		}),
		// restricted: hardened container
		deployWithPodSpec("default", "hardened", map[string]any{
			"securityContext": map[string]any{"runAsNonRoot": true},
			"containers": []any{map[string]any{"name": "c", "image": "x@sha256:abc", "securityContext": map[string]any{
				"runAsNonRoot": true, "allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}}}},
		}),
	}
	rep := AnalyzeSecurity(items)
	if rep.Summary.Privileged != 1 || rep.Summary.Restricted != 1 {
		t.Fatalf("expected 1 privileged + 1 restricted, got %+v", rep.Summary)
	}
	var priv PodSecurityResult
	for _, p := range rep.PodSecurity {
		if p.Name == "priv" {
			priv = p
		}
	}
	if priv.Level != "privileged" {
		t.Fatalf("priv workload should be privileged level, got %+v", priv)
	}
}

func TestAnalyzeSecurityRBAC(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "ClusterRole", Name: "admin", Spec: map[string]any{"rules": []any{
			map[string]any{"verbs": []any{"*"}, "resources": []any{"*"}, "apiGroups": []any{"*"}}}}},
		{Kind: "Role", Namespace: "default", Name: "secret-reader", Spec: map[string]any{"rules": []any{
			map[string]any{"verbs": []any{"get", "list"}, "resources": []any{"secrets"}, "apiGroups": []any{""}}}}},
	}
	rep := AnalyzeSecurity(items)
	if _, ok := secByRule(rep.RBAC, "rbac-cluster-admin"); !ok {
		t.Fatalf("expected rbac-cluster-admin, got %+v", rep.RBAC)
	}
	if _, ok := secByRule(rep.RBAC, "rbac-secret-access"); !ok {
		t.Fatalf("expected rbac-secret-access, got %+v", rep.RBAC)
	}
}

func TestAnalyzeSecurityImageAndNetwork(t *testing.T) {
	items := []store.K8sInventoryItem{
		deployWithPodSpec("prod", "api", map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": "registry/api:latest"}},
		}),
		// prod has a workload but no NetworkPolicy -> network gap.
	}
	rep := AnalyzeSecurity(items)
	if _, ok := secByRule(rep.Images, "image-tag-policy"); !ok {
		t.Fatalf("expected image-tag-policy for :latest, got %+v", rep.Images)
	}
	if _, ok := secByRule(rep.Network, "no-network-policy"); !ok {
		t.Fatalf("expected no-network-policy gap for prod, got %+v", rep.Network)
	}

	// With a NetworkPolicy present, the gap disappears.
	items = append(items, store.K8sInventoryItem{Kind: "NetworkPolicy", Namespace: "prod", Name: "default-deny"})
	rep2 := AnalyzeSecurity(items)
	if _, ok := secByRule(rep2.Network, "no-network-policy"); ok {
		t.Fatalf("network gap should be gone once a NetworkPolicy exists: %+v", rep2.Network)
	}
}

func TestDetectActionAnomalies(t *testing.T) {
	now := mustTime("2026-06-24T10:00:00Z")
	mk := func(user, risk, at string) store.K8sActionRequest {
		return store.K8sActionRequest{RequestedBy: user, RiskLevel: risk, CreatedAt: at}
	}
	actions := []store.K8sActionRequest{
		mk("bob", "high", "2026-06-24T09:30:00Z"),
		mk("bob", "critical", "2026-06-24T09:31:00Z"),
		mk("bob", "high", "2026-06-24T09:32:00Z"),
		mk("bob", "low", "2026-06-24T09:33:00Z"),    // low → ignored
		mk("bob", "high", "2026-06-20T09:00:00Z"),    // outside window → ignored
		mk("alice", "high", "2026-06-24T09:40:00Z"),  // only 1 → below threshold
	}
	// threshold 3 within 1h: bob has 3 risky → flagged; alice has 1 → not.
	out := DetectActionAnomalies(actions, now, time.Hour, 3)
	if len(out) != 1 || out[0].ResourceName != "bob" {
		t.Fatalf("expected only bob flagged, got %+v", out)
	}
}

func mustTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func TestRBACDiffExpansions(t *testing.T) {
	from := store.K8sResourceRevision{Spec: map[string]any{"rules": []any{
		map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get", "list"}},
	}}}
	to := store.K8sResourceRevision{Spec: map[string]any{"rules": []any{
		map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get", "list"}},
		map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"list"}}, // added risky
	}}}
	added := RBACDiffExpansions(from, to)
	if len(added) != 1 || added[0] != "|secrets|list" {
		t.Fatalf("expected added secrets|list, got %+v", added)
	}
	if !IsRiskyPermission(added[0]) {
		t.Fatalf("secrets/list should be risky")
	}
	if IsRiskyPermission("|pods|get") {
		t.Fatalf("pods/get should not be risky")
	}
	// No change → no expansions.
	if got := RBACDiffExpansions(to, to); len(got) != 0 {
		t.Fatalf("identical specs should yield no expansions, got %+v", got)
	}
}

func TestAnalyzeSecuritySecretRefs(t *testing.T) {
	items := []store.K8sInventoryItem{
		deployWithPodSpec("default", "api", map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": "x:1",
				"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "db-creds"}}}}},
		}),
	}
	rep := AnalyzeSecurity(items)
	f, ok := secByRule(rep.Secrets, "secret-access")
	if !ok || len(f.Evidence) == 0 || f.Evidence[0] != "db-creds" {
		t.Fatalf("expected secret-access referencing db-creds, got %+v", rep.Secrets)
	}
}
