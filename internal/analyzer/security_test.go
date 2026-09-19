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

// SEC-06 is a set difference over namespaces, and a posture run without a cluster_id covers
// every cluster — so one cluster's NetworkPolicy must not cover another cluster's namespace of
// the same name, which would drop the unprotected namespace from the report entirely.
func TestAnalyzeSecurityNetworkGapIsPerCluster(t *testing.T) {
	prod := deployWithPodSpec("shop", "api", map[string]any{
		"containers": []any{map[string]any{"name": "c", "image": "registry/api:1.2.3"}},
	})
	prod.ClusterID = "prod"
	dr := prod
	dr.ClusterID = "dr"
	items := []store.K8sInventoryItem{
		prod, dr,
		{ClusterID: "prod", Kind: "NetworkPolicy", Namespace: "shop", Name: "default-deny"},
	}
	rep := AnalyzeSecurity(items)
	if len(rep.Network) != 1 {
		t.Fatalf("expected exactly the dr gap, got %+v", rep.Network)
	}
	if rep.Network[0].ClusterID != "dr" || rep.Network[0].Namespace != "shop" {
		t.Fatalf("expected the gap on dr/shop, got %+v", rep.Network[0])
	}
}

// The Pod Security table is rendered for every cluster when the caller passes no cluster_id, and
// the UI builds its YAML/topology deep links from each row's cluster_id — so a row must carry the
// cluster of the inventory item it was classified from, not stay empty.
func TestAnalyzeSecurityPodSecurityCarriesClusterID(t *testing.T) {
	prod := deployWithPodSpec("shop", "api", map[string]any{
		"hostNetwork": true,
		"containers":  []any{map[string]any{"name": "c", "image": "registry/api:1.2.3"}},
	})
	prod.ClusterID = "prod"
	dr := prod
	dr.ClusterID = "dr"
	rep := AnalyzeSecurity([]store.K8sInventoryItem{prod, dr})
	if len(rep.PodSecurity) != 2 {
		t.Fatalf("expected one row per cluster, got %+v", rep.PodSecurity)
	}
	got := map[string]bool{}
	for _, p := range rep.PodSecurity {
		if p.Namespace != "shop" || p.Name != "api" {
			t.Fatalf("unexpected row %+v", p)
		}
		got[p.ClusterID] = true
	}
	if !got["prod"] || !got["dr"] {
		t.Fatalf("each pod_security row must carry its own cluster_id, got %+v", rep.PodSecurity)
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
		mk("bob", "high", "2026-06-20T09:00:00Z"),   // outside window → ignored
		mk("alice", "high", "2026-06-24T09:40:00Z"), // only 1 → below threshold
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

func rbacRev(rules ...map[string]any) store.K8sResourceRevision {
	raw := make([]any, 0, len(rules))
	for _, r := range rules {
		raw = append(raw, r)
	}
	return store.K8sResourceRevision{Spec: map[string]any{"rules": raw}}
}

// A rule that drops its resourceNames goes from one named Secret to every Secret in the
// namespace — the textbook expansion SEC-08 exists to catch. Both sides used to flatten to
// the same "|secrets|get", so the change was invisible.
func TestRBACDiffExpansions_DroppingResourceNamesIsAnExpansion(t *testing.T) {
	from := rbacRev(map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}, "resourceNames": []any{"tls-cert"}})
	to := rbacRev(map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}})
	added := RBACDiffExpansions(from, to)
	if len(added) != 1 || added[0] != "|secrets|get" {
		t.Fatalf("expected the unrestricted secrets/get to be reported, got %+v", added)
	}
	if !IsRiskyPermission(added[0]) {
		t.Fatalf("unrestricted secrets/get should be risky")
	}

	// Adding a second name is an expansion limited to that name; the original name is not new.
	wider := rbacRev(map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}, "resourceNames": []any{"tls-cert", "db-creds"}})
	added = RBACDiffExpansions(from, wider)
	if len(added) != 1 || added[0] != "|secrets|get|db-creds" {
		t.Fatalf("expected only the newly named secret, got %+v", added)
	}
	if !IsRiskyPermission(added[0]) {
		t.Fatalf("a named secrets/get should still count as secret access")
	}

	// The reverse — restricting an open rule to one name — is a narrowing, not an expansion.
	if got := RBACDiffExpansions(to, from); len(got) != 0 {
		t.Fatalf("adding resourceNames narrows the rule, got %+v", got)
	}
}

// Narrowing "*" to a concrete list was reported as a risky addition of every listed item,
// because the rendered triples differ even though the old rule already allowed them.
func TestRBACDiffExpansions_WildcardAlreadyCoversNarrowerRule(t *testing.T) {
	cases := []struct {
		name     string
		from, to map[string]any
	}{
		{"resources * → secrets",
			map[string]any{"apiGroups": []any{""}, "resources": []any{"*"}, "verbs": []any{"get"}},
			map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}}},
		{"verbs * → get,list",
			map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"*"}},
			map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get", "list"}}},
		{"apiGroups * → apps",
			map[string]any{"apiGroups": []any{"*"}, "resources": []any{"deployments"}, "verbs": []any{"get"}},
			map[string]any{"apiGroups": []any{"apps"}, "resources": []any{"deployments"}, "verbs": []any{"get"}}},
		{"*/scale → deployments/scale",
			map[string]any{"apiGroups": []any{"apps"}, "resources": []any{"*/scale"}, "verbs": []any{"update"}},
			map[string]any{"apiGroups": []any{"apps"}, "resources": []any{"deployments/scale"}, "verbs": []any{"update"}}},
		{"cluster-admin → anything",
			map[string]any{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"}},
			map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}, "resourceNames": []any{"x"}}},
	}
	for _, tc := range cases {
		if got := RBACDiffExpansions(rbacRev(tc.from), rbacRev(tc.to)); len(got) != 0 {
			t.Errorf("%s: narrowing reported as expansion: %+v", tc.name, got)
		}
		// And the opposite direction is an expansion — the wildcard is what got added.
		if got := RBACDiffExpansions(rbacRev(tc.to), rbacRev(tc.from)); len(got) == 0 {
			t.Errorf("%s: widening to the wildcard form was not reported", tc.name)
		}
	}
}

// "*/scale" is a subresource wildcard; it must not be read as covering "deployments".
// A group wildcard on one resource does not cover a different resource either.
func TestRBACDiffExpansions_WildcardDoesNotOverReach(t *testing.T) {
	from := rbacRev(
		map[string]any{"apiGroups": []any{"apps"}, "resources": []any{"*/scale"}, "verbs": []any{"update"}},
		map[string]any{"apiGroups": []any{"*"}, "resources": []any{"pods"}, "verbs": []any{"get"}},
	)
	to := rbacRev(
		map[string]any{"apiGroups": []any{"apps"}, "resources": []any{"deployments"}, "verbs": []any{"update"}},
		map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}},
	)
	added := RBACDiffExpansions(from, to)
	if len(added) != 2 || added[0] != "apps|deployments|update" || added[1] != "|secrets|get" {
		t.Fatalf("expected both concrete grants reported, got %+v", added)
	}
}

// nonResourceURLs rules were not read at all, so a ClusterRole that gained "*" on every
// non-resource path showed no change.
func TestRBACDiffExpansions_NonResourceURLs(t *testing.T) {
	from := rbacRev(map[string]any{"nonResourceURLs": []any{"/healthz", "/metrics"}, "verbs": []any{"get"}})
	to := rbacRev(map[string]any{"nonResourceURLs": []any{"*"}, "verbs": []any{"*"}})
	added := RBACDiffExpansions(from, to)
	if len(added) != 1 || added[0] != "|*|*" {
		t.Fatalf("expected the non-resource wildcard reported, got %+v", added)
	}
	if !IsRiskyPermission(added[0]) {
		t.Fatalf("non-resource wildcard should be risky")
	}
	// A trailing "*" is a prefix match: "/metrics*" already covers "/metrics/cadvisor".
	prefix := rbacRev(map[string]any{"nonResourceURLs": []any{"/metrics*"}, "verbs": []any{"get"}})
	sub := rbacRev(map[string]any{"nonResourceURLs": []any{"/metrics/cadvisor"}, "verbs": []any{"get"}})
	if got := RBACDiffExpansions(prefix, sub); len(got) != 0 {
		t.Fatalf("prefix URL rule already covers the sub-path, got %+v", got)
	}
	if got := RBACDiffExpansions(sub, prefix); len(got) != 1 || got[0] != "|/metrics*|get" {
		t.Fatalf("expected the prefix URL reported as new, got %+v", got)
	}
}

// An apiGroup wildcard is flagged high by the posture check (rbac-wildcard); the diff's risky
// marker used to look only at the resource and verb slots.
func TestIsRiskyPermission_APIGroupWildcard(t *testing.T) {
	if !IsRiskyPermission("*|deployments|get") {
		t.Fatalf("apiGroups=* should be risky")
	}
	if IsRiskyPermission("apps|deployments|get") {
		t.Fatalf("plain deployments/get should not be risky")
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
