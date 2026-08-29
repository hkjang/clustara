package proxy

import (
	"sort"
	"strings"
	"testing"

	"clustara/internal/kube"
)

// The install manifest's ClusterRole and the agent's watch target list are two statements
// about the same thing — what the agent reads — kept in two places, and they had drifted
// apart in both directions. It granted apps/replicasets, which no target collects, and it
// omitted configmaps, serviceaccounts, poddisruptionbudgets and all four RBAC kinds, which
// targets do collect.
//
// Neither half announces itself. configmaps and serviceaccounts are non-optional targets,
// so a 403 on them aborts an entire HTTP collect with an opaque error. The RBAC kinds are
// optional, so a 403 on them is skipped in silence — and disallow_wildcard_rbac, the only
// policy rule that reads Role/ClusterRole, then reports "no violations" over an inventory
// that contains no Role at all (v0.9.242).
//
// The rules are now generated from the target list, so this pins that they stay generated:
// a hand-edit in either direction fails here by name.
func TestAgentManifestGrantsExactlyWhatTheAgentReads(t *testing.T) {
	granted := parseClusterRoleRules(t, agentInstallManifest("c1", "https://clustara.example", "img:v1", "tok"))

	needed := map[string]bool{}
	for _, target := range kube.DefaultWatchTargets() {
		group, resource, ok := kube.GroupResource(target.Path)
		if !ok {
			t.Fatalf("target %q has a path the RBAC mapper cannot read", target.Path)
		}
		needed[group+"/"+resource] = true
	}

	for key := range needed {
		if !granted[key] {
			t.Errorf("the agent watches %s but the install manifest does not grant it; a 403 here is "+
				"either a total collect abort or a silent gap, never an error the operator sees", key)
		}
	}
	for key := range granted {
		if !needed[key] {
			t.Errorf("the install manifest grants %s but no watch target reads it; a read-only agent "+
				"manifest is a security artifact and must not carry permissions nothing uses", key)
		}
	}
}

// Every grant must stay read-only. A collector that can write is a different product.
func TestAgentManifestGrantsOnlyReadVerbs(t *testing.T) {
	manifest := agentInstallManifest("c1", "https://clustara.example", "img:v1", "tok")
	block := clusterRoleBlock(t, manifest)
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "verbs:") {
			continue
		}
		if got := strings.TrimSpace(strings.TrimPrefix(line, "verbs:")); got != `["get", "list", "watch"]` {
			t.Fatalf("non read-only verbs in the agent ClusterRole: %s", got)
		}
	}
}

// clusterRoleBlock returns the manifest text from the ClusterRole's rules: to the next document.
func clusterRoleBlock(t *testing.T, manifest string) string {
	t.Helper()
	start := strings.Index(manifest, "\nrules:\n")
	if start < 0 {
		t.Fatal("no rules block in the generated manifest")
	}
	rest := manifest[start:]
	if end := strings.Index(rest, "\n---"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// parseClusterRoleRules reads the rendered rules into a set of "group/resource" keys. It
// reads the manifest text rather than the generator so a hand-edit is caught too.
func parseClusterRoleRules(t *testing.T, manifest string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	group := ""
	for _, line := range strings.Split(clusterRoleBlock(t, manifest), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		switch {
		case strings.HasPrefix(line, "apiGroups:"):
			groups := yamlStringList(strings.TrimPrefix(line, "apiGroups:"))
			if len(groups) != 1 {
				t.Fatalf("expected one apiGroup per rule, got %v", groups)
			}
			group = groups[0]
		case strings.HasPrefix(line, "resources:"):
			for _, resource := range yamlStringList(strings.TrimPrefix(line, "resources:")) {
				out[group+"/"+resource] = true
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no grants out of the manifest; the scan is looking at the wrong place")
	}
	return out
}

func yamlStringList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		out = append(out, strings.Trim(strings.TrimSpace(part), `"`))
	}
	sort.Strings(out)
	return out
}
