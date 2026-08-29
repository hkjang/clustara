package kube

import (
	"sort"
	"strings"

	"clustara/internal/store"
)

// ResourceTarget describes one Kubernetes collection/watch endpoint.
type ResourceTarget struct {
	Path             string
	Kind             string
	APIVersion       string
	Optional         bool
	KubernetesEvents bool
}

// DefaultInventoryTargets are the resource kinds Clustara stores in the current inventory.
func DefaultInventoryTargets() []ResourceTarget {
	return []ResourceTarget{
		{Path: "/api/v1/namespaces", Kind: "Namespace", APIVersion: "v1"},
		{Path: "/api/v1/nodes", Kind: "Node", APIVersion: "v1"},
		{Path: "/api/v1/pods", Kind: "Pod", APIVersion: "v1"},
		{Path: "/apis/apps/v1/deployments", Kind: "Deployment", APIVersion: "apps/v1"},
		{Path: "/apis/apps/v1/statefulsets", Kind: "StatefulSet", APIVersion: "apps/v1"},
		{Path: "/apis/apps/v1/daemonsets", Kind: "DaemonSet", APIVersion: "apps/v1"},
		{Path: "/api/v1/configmaps", Kind: "ConfigMap", APIVersion: "v1"},
		{Path: "/api/v1/serviceaccounts", Kind: "ServiceAccount", APIVersion: "v1"},
		{Path: "/api/v1/services", Kind: "Service", APIVersion: "v1"},
		{Path: "/apis/networking.k8s.io/v1/ingresses", Kind: "Ingress", APIVersion: "networking.k8s.io/v1", Optional: true},
		{Path: "/apis/networking.k8s.io/v1/networkpolicies", Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1", Optional: true},
		{Path: "/api/v1/persistentvolumeclaims", Kind: "PersistentVolumeClaim", APIVersion: "v1"},
		{Path: "/api/v1/secrets", Kind: "Secret", APIVersion: "v1", Optional: true},
		{Path: "/apis/batch/v1/jobs", Kind: "Job", APIVersion: "batch/v1"},
		{Path: "/apis/batch/v1/cronjobs", Kind: "CronJob", APIVersion: "batch/v1", Optional: true},
		{Path: "/apis/autoscaling/v2/horizontalpodautoscalers", Kind: "HorizontalPodAutoscaler", APIVersion: "autoscaling/v2", Optional: true},
		{Path: "/apis/policy/v1/poddisruptionbudgets", Kind: "PodDisruptionBudget", APIVersion: "policy/v1", Optional: true},
		{Path: "/apis/rbac.authorization.k8s.io/v1/roles", Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1", Optional: true},
		{Path: "/apis/rbac.authorization.k8s.io/v1/clusterroles", Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1", Optional: true},
		{Path: "/apis/rbac.authorization.k8s.io/v1/rolebindings", Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1", Optional: true},
		{Path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1", Optional: true},
	}
}

// DefaultWatchTargets are the resources watched by clustara-agent.
func DefaultWatchTargets() []ResourceTarget {
	targets := append([]ResourceTarget{}, DefaultInventoryTargets()...)
	targets = append(targets, ResourceTarget{Path: "/api/v1/events", Kind: "Event", APIVersion: "v1", KubernetesEvents: true})
	return targets
}

// RBACRule is one apiGroup's read grant in the collector agent's ClusterRole.
type RBACRule struct {
	APIGroup  string
	Resources []string
}

// GroupResource splits a list path into the (apiGroup, resource) pair the API server
// authorizes against. Core resources live under /api/v1/<resource> and carry the empty
// group; everything else under /apis/<group>/<version>/<resource>.
func GroupResource(path string) (group, resource string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(parts) == 3 && parts[0] == "api":
		return "", parts[2], true
	case len(parts) == 4 && parts[0] == "apis":
		return parts[1], parts[3], true
	}
	return "", "", false
}

// WatchRBACRules returns the least-privilege read grants an agent needs to watch the
// default target set, one entry per apiGroup with the core group first and the rest
// sorted, so the rendered manifest is stable.
//
// Generated rather than written out by hand. The hand-written ClusterRole that shipped
// in the install manifest had drifted from this list in both directions: it granted
// apps/replicasets, which nothing collects, and it was missing configmaps,
// serviceaccounts, poddisruptionbudgets and all four RBAC kinds, which everything does.
// The two halves of that gap fail differently and both fail quietly — configmaps and
// serviceaccounts are non-optional targets, so a 403 on them aborts an entire HTTP
// collect, while the RBAC kinds are optional, so a 403 on them is skipped in silence and
// disallow_wildcard_rbac then passes over an inventory containing no Role at all.
func WatchRBACRules() []RBACRule {
	byGroup := map[string]map[string]bool{}
	for _, target := range DefaultWatchTargets() {
		group, resource, ok := GroupResource(target.Path)
		if !ok {
			continue
		}
		if byGroup[group] == nil {
			byGroup[group] = map[string]bool{}
		}
		byGroup[group][resource] = true
	}
	groups := make([]string, 0, len(byGroup))
	for group := range byGroup {
		groups = append(groups, group)
	}
	sort.Strings(groups) // the empty core group sorts first, which is where it reads best
	out := make([]RBACRule, 0, len(groups))
	for _, group := range groups {
		resources := make([]string, 0, len(byGroup[group]))
		for resource := range byGroup[group] {
			resources = append(resources, resource)
		}
		sort.Strings(resources)
		out = append(out, RBACRule{APIGroup: group, Resources: resources})
	}
	return out
}

// InventoryFromObject converts a raw Kubernetes object into Clustara's sanitized inventory shape.
func InventoryFromObject(kind, apiVersion string, obj map[string]any) store.K8sInventoryItem {
	return inventoryFromObject(kind, apiVersion, obj)
}

// EventFromObject converts a raw Kubernetes Event object into Clustara's event shape.
func EventFromObject(obj map[string]any) store.K8sEvent {
	return eventFromObject(obj)
}
