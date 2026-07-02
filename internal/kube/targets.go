package kube

import "clustara/internal/store"

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

// InventoryFromObject converts a raw Kubernetes object into Clustara's sanitized inventory shape.
func InventoryFromObject(kind, apiVersion string, obj map[string]any) store.K8sInventoryItem {
	return inventoryFromObject(kind, apiVersion, obj)
}

// EventFromObject converts a raw Kubernetes Event object into Clustara's event shape.
func EventFromObject(obj map[string]any) store.K8sEvent {
	return eventFromObject(obj)
}
