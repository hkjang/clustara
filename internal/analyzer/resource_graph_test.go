package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestBuildResourceGraphLinksIngressServicePodPVCAndNode(t *testing.T) {
	items := []store.K8sInventoryItem{
		{
			ClusterID: "c1", Kind: "Ingress", Namespace: "default", Name: "web",
			Spec: map[string]any{
				"rules": []any{
					map[string]any{
						"host": "web.example.com",
						"http": map[string]any{
							"paths": []any{
								map[string]any{
									"path": "/api",
									"backend": map[string]any{
										"service": map[string]any{"name": "web", "port": map[string]any{"number": float64(80)}},
									},
								},
							},
						},
					},
				},
			},
		},
		{ClusterID: "c1", Kind: "Service", Namespace: "default", Name: "web", Spec: map[string]any{
			"selector": map[string]any{"app": "web"},
			"ports":    []any{map[string]any{"name": "http", "port": float64(80), "targetPort": "http-app", "nodePort": float64(30080), "protocol": "TCP"}},
		}},
		{ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "web", Spec: map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "web"}}}},
		{ClusterID: "c1", Kind: "Pod", Namespace: "default", Name: "web-123", Labels: map[string]string{"app": "web"}, RiskLevel: "high", Spec: map[string]any{
			"nodeName": "node-1",
			"volumes":  []any{map[string]any{"persistentVolumeClaim": map[string]any{"claimName": "data"}}},
		}},
		{ClusterID: "c1", Kind: "PersistentVolumeClaim", Namespace: "default", Name: "data"},
		{ClusterID: "c1", Kind: "Node", Name: "node-1"},
	}
	owners := []store.K8sNamespaceOwnership{{ClusterID: "c1", Namespace: "default", Team: "platform", ServiceName: "frontend", Criticality: "high", CostCenter: "cc-1"}}

	g := BuildResourceGraph(items, owners, ResourceGraphFocus{ClusterID: "c1", Kind: "Service", Namespace: "default", Name: "web", Radius: 2})
	if len(g.Nodes) != 6 {
		t.Fatalf("nodes = %d, want 6: %+v", len(g.Nodes), g.Nodes)
	}
	for _, want := range []string{"routes_to", "selects", "owns", "mounts", "scheduled_on"} {
		if !hasGraphRelation(g.Edges, want) {
			t.Fatalf("missing relation %q in %+v", want, g.Edges)
		}
	}
	if g.Impact.HighRisk != 1 || g.Impact.HighestRisk != "high" {
		t.Fatalf("impact risk wrong: %+v", g.Impact)
	}
	if len(g.Impact.Teams) != 1 || g.Impact.Teams[0] != "platform" {
		t.Fatalf("teams wrong: %+v", g.Impact.Teams)
	}
	assertGraphNodePorts(t, g.Nodes, "Ingress", []string{"web.example.com/api → web:80"})
	assertGraphNodePorts(t, g.Nodes, "Service", []string{"http: 80/TCP → target http-app · nodePort 30080"})
	for _, edge := range g.Edges {
		if edge.Relation == "routes_to" && edge.Reason != "Ingress backend web.example.com/api → web:80" {
			t.Fatalf("ingress edge should expose backend port, got %q", edge.Reason)
		}
	}
}

func TestBuildResourceGraphPreservesParallelIngressRoutes(t *testing.T) {
	items := []store.K8sInventoryItem{
		{
			ClusterID: "c1", Kind: "Ingress", Namespace: "default", Name: "web",
			Spec: map[string]any{
				"rules": []any{
					map[string]any{
						"host": "web.example.com",
						"http": map[string]any{"paths": []any{
							map[string]any{
								"path":    "/api",
								"backend": map[string]any{"service": map[string]any{"name": "web", "port": map[string]any{"number": float64(80)}}},
							},
							map[string]any{
								"path":    "/admin",
								"backend": map[string]any{"service": map[string]any{"name": "web", "port": map[string]any{"number": float64(8080)}}},
							},
						}},
					},
				},
			},
		},
		{ClusterID: "c1", Kind: "Service", Namespace: "default", Name: "web"},
	}

	g := BuildResourceGraph(items, nil, ResourceGraphFocus{ClusterID: "c1"})
	var routeReasons []string
	for _, edge := range g.Edges {
		if edge.Relation == "routes_to" {
			routeReasons = append(routeReasons, edge.Reason)
		}
	}
	if len(routeReasons) != 2 {
		t.Fatalf("parallel ingress routes = %v, want both host/path/port routes", routeReasons)
	}
	if routeReasons[0] == routeReasons[1] {
		t.Fatalf("parallel ingress route evidence must be distinct: %v", routeReasons)
	}
}

func assertGraphNodePorts(t *testing.T, nodes []ResourceGraphNode, kind string, want []string) {
	t.Helper()
	for _, node := range nodes {
		if node.Kind == kind {
			if len(node.Ports) != len(want) {
				t.Fatalf("%s ports = %+v, want %+v", kind, node.Ports, want)
			}
			for i := range want {
				if node.Ports[i] != want[i] {
					t.Fatalf("%s ports = %+v, want %+v", kind, node.Ports, want)
				}
			}
			return
		}
	}
	t.Fatalf("missing %s node", kind)
}

func TestBuildResourceGraphDefaultViewExcludesIsolatedRBACNoise(t *testing.T) {
	items := []store.K8sInventoryItem{
		{ClusterID: "c1", Kind: "Service", Namespace: "default", Name: "web", Spec: map[string]any{"selector": map[string]any{"app": "web"}}},
		{ClusterID: "c1", Kind: "Pod", Namespace: "default", Name: "web-123", Labels: map[string]string{"app": "web"}},
		{ClusterID: "c1", Kind: "ClusterRole", Name: "system:discovery"},
		{ClusterID: "c1", Kind: "ClusterRoleBinding", Name: "system:discovery"},
	}

	g := BuildResourceGraph(items, nil, ResourceGraphFocus{ClusterID: "c1"})
	if len(g.Nodes) != 2 {
		t.Fatalf("default topology should include only connected nodes, got %+v", g.Nodes)
	}
	for _, n := range g.Nodes {
		if n.Kind == "ClusterRole" || n.Kind == "ClusterRoleBinding" {
			t.Fatalf("default topology should not be dominated by isolated RBAC nodes: %+v", g.Nodes)
		}
	}
	if !hasGraphRelation(g.Edges, "selects") {
		t.Fatalf("default topology should keep service selector edge: %+v", g.Edges)
	}
}

func hasGraphRelation(edges []ResourceGraphEdge, relation string) bool {
	for _, e := range edges {
		if e.Relation == relation {
			return true
		}
	}
	return false
}
