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
						"http": map[string]any{
							"paths": []any{
								map[string]any{
									"backend": map[string]any{
										"service": map[string]any{"name": "web"},
									},
								},
							},
						},
					},
				},
			},
		},
		{ClusterID: "c1", Kind: "Service", Namespace: "default", Name: "web", Spec: map[string]any{"selector": map[string]any{"app": "web"}}},
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
}

func hasGraphRelation(edges []ResourceGraphEdge, relation string) bool {
	for _, e := range edges {
		if e.Relation == relation {
			return true
		}
	}
	return false
}
