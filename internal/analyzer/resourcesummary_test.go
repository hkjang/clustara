package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestSummarizePodResources(t *testing.T) {
	// Pod spec with one container requesting 250m/256Mi, limiting 500m/512Mi.
	spec := map[string]any{
		"containers": []any{
			map[string]any{"name": "web", "resources": map[string]any{
				"requests": map[string]any{"cpu": "250m", "memory": "256Mi"},
				"limits":   map[string]any{"cpu": "500m", "memory": "512Mi"},
			}},
		},
	}
	tags := SummarizePodResources(spec)
	if !tags.HasReq || !tags.HasLim {
		t.Fatalf("expected has req+lim, got %+v", tags)
	}
	if tags.ReqCPU != "250m" || tags.ReqMem != "256Mi" {
		t.Fatalf("requests wrong: %+v", tags)
	}
	if tags.LimCPU != "500m" || tags.LimMem != "512Mi" {
		t.Fatalf("limits wrong: %+v", tags)
	}

	// Workload spec (.template.spec.containers), whole-core + Gi formatting, two containers summed.
	wl := map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{
		map[string]any{"name": "a", "resources": map[string]any{"requests": map[string]any{"cpu": "1", "memory": "1Gi"}}},
		map[string]any{"name": "b", "resources": map[string]any{"requests": map[string]any{"cpu": "500m", "memory": "1Gi"}}},
	}}}}
	tw := SummarizePodResources(wl)
	if tw.ReqCPU != "1.5" { // 1000m + 500m
		t.Fatalf("summed cpu = %q, want 1.5", tw.ReqCPU)
	}
	if tw.ReqMem != "2Gi" { // 1Gi + 1Gi
		t.Fatalf("summed mem = %q, want 2Gi", tw.ReqMem)
	}
	if tw.HasLim {
		t.Fatalf("no limits declared, HasLim should be false")
	}

	// No resources → empty.
	empty := SummarizePodResources(map[string]any{"containers": []any{map[string]any{"name": "x"}}})
	if empty.HasReq || empty.HasLim {
		t.Fatalf("expected empty, got %+v", empty)
	}
}

func TestWorkloadGroupCarriesResourcesAndSamples(t *testing.T) {
	res := ResourceTags{ReqCPU: "250m", ReqMem: "256Mi", HasReq: true}
	pods := []WorkloadPod{
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "web", Name: "web-1", HealthScore: 80, HealthBand: "healthy", Ready: true, Resources: res},
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "web", Name: "web-2", HealthScore: 20, HealthBand: "critical", PrimarySymptom: "OOMKilled", RestartCount: 5, Resources: res},
	}
	groups := BuildWorkloadGroups(pods)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	g := groups[0]
	if !g.Resources.HasReq || g.Resources.ReqMem != "256Mi" {
		t.Fatalf("group resources not propagated: %+v", g.Resources)
	}
	// worst-health pod first in samples
	if len(g.SamplePods) != 2 || g.SamplePods[0] != "web-2" {
		t.Fatalf("sample pods wrong (worst-first expected): %+v", g.SamplePods)
	}
}

func TestRestartStormCarriesResources(t *testing.T) {
	res := ResourceTags{LimMem: "512Mi", HasLim: true}
	pods := []RestartStormPod{
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "api", Name: "api-1", RestartCount: 5, Unhealthy: true, Resources: res},
		{Namespace: "prod", OwnerKind: "ReplicaSet", OwnerName: "api", Name: "api-2", RestartCount: 4, Unhealthy: true, Resources: res},
	}
	storms := DetectRestartStorms(pods, RestartStormOptions{})
	if len(storms) != 1 {
		t.Fatalf("expected 1 storm, got %d", len(storms))
	}
	if !storms[0].Resources.HasLim || storms[0].Resources.LimMem != "512Mi" {
		t.Fatalf("storm resources not propagated: %+v", storms[0].Resources)
	}
}

func TestAttachFindingResources(t *testing.T) {
	findings := []RCAFinding{
		{ClusterID: "c1", Namespace: "prod", ResourceKind: "Pod", ResourceName: "web-1", Condition: "OOMKilled"},
		{ClusterID: "c1", Namespace: "prod", ResourceKind: "Pod", ResourceName: "ghost", Condition: "X"},
	}
	items := []store.K8sInventoryItem{
		{Kind: "Pod", Namespace: "prod", Name: "web-1", Spec: map[string]any{"containers": []any{
			map[string]any{"name": "web", "resources": map[string]any{"limits": map[string]any{"memory": "512Mi"}}},
		}}},
	}
	AttachFindingResources(findings, items)
	if findings[0].Resources == nil || findings[0].Resources.LimMem != "512Mi" {
		t.Fatalf("expected web-1 to get memory limit tag, got %+v", findings[0].Resources)
	}
	if findings[1].Resources != nil {
		t.Fatalf("ghost (no inventory match) should have nil Resources")
	}
}
