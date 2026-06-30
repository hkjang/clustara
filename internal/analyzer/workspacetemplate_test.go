package analyzer

import (
	"strings"
	"testing"
)

func TestGenerateWorkspaceTemplate(t *testing.T) {
	tpl := GenerateWorkspaceTemplate(WorkspaceTemplateRequest{
		Namespace: "payments", OwnerTeam: "fintech", Environment: "prod", CPUQuota: "8", MemQuota: "16Gi", PodQuota: "40", DefaultDeny: true,
	})
	for _, want := range []string{"kind: Namespace", "name: payments", "clustara.io/team: \"fintech\"", "kind: ResourceQuota", "requests.cpu: \"8\"", "kind: LimitRange", "kind: NetworkPolicy", "default-deny"} {
		if !strings.Contains(tpl.Manifest, want) {
			t.Fatalf("manifest missing %q:\n%s", want, tpl.Manifest)
		}
	}
	if len(tpl.Resources) != 4 {
		t.Fatalf("expected 4 resources (ns, quota, limitrange, netpol): %+v", tpl.Resources)
	}

	// Without default-deny → 3 resources, no NetworkPolicy.
	tpl2 := GenerateWorkspaceTemplate(WorkspaceTemplateRequest{Namespace: "dev"})
	if strings.Contains(tpl2.Manifest, "NetworkPolicy") || len(tpl2.Resources) != 3 {
		t.Fatalf("no default-deny should omit NetworkPolicy: %+v", tpl2.Resources)
	}
	// defaults applied.
	if !strings.Contains(tpl2.Manifest, "name: dev") || !strings.Contains(tpl2.Manifest, "pods: \"50\"") {
		t.Fatalf("defaults not applied: %s", tpl2.Manifest)
	}
}
