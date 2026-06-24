package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestBuildIncidents(t *testing.T) {
	findings := []RCAFinding{
		{ClusterID: "c1", Namespace: "prod", ResourceKind: "Pod", ResourceName: "api-1", Condition: "OOMKilled", Severity: "high", Cause: "메모리 초과", Evidence: []string{"limit 256Mi"}},
		{ClusterID: "c1", Namespace: "prod", ResourceKind: "Pod", ResourceName: "api-1", Condition: "OOMKilled", Severity: "high", Cause: "메모리 초과"}, // dup key
		{ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment", ResourceName: "web", Condition: "RolloutStuck", Severity: "medium"},        // medium → excluded
	}
	events := []store.K8sEvent{
		{Namespace: "prod", InvolvedName: "api-1", Type: "Warning", Reason: "OOMKilling", Message: "killed"},
		{Namespace: "prod", InvolvedName: "other", Type: "Warning", Reason: "X", Message: "noise"},
	}
	out := BuildIncidents(nil, findings, events)
	if len(out) != 1 {
		t.Fatalf("expected 1 incident (high, deduped, medium excluded), got %d: %+v", len(out), out)
	}
	d := out[0]
	if d.Key != "c1|prod|Pod|api-1|OOMKilled" || d.Condition != "OOMKilled" || d.Severity != "high" {
		t.Fatalf("incident draft wrong: %+v", d)
	}
	joined := strings.Join(d.Evidence, "\n")
	if !strings.Contains(joined, "메모리 초과") || !strings.Contains(joined, "limit 256Mi") || !strings.Contains(joined, "OOMKilling") {
		t.Fatalf("evidence should include cause + finding evidence + matching event: %+v", d.Evidence)
	}
	if strings.Contains(joined, "noise") {
		t.Fatalf("unrelated event must not be attached: %+v", d.Evidence)
	}
}
