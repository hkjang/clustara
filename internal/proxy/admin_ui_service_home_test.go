package proxy

import (
	"strings"
	"testing"
)

func TestServiceHomeOperationsUXContract(t *testing.T) {
	for _, marker := range []string{
		`class="service-home-hero"`,
		`class="service-home-score-ring"`,
		`class="service-home-metrics"`,
		`class="service-category-grid"`,
		`class="service-attention-clear"`,
		`class="service-worker-facts"`,
		`우선 조치 큐`,
		`attentionPriority={failed:0,degraded:1,pending_approval:2,expired:3}`,
		`const actions=(canOperate?`,
		`const workerActions=(canUpdate?`,
		`uxAllowed('k8s-stacks')`,
		`const detailRoute=uxAllowed('services-all')`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("service home is missing operations UX contract %q", marker)
		}
	}
}
