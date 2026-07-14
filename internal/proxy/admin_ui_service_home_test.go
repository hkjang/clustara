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
		`const actions=(canUpdate&&`,
		`const workerActions=(canUpdate?`,
		`uxAllowed('k8s-stacks')`,
		`const detailRoute=uxAllowed('services-all')`,
		`openServiceDiscoveryGuide`,
		`연결 신뢰도·유형 분류 가이드`,
		`openServiceCandidateLabelModal`,
		`openServiceRegisteredLabelModal`,
		`/admin/k8s/services/discovery/label`,
		`Pod template에도 전파`,
		`기존 서비스 라벨과 충돌합니다`,
		`selector에 쓰이는 기존 app 라벨을 보존하고 새 요청을 생성하세요`,
		`AI Platform Agent · 자연어 서비스 빌더`,
		`/admin/k8s/services/agent-plan`,
		`platformAgentCheckReadiness`,
		`platformAgentStackDryRun`,
		`업무시간 외 제외`,
		`k8sNodeBusinessHourSeries`,
		`서비스·Stack 초안 등록`,
		`실제 클러스터에는 아직 적용되지 않습니다`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("service home is missing operations UX contract %q", marker)
		}
	}
}
