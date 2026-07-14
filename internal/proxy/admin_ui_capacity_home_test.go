package proxy

import (
	"strings"
	"testing"
)

func TestCapacityVisualizationAndGuideUXContract(t *testing.T) {
	for _, marker := range []string{
		"openK8sCapacityGuide", "용량·자동확장 운영 가이드", "capacityMeter",
		"확장·노드 수용력 요약", "HPA desired / max", "노드 CPU request 점유율",
		"30일 내 소진", "sim-workload-options", "k8sSimPick", "실제 scale은 수행하지 않습니다",
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("capacity UX is missing %q", marker)
		}
	}
}

func TestOperationsHomePriorityAndGuideUXContract(t *testing.T) {
	for _, marker := range []string{
		"openK8sHomeGuide", "운영 홈 활용 가이드", "데이터 신뢰도", "지금 무엇을 먼저 볼지",
		"장애 파악", "변경 추적", "용량 점검", "승인·조치", "우선 확인할 중대 장애 후보",
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("operations home UX is missing %q", marker)
		}
	}
}
