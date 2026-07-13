package proxy

import (
	"strings"
	"testing"
)

func TestJupyterHubNamedServerIdlePolicyUXContract(t *testing.T) {
	for _, marker := range []string{
		`현재 값 연결 테스트`,
		`id="jhub-api-test-result"`,
		`window.evaluateJupyterHubIdlePolicy`,
		`/jupyter-idle-policy`,
		`유휴 정책 미리보기`,
		`유휴 승인 요청 생성`,
		`idle_action_id`,
		`실행 직전에 활동 상태를 다시 검사합니다`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("JupyterHub idle policy UI is missing contract %q", marker)
		}
	}
}
