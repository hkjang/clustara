package proxy

import (
	"strings"
	"testing"
)

func TestAdminUserMenuAndMCPPageExposeUsageGuide(t *testing.T) {
	menuGuide := `🤖 MCP 사용 가이드`
	openAPIDownload := `openapi.json 내려받기`
	guideAt := strings.Index(adminHTML, menuGuide)
	downloadAt := strings.Index(adminHTML, openAPIDownload)
	if guideAt < 0 || downloadAt < 0 || guideAt > downloadAt {
		t.Fatalf("MCP usage guide must appear above openapi.json download: guide=%d download=%d", guideAt, downloadAt)
	}
	for _, marker := range []string{
		`gateway_search_api_catalog`,
		`k8s_node_metrics`,
		`k8s_pod_metrics`,
		`k8s_create_manifest_change`,
		`k8s_validate_manifest_change`,
		`k8s_apply_manifest_change`,
		`모니터링 <code>admin:read</code>`,
		`YAML 변경 <code>admin:write</code>`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("MCP guide missing %q", marker)
		}
	}
}

func TestMCPUsageGuideTabParticipatesInNavigationPolicy(t *testing.T) {
	adminTabs := tabSet(roleScopes["admin"], map[string]bool{})
	if !adminTabs["gateway-mcp"] {
		t.Fatal("admin:read user must receive gateway-mcp in allowed_tabs; otherwise the user-menu link is hidden")
	}
	developerTabs := tabSet(roleScopes["developer"], map[string]bool{})
	if developerTabs["gateway-mcp"] {
		t.Fatal("user without admin:read must not receive the admin MCP guide route")
	}
}
