package proxy

import (
	"strings"
	"testing"
)

func TestAdminUIQuickAccessFitsViewportAndSearchesMajorResources(t *testing.T) {
	for _, want := range []string{
		"max-height: calc(100dvh - 76px)",
		"overflow-y: auto; overscroll-behavior: contain",
		"@media (max-width: 720px)",
		"주요 리소스 검색 · Pod, Deployment, StatefulSet 등",
		"UX_QUICK_RESOURCE_KINDS",
		"uxQuickAccessInventorySearch",
		"uxMergeQuickAccessResources",
		"limit: '2000'",
	} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin quick access should include %q", want)
		}
	}
}
