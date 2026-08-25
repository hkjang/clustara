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
		"limit: '20'",
		"uxResourceSearchController.abort()",
		"로컬 결과 · 서버 갱신 실패",
		"local ? { ...local, ...item } : item",
	} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin quick access should include %q", want)
		}
	}
	if strings.Contains(adminHTML, "item.name || '', item.catalog_id || ''") {
		t.Fatal("Quick Access resource identity must not include catalog_id")
	}
	seqIndex := strings.Index(adminHTML, "const seq = ++uxResourceSearchSeq")
	shortQueryIndex := strings.Index(adminHTML, "if (!query || query.length < 2)")
	if seqIndex < 0 || shortQueryIndex < 0 || seqIndex > shortQueryIndex {
		t.Fatal("Quick Access must invalidate the active search before returning for a short query")
	}
}
