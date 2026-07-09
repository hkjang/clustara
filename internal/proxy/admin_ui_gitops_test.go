package proxy

import (
	"strings"
	"testing"
)

func TestAdminUIIncludesGitOpsGuideAndQuickActions(t *testing.T) {
	for _, want := range []string{
		"GitOps 운영 가이드",
		"gitOpsGuideHTML",
		"gitOpsWorkflowHTML",
		"GitOps 빠른 등록",
		"gitOpsCreateSource",
		"gitOpsCreatePRDraft",
		"gitOpsCreateChangeWindow",
		"gitOpsCreateRollout",
		"gitOpsCreateEvidence",
		"1. Stack 연결",
	} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin UI should include GitOps guide marker %q", want)
		}
	}
}
