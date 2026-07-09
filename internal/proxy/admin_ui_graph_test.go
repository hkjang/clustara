package proxy

import (
	"strings"
	"testing"
)

func TestAdminUIIncludesResourceGraphTopologyCanvas(t *testing.T) {
	for _, want := range []string{
		"resource-graph-canvas",
		"k8sGraphVisualHTML",
		"openK8sGraphModal",
		"k8sGraphModalLink",
		"토폴로지 맵",
		"클릭하면 해당 리소스로 포커스 이동",
	} {
		if !strings.Contains(adminHTML, want) {
			t.Fatalf("admin UI should include resource graph topology marker %q", want)
		}
	}
}
