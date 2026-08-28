package proxy

import (
	"strings"
	"testing"
)

// The backend now distinguishes "no findings" from "nothing was checked" —
// policy_check reports unavailable / no_rules / no_resources / partial, and the
// security and drift reports carry a scan block. None of it reaches an operator
// unless the UI reads it.
//
// The compliance view did the opposite: it swallowed a failed request into
// `{violations: []}` and rendered the empty table as "위반 없음", converting the
// backend's refusal back into a clean bill of health.
func TestAdminUIRendersScanState(t *testing.T) {
	ui := adminUISource(t)

	if !strings.Contains(ui, "function scanNotice(") || !strings.Contains(ui, "function scanIncomplete(") {
		t.Fatal("the scan-state helpers are missing from the admin UI")
	}

	// Every report that can answer "checked/partial/…" must render the state.
	for _, call := range []string{
		"scanNotice(comp.policy_check)", // K8s policy centre
		"scanNotice(data.scan)",         // K8s security posture
		"scanNotice(d.scan)",            // stack drift (resource and field views)
	} {
		if !strings.Contains(ui, call) {
			t.Errorf("no view renders %s; the backend state is computed and then dropped", call)
		}
	}
	// The drift helper is used by both drift views.
	if strings.Count(ui, "scanNotice(d.scan)") < 2 {
		t.Errorf("only %d drift view(s) render the scan state; both resource and field drift need it",
			strings.Count(ui, "scanNotice(d.scan)"))
	}
}

// A failed compliance request must not be rendered as an absence of violations.
func TestComplianceFetchFailureIsNotRenderedAsClean(t *testing.T) {
	ui := adminUISource(t)

	if strings.Contains(ui, "api('/admin/k8s/policies/compliance').catch(() => ({ violations: [] }))") {
		t.Fatal("a failed compliance request is still swallowed into an empty violations list, " +
			"which the table renders as \"위반 없음\" — the backend's refusal is undone in the browser")
	}
	if !strings.Contains(ui, "policy_check: { status: 'unavailable'") {
		t.Error("the compliance fetch's failure path does not mark the check unavailable")
	}
	// The empty-table text must depend on whether the check actually ran.
	if !strings.Contains(ui, "scanIncomplete(comp.policy_check) ? '검사가 완료되지 않아") {
		t.Error("the empty violations row still asserts \"위반 없음\" regardless of whether the check ran")
	}
}

func adminUISource(t *testing.T) string {
	t.Helper()
	return repoFile(t, "internal", "proxy", "admin_ui.go")
}
