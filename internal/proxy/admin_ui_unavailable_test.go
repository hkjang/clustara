package proxy

import (
	"strings"
	"testing"
)

// The Text2SQL kill switch is a safety control, and its state was fabricated on
// a failed read: the catch returned {disabled: false}, drawing the box unchecked
// and labelling the service 정상.
//
// The control is interactive from that display. An operator whose kill switch is
// actually engaged sees "normal" — and clicking the box, believing they are
// engaging it, turns it OFF in the middle of the incident it was engaged for.
func TestKillSwitchStateIsNotFabricated(t *testing.T) {
	ui := adminUISource(t)

	if strings.Contains(ui, "api('/admin/text2sql/kill-switch').catch(() => ({ disabled: false }))") {
		t.Fatal("a failed kill-switch read still renders the control as off; the toggle then acts " +
			"from a state the server never reported")
	}
	if !strings.Contains(ui, "killState._unavailable") {
		t.Error("the kill-switch view does not distinguish an unknown state from off")
	}
	if !strings.Contains(ui, "상태 불명") {
		t.Error("an unknown kill-switch state is not labelled as unknown")
	}
	// The toggle must not be offered from a state the server never reported.
	idx := strings.Index(ui, "killState._unavailable")
	if idx < 0 {
		t.Fatal("kill-switch guard missing")
	}
	window := ui[idx:min(idx+400, len(ui))]
	if !strings.Contains(window, "전환할 수 없습니다") {
		t.Error("the kill-switch toggle is still offered when the real state is unknown")
	}
}

// Views whose emptiness reads as a conclusion must not present a fabricated
// empty result as the answer.
func TestSafetyListsMarkAFailedFetch(t *testing.T) {
	ui := adminUISource(t)

	if !strings.Contains(ui, "function unavailable(") || !strings.Contains(ui, "function fetchNotice(") {
		t.Fatal("the failed-fetch helpers are missing")
	}
	for _, swallowed := range []string{
		"api('/admin/approvals?status=pending&window=24h&limit=50').catch(() => (",
		"api('/admin/budgets').catch(() => (",
		"api('/admin/anomalies?recent=6h&z=3').catch(() => (",
	} {
		if strings.Contains(ui, swallowed) {
			t.Errorf("still swallowing a failure into an empty result: %s", swallowed)
		}
	}
	for _, rendered := range []string{"approvalsNotice", "anomaliesNotice", "fetchNotice(br, '예산')"} {
		if !strings.Contains(ui, rendered) {
			t.Errorf("%s is computed or expected but never rendered", rendered)
		}
	}
	// The empty-budget text must depend on whether the fetch succeeded.
	if !strings.Contains(ui, "br._unavailable ? '예산을 조회하지 못했습니다") {
		t.Error("an empty budget list still reads as \"no budgets configured\" after a failed fetch")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
