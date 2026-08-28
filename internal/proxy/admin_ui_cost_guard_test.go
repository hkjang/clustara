package proxy

import (
	"strings"
	"testing"
)

// The Safety page's cost-guard card is a form, and its save posts exactly the two
// fields the card renders:
//
//	enabled:       #cost-enabled.checked
//	threshold_krw: #cost-threshold.value
//
// A failed read of /admin/cost used to render the guard as off with a 0
// threshold. Saving from that state writes enabled:false and threshold_krw:0 --
// disabling the guard and destroying its configured threshold, over a state the
// server never reported.
//
// This is the write-side of the kill-switch defect fixed in v0.9.230: there a
// click flipped a control from a fabricated position; here a save replaces real
// configuration with fabricated defaults.
func TestCostGuardFormIsWithheldWhenItsStateIsUnknown(t *testing.T) {
	ui := adminUISource(t)

	if strings.Contains(ui, "api('/admin/cost').catch(() => ({ enabled: false, threshold_krw: 0 }))") {
		t.Fatal("a failed cost-guard read still renders the guard as off with a 0 threshold, and the " +
			"save posts those values back over the real configuration")
	}
	if !strings.Contains(ui, "cost._unavailable") {
		t.Error("the cost-guard card does not distinguish an unknown state from off")
	}
	if !strings.Contains(ui, "편집 폼을 표시하지 않습니다") {
		t.Error("the cost-guard form is not withheld when the current settings are unknown")
	}
}

// Withholding the form removes #cost-save, so binding its listener
// unconditionally would throw and take the rest of the page's initialisation
// with it.
func TestCostSaveListenerToleratesTheWithheldForm(t *testing.T) {
	ui := adminUISource(t)
	if strings.Contains(ui, "document.getElementById('cost-save').addEventListener(") {
		t.Fatal("the cost-save listener is still bound unconditionally; with the form withheld this " +
			"throws on a null element and aborts the remaining setup on the page")
	}
	if !strings.Contains(ui, "if (costSaveBtn) costSaveBtn.addEventListener(") {
		t.Error("the cost-save listener is not guarded against the withheld form")
	}
}
