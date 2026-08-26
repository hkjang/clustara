package proxy

import (
	"testing"

	"clustara/internal/store"
)

// The drift guard is the staleness control on a manifest apply: it compares the
// live resource's UID and baseline hash against what the request was built from.
// When it cannot read live state it reports "unknown" — neither comparison ran —
// and that used to fall through to "does not block", so an apply proceeded with no
// staleness guard at all. Unverified must not read as verified-safe.
func TestDriftGuardBlocksWhenItCouldNotVerify(t *testing.T) {
	cases := []struct {
		status      string
		hardBlock   bool
		wantPlain   bool
		wantForced  bool
		description string
	}{
		{status: "passed", wantPlain: false, wantForced: false, description: "verified clean"},
		{status: "drift", wantPlain: true, wantForced: false, description: "verified changed, operator may override"},
		{status: "blocked", hardBlock: true, wantPlain: true, wantForced: true, description: "hard block survives force"},
		{status: "unknown", wantPlain: true, wantForced: false, description: "could not verify, operator may override"},
	}
	for _, c := range cases {
		guard := map[string]any{"status": c.status}
		if c.hardBlock {
			guard["hard_block"] = true
		}
		if got := manifestChangeDriftBlocks(guard, false); got != c.wantPlain {
			t.Errorf("%s: blocks(force=false) = %v, want %v", c.description, got, c.wantPlain)
		}
		if got := manifestChangeDriftBlocks(guard, true); got != c.wantForced {
			t.Errorf("%s: blocks(force=true) = %v, want %v", c.description, got, c.wantForced)
		}
	}
}

// Why discarding the inventory read error in the rollout precheck was unsafe: a
// failed read yields an empty slice, and every inventory-backed safety check reads
// an empty slice as "nothing wrong". This pins that premise — the precheck must
// therefore refuse to run these checks rather than report their empty-input answers.
func TestEmptyInventoryMakesEverySafetyCheckLookClean(t *testing.T) {
	target := store.K8sInventoryItem{
		Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}},
	}
	var empty []store.K8sInventoryItem

	if hasBadOwnedPod(target, empty) {
		t.Error("precondition changed: empty inventory now reports bad pods")
	}
	if hasNotReadyNode(empty) {
		t.Error("precondition changed: empty inventory now reports NotReady nodes")
	}
	if hasBadPVC("prod", empty) {
		t.Error("precondition changed: empty inventory now reports bad PVCs")
	}
	if verdict := pdbSafety(target, empty); verdict.Blocked || verdict.Found {
		t.Errorf("precondition changed: empty inventory now yields a PDB verdict: %+v", verdict)
	}
	// All four are silent on empty input, so an unreported read error would have the
	// precheck announce "no blocking Pod errors" having examined no pods at all.
}

// A PodDisruptionBudget that has not yet reported disruptionsAllowed must block
// rather than be read as permissive — the same unverified-is-not-safe rule, which
// pdbSafety already applies.
func TestPDBWithoutReportedStatusBlocks(t *testing.T) {
	target := store.K8sInventoryItem{
		Kind: "Deployment", Namespace: "prod", Name: "api",
		Spec: map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}},
	}
	pdb := store.K8sInventoryItem{
		Kind: "PodDisruptionBudget", Namespace: "prod", Name: "api-pdb",
		Spec:         map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}},
		StatusObject: map[string]any{},
	}
	verdict := pdbSafety(target, []store.K8sInventoryItem{pdb})
	if !verdict.Blocked {
		t.Fatalf("PDB with no reported disruptionsAllowed must block: %+v", verdict)
	}
}
