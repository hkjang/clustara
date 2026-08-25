package proxy

import (
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func pdbTarget() store.K8sInventoryItem {
	return store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: map[string]any{
			"replicas": float64(2),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		},
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func pdbItem(name string, status map[string]any) store.K8sInventoryItem {
	return store.K8sInventoryItem{
		ID: "pdb-" + name, ClusterID: "c1", Kind: "PodDisruptionBudget", Namespace: "prod", Name: name,
		Spec:         map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}},
		StatusObject: status,
		ObservedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// Returning on the first matching budget let a permissive one mask a
// restrictive one covering the same pods — the wrong direction for a safety
// check. Every match is considered and the most restrictive wins.
func TestPDBSafetyMostRestrictiveWins(t *testing.T) {
	target := pdbTarget()
	permissive := pdbItem("permissive", map[string]any{"disruptionsAllowed": float64(1)})
	restrictive := pdbItem("restrictive", map[string]any{"disruptionsAllowed": float64(0)})

	for _, order := range [][]store.K8sInventoryItem{
		{target, permissive, restrictive},
		{target, restrictive, permissive},
	} {
		verdict := pdbSafety(target, order)
		if !verdict.Found {
			t.Fatal("a matching PodDisruptionBudget was not found")
		}
		if !verdict.Blocked {
			t.Fatalf("verdict = %+v, want blocked regardless of inventory order", verdict)
		}
		if !strings.Contains(verdict.Reason, "restrictive") {
			t.Fatalf("reason = %q, want it to name the deciding budget", verdict.Reason)
		}
	}
}

// A budget with no status yet blocks, but must not be reported as an explicit
// zero: an operator chasing "disruptionsAllowed=0" on an absent field would be
// looking for something that is not there.
func TestPDBSafetyDistinguishesUnreportedStatus(t *testing.T) {
	target := pdbTarget()
	verdict := pdbSafety(target, []store.K8sInventoryItem{target, pdbItem("fresh", map[string]any{})})
	if !verdict.Blocked {
		t.Fatalf("verdict = %+v, want an unreported budget to block conservatively", verdict)
	}
	if strings.Contains(verdict.Reason, "disruptionsAllowed=0") {
		t.Fatalf("reason = %q, want it to say the status is not reported yet", verdict.Reason)
	}
	if !strings.Contains(verdict.Reason, "not reported") {
		t.Fatalf("reason = %q, want it to name the unreported status", verdict.Reason)
	}
}

func TestPDBSafetyAllowsAndIgnoresNonMatching(t *testing.T) {
	target := pdbTarget()

	allowed := pdbSafety(target, []store.K8sInventoryItem{target, pdbItem("ok", map[string]any{"disruptionsAllowed": float64(2)})})
	if !allowed.Found || allowed.Blocked {
		t.Fatalf("verdict = %+v, want a found, unblocked budget", allowed)
	}

	other := pdbItem("other", map[string]any{"disruptionsAllowed": float64(0)})
	other.Spec["selector"] = map[string]any{"matchLabels": map[string]any{"app": "worker"}}
	unrelated := pdbSafety(target, []store.K8sInventoryItem{target, other})
	if unrelated.Found || unrelated.Blocked {
		t.Fatalf("verdict = %+v, want a budget for other pods to be ignored", unrelated)
	}

	otherNamespace := pdbItem("elsewhere", map[string]any{"disruptionsAllowed": float64(0)})
	otherNamespace.Namespace = "staging"
	crossNS := pdbSafety(target, []store.K8sInventoryItem{target, otherNamespace})
	if crossNS.Found || crossNS.Blocked {
		t.Fatalf("verdict = %+v, want a budget in another namespace to be ignored", crossNS)
	}
}
