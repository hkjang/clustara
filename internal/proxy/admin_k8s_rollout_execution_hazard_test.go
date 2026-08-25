package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func hazardTarget() store.K8sInventoryItem {
	return store.K8sInventoryItem{
		ID: "dep-api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api", UID: "uid-api",
		Spec: map[string]any{"replicas": float64(2)},
		StatusObject: map[string]any{
			"replicas": float64(2), "updatedReplicas": float64(2), "readyReplicas": float64(2),
			"availableReplicas": float64(2), "observedGeneration": float64(4),
		},
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func hazardServer(t *testing.T, items ...store.K8sInventoryItem) *Server {
	t.Helper()
	db := openTestStore(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "c1"}); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{db: db}
}

// The full precheck runs when a rollout is requested, but an approval can be
// granted hours later. These conditions appear without changing the target's
// spec, so the drift check cannot see them.
func TestRolloutExecutionHazardBlocksDisruptionUnsafeStates(t *testing.T) {
	ctx := context.Background()
	roll := store.K8sRolloutAction{
		ID: "roll-1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-api",
	}

	t.Run("target being deleted", func(t *testing.T) {
		target := hazardTarget()
		target.DeletionTimestamp = time.Now().UTC().Format(time.RFC3339Nano)
		server := hazardServer(t, target)
		if hazard := server.rolloutExecutionHazard(ctx, roll, target); !strings.Contains(hazard, "deleted") {
			t.Fatalf("hazard = %q, want the deletion to block execution", hazard)
		}
	})

	t.Run("another rollout in progress", func(t *testing.T) {
		target := hazardTarget()
		target.StatusObject["updatedReplicas"] = float64(1)
		server := hazardServer(t, target)
		if hazard := server.rolloutExecutionHazard(ctx, roll, target); !strings.Contains(hazard, "in progress") {
			t.Fatalf("hazard = %q, want the in-flight rollout to block execution", hazard)
		}
	})

	t.Run("PodDisruptionBudget allows nothing", func(t *testing.T) {
		target := hazardTarget()
		pdb := store.K8sInventoryItem{
			ID: "pdb-api", ClusterID: "c1", Kind: "PodDisruptionBudget", Namespace: "prod", Name: "api",
			Spec:         map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}},
			StatusObject: map[string]any{"disruptionsAllowed": float64(0)},
			ObservedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		}
		target.Spec["selector"] = map[string]any{"matchLabels": map[string]any{"app": "api"}}
		server := hazardServer(t, target, pdb)
		if hazard := server.rolloutExecutionHazard(ctx, roll, target); !strings.Contains(hazard, "PodDisruptionBudget") {
			t.Fatalf("hazard = %q, want the PDB to block execution", hazard)
		}
	})
}

// A healthy target must stay executable, and the check is deliberately narrower
// than the request-time precheck: a degraded workload is often exactly what an
// operator is restarting, so it stays advice rather than a block.
func TestRolloutExecutionHazardAllowsHealthyAndDegradedTargets(t *testing.T) {
	ctx := context.Background()
	roll := store.K8sRolloutAction{
		ID: "roll-1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-api",
	}

	healthy := hazardTarget()
	if hazard := hazardServer(t, healthy).rolloutExecutionHazard(ctx, roll, healthy); hazard != "" {
		t.Fatalf("healthy target reported hazard %q", hazard)
	}

	degraded := hazardTarget()
	degraded.StatusObject["readyReplicas"] = float64(0)
	degraded.StatusObject["availableReplicas"] = float64(0)
	if hazard := hazardServer(t, degraded).rolloutExecutionHazard(ctx, roll, degraded); hazard != "" {
		t.Fatalf("degraded target reported hazard %q; restarting it must stay possible", hazard)
	}
}

// validateRolloutExecutionTarget is the gate the executor calls, so the hazard
// has to surface through it and not just from the helper.
func TestValidateRolloutExecutionTargetSurfacesHazards(t *testing.T) {
	ctx := context.Background()
	target := hazardTarget()
	target.DeletionTimestamp = time.Now().UTC().Format(time.RFC3339Nano)
	server := hazardServer(t, target)

	roll := store.K8sRolloutAction{
		ID: "roll-1", ClusterID: "c1", Namespace: "prod", ResourceKind: "Deployment",
		ResourceName: "api", ResourceUID: "uid-api", PreviousSpecHash: hashJSON(target.Spec),
	}
	err := server.validateRolloutExecutionTarget(ctx, roll)
	if err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("validate error = %v, want the deletion hazard", err)
	}
}
