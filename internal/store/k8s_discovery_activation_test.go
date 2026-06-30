package store

import (
	"context"
	"path/filepath"
	"testing"

	"clustara/internal/config"
)

func TestK8sDiscoveryActivation(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, config.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "act.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Activate a target and a tool.
	if err := db.SetK8sDiscoveryActivation(ctx, K8sDiscoveryActivation{ClusterID: "c1", Kind: "target", Key: "apps/v1/deployments", Enabled: true, UpdatedBy: "ops"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetK8sDiscoveryActivation(ctx, K8sDiscoveryActivation{ClusterID: "c1", Kind: "mcp_tool", Key: "k8s_list_pods", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Upsert toggles the same key off (no duplicate row).
	if err := db.SetK8sDiscoveryActivation(ctx, K8sDiscoveryActivation{ClusterID: "c1", Kind: "target", Key: "apps/v1/deployments", Enabled: false}); err != nil {
		t.Fatal(err)
	}

	targets, _ := db.ListK8sDiscoveryActivations(ctx, "c1", "target")
	if len(targets) != 1 || targets[0].Enabled {
		t.Fatalf("target should be a single disabled row after upsert: %+v", targets)
	}
	tools, _ := db.ListK8sDiscoveryActivations(ctx, "c1", "mcp_tool")
	if len(tools) != 1 || !tools[0].Enabled {
		t.Fatalf("tool should be enabled: %+v", tools)
	}
	all, _ := db.ListK8sDiscoveryActivations(ctx, "c1", "")
	if len(all) != 2 {
		t.Fatalf("expected 2 activations total: %+v", all)
	}
}
