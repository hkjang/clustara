package store

import (
	"context"
	"fmt"
	"testing"
)

func TestListK8sInventorySearchFiltersAndRanksBeforeLimit(t *testing.T) {
	db := openK8sAgentTestStore(t)
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, K8sCluster{ID: "c1", Name: "production-east", GroupID: "g1", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sClusterGroup(ctx, K8sClusterGroup{ID: "g1", Name: "production", Kind: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sNamespaceOwnership(ctx, K8sNamespaceOwnership{
		ID: "owner-prod", ClusterID: "c1", Namespace: "payments", Team: "platform-team", Owner: "sre",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if err := db.UpsertK8sInventory(ctx, K8sInventoryItem{
			ID:        fmt.Sprintf("decoy-%02d", i),
			ClusterID: "c1",
			Kind:      "Deployment",
			Namespace: "payments",
			Name:      fmt.Sprintf("recent-%02d", i),
			UpdatedAt: fmt.Sprintf("2026-07-28T02:%02d:00Z", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []K8sInventoryItem{
		{ID: "substring", ClusterID: "c1", Kind: "Deployment", Namespace: "payments", Name: "old-needle-worker", UpdatedAt: "2020-01-01T00:00:02Z"},
		{ID: "prefix", ClusterID: "c1", Kind: "Deployment", Namespace: "payments", Name: "needle-worker", UpdatedAt: "2020-01-01T00:00:01Z"},
		{ID: "exact", ClusterID: "c1", Kind: "Deployment", Namespace: "payments", Name: "needle", Spec: map[string]any{"image": "registry.example/needle:v1"}, UpdatedAt: "2020-01-01T00:00:00Z"},
	} {
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertCatalogEntity(ctx, CatalogEntity{
		ID: "catalog-needle", Kind: "service", Name: "catalog-token", RuntimeRef: "c1/payments/Deployment/needle",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := db.ListK8sInventory(ctx, K8sInventoryFilter{
		SearchTerms: []string{"needle"},
		RankQuery:   "needle",
		Limit:       2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "needle" || got[1].Name != "needle-worker" {
		t.Fatalf("ranked inventory search = %+v, want exact then prefix despite old timestamps", got)
	}

	ownerMatch, err := db.ListK8sInventory(ctx, K8sInventoryFilter{
		SearchTerms: []string{"platform-team", "needle"},
		Limit:       5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ownerMatch) != 3 {
		t.Fatalf("ownership-enriched inventory search = %+v, want all needle resources", ownerMatch)
	}

	catalogMatch, err := db.ListK8sInventory(ctx, K8sInventoryFilter{
		SearchTerms: []string{"catalog-token"},
		Limit:       5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(catalogMatch) != 1 || catalogMatch[0].Name != "needle" {
		t.Fatalf("catalog-enriched inventory search = %+v, want linked runtime", catalogMatch)
	}

	imageMatch, err := db.ListK8sInventory(ctx, K8sInventoryFilter{
		ImageQuery: "registry.example/needle",
		Limit:      5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(imageMatch) != 1 || imageMatch[0].Name != "needle" {
		t.Fatalf("image inventory search = %+v, want needle", imageMatch)
	}

	for _, item := range []K8sInventoryItem{
		{ID: "literal-percent", ClusterID: "c1", Kind: "Service", Namespace: "default", Name: "literal%name"},
		{ID: "wildcard-decoy", ClusterID: "c1", Kind: "Service", Namespace: "default", Name: "literalXname"},
	} {
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	literalMatch, err := db.ListK8sInventory(ctx, K8sInventoryFilter{SearchTerms: []string{"%"}, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(literalMatch) != 1 || literalMatch[0].Name != "literal%name" {
		t.Fatalf("LIKE wildcard must retain literal search semantics: %+v", literalMatch)
	}
}
