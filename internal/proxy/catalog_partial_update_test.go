package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"clustara/internal/store"
)

// PUT /admin/k8s/services/catalogs/{id} replaces the whole row, so every key the
// caller omits arrives as a zero value. The handler already defended Code and
// Name by hand — the author knew partial updates happen — but not Enabled, and
// Enabled is a bool.
//
// The consequence is not a lost setting. The DELETE branch of this same endpoint
// is exactly `cat.Enabled = false`, so a PUT that changes only the description
// performs the delete.
func TestCatalogUpdateKeepsFieldsTheCallerOmitted(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	ctx := context.Background()

	original := store.K8sServiceCatalog{
		ID: "cat_pg", Code: "postgres", Name: "PostgreSQL", Category: "database",
		Description: "관계형 데이터베이스", Icon: "pg", DocsURL: "https://example.invalid/pg",
		DeploymentType: "helm", Enabled: true,
	}
	if err := db.UpsertK8sServiceCatalog(ctx, original); err != nil {
		t.Fatal(err)
	}

	putCatalog(t, srv.URL, "cat_pg", map[string]any{"description": "설명만 바꿉니다"})

	got, err := db.GetK8sServiceCatalog(ctx, "cat_pg")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled {
		t.Fatal("a description-only update disabled the catalog: omitting \"enabled\" decoded as false, " +
			"which is exactly what this endpoint's DELETE does")
	}
	if got.Description != "설명만 바꿉니다" {
		t.Fatalf("description = %q: the field that WAS sent must still apply", got.Description)
	}
	if got.Category != "database" || got.Icon != "pg" || got.DocsURL != original.DocsURL || got.DeploymentType != "helm" {
		t.Fatalf("omitted fields were overwritten: %+v", got)
	}
}

// An explicit false must still disable, and DELETE must keep working: the merge
// covers absent keys only.
func TestCatalogUpdateHonoursAnExplicitDisable(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	if err := db.UpsertK8sServiceCatalog(context.Background(), store.K8sServiceCatalog{
		ID: "cat_pg", Code: "postgres", Name: "PostgreSQL", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	putCatalog(t, srv.URL, "cat_pg", map[string]any{"enabled": false})
	got, _ := db.GetK8sServiceCatalog(context.Background(), "cat_pg")
	if got.Enabled {
		t.Fatal("an explicit \"enabled\": false was ignored; the merge must only cover absent keys")
	}
}

// decodeWithPresence must report exactly the keys the body carried — the whole
// mechanism rests on that distinction.
func TestDecodeWithPresenceReportsOnlySentKeys(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "/x", bytes.NewReader([]byte(`{"name":"n","enabled":false}`)))
	if err != nil {
		t.Fatal(err)
	}
	var into store.K8sServiceCatalog
	present, err := decodeWithPresence(req, &into)
	if err != nil {
		t.Fatal(err)
	}
	if !present["name"] || !present["enabled"] {
		t.Fatalf("sent keys not reported: %v", present)
	}
	if present["category"] || present["code"] {
		t.Fatalf("absent keys reported as present: %v", present)
	}
	// An explicit false must be distinguishable from an absent key.
	if into.Enabled {
		t.Fatal("an explicit false did not decode")
	}
}

func putCatalog(t *testing.T, base, id string, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPut, base+"/admin/k8s/services/catalogs/"+id, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("PUT catalog %s = %d for %v", id, resp.StatusCode, body)
	}
}
