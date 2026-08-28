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

// enabled = 1 is the filter ActiveContextRegistry uses to decide which contexts
// are injected into every prompt, so the flag costs tokens on each request. The
// only writer forced it true on every write — including when the caller sent
// "enabled": false — and there is no DELETE route, so a context could never be
// turned off.
//
// Same root cause as the policy and catalog defects, opposite polarity: those let
// an omitted key disable something; this discarded an explicit disable.
func TestContextCanBeDisabledExplicitly(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	ctx := context.Background()

	if err := db.UpsertContextRegistry(ctx, store.ContextRegistryEntry{
		ID: "ctx_live", Key: "house-style", Name: "House style", Content: "…", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	postJSONTo(t, srv.URL+"/admin/contexts", map[string]any{"id": "ctx_live", "enabled": false})

	entries, err := db.ListContextRegistry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.ID != "ctx_live" {
			continue
		}
		if e.Enabled {
			t.Fatal("an explicit \"enabled\": false was discarded; the context stays injected into " +
				"every prompt and there is no other way to turn it off")
		}
		if e.Key != "house-style" || e.Content != "…" {
			t.Fatalf("fields the caller did not send were cleared: %+v", e)
		}
		return
	}
	t.Fatal("context not found")
}

// A newly registered context is still on by default when enabled is absent.
func TestNewContextDefaultsToEnabled(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	postJSONTo(t, srv.URL+"/admin/contexts", map[string]any{
		"key": "fresh", "name": "Fresh", "content": "body",
	})
	entries, _ := db.ListContextRegistry(context.Background())
	for _, e := range entries {
		if e.Key == "fresh" {
			if !e.Enabled {
				t.Fatal("a new context defaulted to disabled")
			}
			return
		}
	}
	t.Fatal("context not created")
}

func postJSONTo(t *testing.T, url string, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("POST %s = %d for %v", url, resp.StatusCode, body)
	}
}
