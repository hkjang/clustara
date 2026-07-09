package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestGitOpsProviderRegistryDoesNotPersistTokenAndCatalogsOffline(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "gitops-provider.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	createResp := postJSON(t, srv.URL+"/admin/gitops/providers", "", map[string]any{
		"name":       "offline gitlab",
		"scope_type": "git_provider",
		"payload": map[string]any{
			"provider": "gitlab",
			"base_url": "mock://gitlab",
			"token":    "super-secret-token",
		},
	})
	defer createResp.Body.Close()
	body, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create provider = %d body=%s", createResp.StatusCode, body)
	}
	if strings.Contains(string(body), "super-secret-token") {
		t.Fatalf("provider response leaked token: %s", body)
	}
	var created struct {
		Provider store.EnterpriseRecord `json:"provider"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Provider.Payload["token_storage"] != "transient_only" {
		t.Fatalf("unexpected token policy: %+v", created.Provider.Payload)
	}

	listResp, err := http.Get(srv.URL + "/admin/gitops/providers")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	listBody, _ := io.ReadAll(listResp.Body)
	if strings.Contains(string(listBody), "super-secret-token") {
		t.Fatalf("list response leaked token: %s", listBody)
	}

	catalogResp := postJSON(t, srv.URL+"/admin/gitops/providers/catalog", "", map[string]any{
		"provider_id": created.Provider.ID,
		"target":      "branches",
		"token":       "one-shot-token",
	})
	defer catalogResp.Body.Close()
	catalogBody, _ := io.ReadAll(catalogResp.Body)
	if catalogResp.StatusCode != http.StatusOK {
		t.Fatalf("catalog = %d body=%s", catalogResp.StatusCode, catalogBody)
	}
	if strings.Contains(string(catalogBody), "one-shot-token") {
		t.Fatalf("catalog response leaked token: %s", catalogBody)
	}
	if !strings.Contains(string(catalogBody), `"branch":"main"`) {
		t.Fatalf("catalog did not include offline branches: %s", catalogBody)
	}
}
