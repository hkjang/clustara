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

func TestExternalIntegrationCredentialsAreEncryptedAndReusable(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "external-integrations.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	createResp := postJSON(t, srv.URL+"/admin/external-integrations/credentials", "", map[string]any{
		"name":      "offline gitlab credential",
		"provider":  "gitlab",
		"base_url":  "mock://gitlab",
		"username":  "svc-clustara",
		"secret":    "super-secret-token",
		"auth_type": "token",
		"metadata": map[string]any{
			"default_branch": "main",
		},
	})
	defer createResp.Body.Close()
	body, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create credential = %d body=%s", createResp.StatusCode, body)
	}
	assertNoSecretLeak(t, body, "super-secret-token")
	var created struct {
		Credential store.EnterpriseRecord `json:"credential"`
		Data       struct {
			Credential store.EnterpriseRecord `json:"credential"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	cred := created.Credential
	if cred.ID == "" {
		cred = created.Data.Credential
	}
	if cred.ID == "" {
		t.Fatalf("credential id missing: %s", body)
	}
	if got := cred.Payload["secret_configured"]; got != true {
		t.Fatalf("secret_configured = %v, want true", got)
	}
	if _, leaked := cred.Payload["encrypted_secret"]; leaked {
		t.Fatalf("encrypted secret leaked in response payload: %+v", cred.Payload)
	}

	listResp, err := http.Get(srv.URL + "/admin/external-integrations/credentials")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	listBody, _ := io.ReadAll(listResp.Body)
	assertNoSecretLeak(t, listBody, "super-secret-token")
	if !strings.Contains(string(listBody), `"secret_configured":true`) {
		t.Fatalf("list did not expose safe secret_configured marker: %s", listBody)
	}

	catalogResp := postJSON(t, srv.URL+"/admin/gitops/providers/catalog", "", map[string]any{
		"credential_id": cred.ID,
		"target":        "branches",
	})
	defer catalogResp.Body.Close()
	catalogBody, _ := io.ReadAll(catalogResp.Body)
	if catalogResp.StatusCode != http.StatusOK {
		t.Fatalf("gitops catalog via credential = %d body=%s", catalogResp.StatusCode, catalogBody)
	}
	assertNoSecretLeak(t, catalogBody, "super-secret-token")
	if !strings.Contains(string(catalogBody), `"branch":"main"`) {
		t.Fatalf("gitops catalog did not use saved credential: %s", catalogBody)
	}

	testResp := postJSON(t, srv.URL+"/admin/external-integrations/credentials/"+cred.ID+"/test", "", map[string]any{})
	defer testResp.Body.Close()
	testBody, _ := io.ReadAll(testResp.Body)
	if testResp.StatusCode != http.StatusOK {
		t.Fatalf("credential test = %d body=%s", testResp.StatusCode, testBody)
	}
	assertNoSecretLeak(t, testBody, "super-secret-token")
}

func TestHarborCatalogCanUseExternalCredential(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "harbor-credential.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()

	createResp := postJSON(t, srv.URL+"/admin/external-integrations/credentials", "", map[string]any{
		"name":      "harbor robot credential",
		"provider":  "harbor_robot",
		"base_url":  "mock://harbor",
		"username":  "robot$platform+clustara",
		"secret":    "harbor-secret-token",
		"auth_type": "password",
		"metadata": map[string]any{
			"default_project": "platform",
		},
	})
	defer createResp.Body.Close()
	body, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create harbor credential = %d body=%s", createResp.StatusCode, body)
	}
	assertNoSecretLeak(t, body, "harbor-secret-token")
	var created struct {
		Credential store.EnterpriseRecord `json:"credential"`
		Data       struct {
			Credential store.EnterpriseRecord `json:"credential"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	cred := created.Credential
	if cred.ID == "" {
		cred = created.Data.Credential
	}

	catalogResp := postJSON(t, srv.URL+"/admin/harbor/catalog/query", "", map[string]any{
		"registry_url":  "mock://harbor",
		"target":        "projects",
		"credential_id": cred.ID,
		"project_name":  "platform",
		"robot_name":    "",
		"token":         "",
	})
	defer catalogResp.Body.Close()
	catalogBody, _ := io.ReadAll(catalogResp.Body)
	if catalogResp.StatusCode != http.StatusOK {
		t.Fatalf("harbor catalog via credential = %d body=%s", catalogResp.StatusCode, catalogBody)
	}
	assertNoSecretLeak(t, catalogBody, "harbor-secret-token")
	if !strings.Contains(string(catalogBody), `"platform"`) {
		t.Fatalf("harbor catalog did not return mock projects: %s", catalogBody)
	}
}

func assertNoSecretLeak(t *testing.T, body []byte, secret string) {
	t.Helper()
	text := string(body)
	for _, needle := range []string{secret, "encrypted_secret", "secret_hash"} {
		if strings.Contains(text, needle) {
			t.Fatalf("response leaked %q: %s", needle, body)
		}
	}
}
