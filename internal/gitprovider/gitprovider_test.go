package gitprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitLabBranchesUsePrivateTokenAndEncodedProjectPath(t *testing.T) {
	var requestURI, token string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.RequestURI
		token = r.Header.Get("PRIVATE-TOKEN")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"main","commit":{"id":"abc123"},"protected":true}]`))
	}))
	defer srv.Close()

	res := QueryCatalog(context.Background(), srv.Client(), Query{
		Config: Config{Provider: "gitlab", BaseURL: srv.URL, Token: "gl-secret"},
		Target: "branches", ProjectID: "platform/payments", Search: "main",
	})
	if !res.OK {
		t.Fatalf("catalog failed: %+v", res)
	}
	if token != "gl-secret" {
		t.Fatalf("PRIVATE-TOKEN header = %q", token)
	}
	if !strings.Contains(requestURI, "platform%2Fpayments") {
		t.Fatalf("project path was not URL encoded in request URI: %s", requestURI)
	}
	if len(res.Items) != 1 || res.Items[0]["branch"] != "main" {
		t.Fatalf("unexpected branch items: %+v", res.Items)
	}
}

func TestBitbucketServerPRTemplate(t *testing.T) {
	res := BuildPRTemplate(PRTemplateInput{
		Config:       Config{Provider: "bitbucket_server", BaseURL: "https://bitbucket.local"},
		ProjectKey:   "OPS",
		RepoSlug:     "platform",
		SourceBranch: "clustara/hotfix",
		TargetBranch: "main",
		Title:        "Sync hotfix",
	})
	if !res.OK {
		t.Fatalf("template failed: %+v", res)
	}
	if !strings.Contains(res.RequestPath, "/rest/api/1.0/projects/OPS/repos/platform/pull-requests") {
		t.Fatalf("unexpected request path: %s", res.RequestPath)
	}
	payload, ok := res.Items[0]["payload"].(map[string]any)
	if !ok {
		t.Fatalf("missing payload: %+v", res.Items)
	}
	fromRef := payload["fromRef"].(map[string]any)
	if fromRef["id"] != "refs/heads/clustara/hotfix" {
		t.Fatalf("unexpected fromRef: %+v", fromRef)
	}
}

func TestMockCatalogWorksOffline(t *testing.T) {
	res := QueryCatalog(context.Background(), nil, Query{Config: Config{Provider: "gitlab", BaseURL: "mock://gitlab"}, Target: "tree"})
	if !res.OK || len(res.Items) == 0 || res.OfflineNote == "" {
		t.Fatalf("mock catalog failed: %+v", res)
	}
}
