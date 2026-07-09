package gitprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config describes a Git provider connection. Token is intentionally transient:
// callers should pass it for one request and avoid persisting it.
type Config struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	Username string `json:"username,omitempty"`
	Token    string `json:"-"`
}

// Query is a provider-neutral catalog request used by the GitOps UI.
type Query struct {
	Config
	Target     string `json:"target"`
	Search     string `json:"search,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	ProjectKey string `json:"project_key,omitempty"`
	RepoSlug   string `json:"repo_slug,omitempty"`
	Branch     string `json:"branch,omitempty"`
	Path       string `json:"path,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

type PRTemplateInput struct {
	Config
	ProjectID    string `json:"project_id,omitempty"`
	ProjectKey   string `json:"project_key,omitempty"`
	RepoSlug     string `json:"repo_slug,omitempty"`
	SourceBranch string `json:"source_branch,omitempty"`
	TargetBranch string `json:"target_branch,omitempty"`
	Title        string `json:"title,omitempty"`
	Description  string `json:"description,omitempty"`
}

type CatalogResult struct {
	Provider    string           `json:"provider"`
	Target      string           `json:"target"`
	URL         string           `json:"url"`
	RequestPath string           `json:"request_path"`
	OK          bool             `json:"ok"`
	StatusCode  int              `json:"status_code,omitempty"`
	Items       []map[string]any `json:"items"`
	Error       string           `json:"error,omitempty"`
	OfflineNote string           `json:"offline_note,omitempty"`
	TokenPolicy string           `json:"token_policy"`
	QueriedAt   string           `json:"queried_at"`
}

func Test(ctx context.Context, client *http.Client, cfg Config) CatalogResult {
	q := Query{Config: cfg, Target: "projects", Limit: 1}
	return QueryCatalog(ctx, client, q)
}

func QueryCatalog(ctx context.Context, client *http.Client, q Query) CatalogResult {
	q.Provider = normalizeProvider(q.Provider)
	q.BaseURL = strings.TrimRight(strings.TrimSpace(q.BaseURL), "/")
	q.Target = normalizeTarget(q.Target)
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 100
	}
	result := CatalogResult{
		Provider:    q.Provider,
		Target:      q.Target,
		URL:         q.BaseURL,
		OK:          false,
		TokenPolicy: "token_not_persisted",
		QueriedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if q.Provider == "" {
		result.Error = "provider is required"
		return result
	}
	if isOffline(q.BaseURL) {
		result.OK = true
		result.Items = mockItems(q)
		result.OfflineNote = "mock/offline provider catalog was returned without network access"
		result.RequestPath = q.Target
		return result
	}
	if q.BaseURL == "" {
		result.Error = "base_url is required"
		return result
	}
	switch q.Provider {
	case "gitlab":
		return queryGitLab(ctx, httpClient(client), q, result)
	case "bitbucket_server":
		return queryBitbucketServer(ctx, httpClient(client), q, result)
	default:
		result.Error = "unsupported provider: " + q.Provider
		return result
	}
}

func BuildPRTemplate(in PRTemplateInput) CatalogResult {
	in.Provider = normalizeProvider(in.Provider)
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	source := firstNonEmpty(in.SourceBranch, "clustara-change")
	target := firstNonEmpty(in.TargetBranch, "main")
	title := firstNonEmpty(in.Title, "Clustara GitOps change")
	desc := firstNonEmpty(in.Description, "Created from Clustara GitOps Change Manager.")
	res := CatalogResult{
		Provider:    in.Provider,
		Target:      "pull_request_template",
		URL:         in.BaseURL,
		OK:          true,
		TokenPolicy: "template_only_no_remote_write",
		QueriedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	switch in.Provider {
	case "gitlab":
		project := strings.TrimSpace(in.ProjectID)
		res.RequestPath = "/api/v4/projects/" + escapePath(project) + "/merge_requests"
		res.Items = []map[string]any{{
			"method":   "POST",
			"endpoint": in.BaseURL + res.RequestPath,
			"payload": map[string]any{
				"source_branch":        source,
				"target_branch":        target,
				"title":                title,
				"description":          desc,
				"remove_source_branch": false,
			},
			"note": "GitLab Merge Request API payload preview. Clustara does not submit it automatically.",
		}}
	case "bitbucket_server":
		projectKey := strings.ToUpper(strings.TrimSpace(in.ProjectKey))
		repoSlug := strings.TrimSpace(in.RepoSlug)
		res.RequestPath = "/rest/api/1.0/projects/" + escapePath(projectKey) + "/repos/" + escapePath(repoSlug) + "/pull-requests"
		res.Items = []map[string]any{{
			"method":   "POST",
			"endpoint": in.BaseURL + res.RequestPath,
			"payload": map[string]any{
				"title":       title,
				"description": desc,
				"state":       "OPEN",
				"open":        true,
				"closed":      false,
				"fromRef": map[string]any{
					"id":         branchRef(source),
					"repository": bitbucketRepoRef(projectKey, repoSlug),
				},
				"toRef": map[string]any{
					"id":         branchRef(target),
					"repository": bitbucketRepoRef(projectKey, repoSlug),
				},
			},
			"note": "Bitbucket Server pull request payload preview. Clustara does not submit it automatically.",
		}}
	default:
		res.OK = false
		res.Error = "unsupported provider: " + in.Provider
	}
	return res
}

func queryGitLab(ctx context.Context, client *http.Client, q Query, res CatalogResult) CatalogResult {
	var requestPath string
	params := url.Values{}
	params.Set("per_page", fmt.Sprintf("%d", q.Limit))
	switch q.Target {
	case "projects", "repositories":
		requestPath = "/api/v4/projects"
		params.Set("simple", "true")
		if q.Search != "" {
			params.Set("search", q.Search)
		}
	case "branches":
		if q.ProjectID == "" {
			return withError(res, "project_id is required for GitLab branches")
		}
		requestPath = "/api/v4/projects/" + escapePath(q.ProjectID) + "/repository/branches"
		if q.Search != "" {
			params.Set("search", q.Search)
		}
	case "tree":
		if q.ProjectID == "" {
			return withError(res, "project_id is required for GitLab repository tree")
		}
		requestPath = "/api/v4/projects/" + escapePath(q.ProjectID) + "/repository/tree"
		if q.Branch != "" {
			params.Set("ref", q.Branch)
		}
		if q.Path != "" {
			params.Set("path", q.Path)
		}
	case "file":
		if q.ProjectID == "" || q.Path == "" {
			return withError(res, "project_id and path are required for GitLab raw file")
		}
		requestPath = "/api/v4/projects/" + escapePath(q.ProjectID) + "/repository/files/" + escapePath(q.Path) + "/raw"
		params.Set("ref", firstNonEmpty(q.Branch, "main"))
	default:
		return withError(res, "unsupported target: "+q.Target)
	}
	fullURL := q.BaseURL + requestPath
	if enc := params.Encode(); enc != "" {
		fullURL += "?" + enc
	}
	if q.Target == "file" {
		status, body, err := doRequest(ctx, client, http.MethodGet, fullURL, q.Config)
		res.StatusCode = status
		res.RequestPath = requestPath
		if err != nil {
			return withError(res, err.Error())
		}
		res.OK = status >= 200 && status < 300
		res.Items = []map[string]any{{"path": q.Path, "branch": firstNonEmpty(q.Branch, "main"), "size": len(body), "content_preview": preview(body)}}
		if !res.OK {
			res.Error = preview(body)
		}
		return res
	}
	status, body, err := doRequest(ctx, client, http.MethodGet, fullURL, q.Config)
	res.StatusCode = status
	res.RequestPath = requestPath
	if err != nil {
		return withError(res, err.Error())
	}
	raw, err := decodeJSON(body)
	if err != nil {
		return withError(res, err.Error())
	}
	res.OK = status >= 200 && status < 300
	res.Items = normalizeGitLab(q.Target, raw)
	if !res.OK {
		res.Error = preview(body)
	}
	return res
}

func queryBitbucketServer(ctx context.Context, client *http.Client, q Query, res CatalogResult) CatalogResult {
	var requestPath string
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", q.Limit))
	projectKey := strings.ToUpper(strings.TrimSpace(q.ProjectKey))
	repoSlug := strings.TrimSpace(q.RepoSlug)
	switch q.Target {
	case "projects":
		requestPath = "/rest/api/1.0/projects"
	case "repositories":
		if projectKey == "" {
			return withError(res, "project_key is required for Bitbucket repositories")
		}
		requestPath = "/rest/api/1.0/projects/" + escapePath(projectKey) + "/repos"
		if q.Search != "" {
			params.Set("name", q.Search)
		}
	case "branches":
		if projectKey == "" || repoSlug == "" {
			return withError(res, "project_key and repo_slug are required for Bitbucket branches")
		}
		requestPath = "/rest/api/1.0/projects/" + escapePath(projectKey) + "/repos/" + escapePath(repoSlug) + "/branches"
		if q.Search != "" {
			params.Set("filterText", q.Search)
		}
	case "tree":
		if projectKey == "" || repoSlug == "" {
			return withError(res, "project_key and repo_slug are required for Bitbucket browse")
		}
		requestPath = "/rest/api/1.0/projects/" + escapePath(projectKey) + "/repos/" + escapePath(repoSlug) + "/browse"
		if q.Path != "" {
			requestPath += "/" + escapePathSegments(q.Path)
		}
		if q.Branch != "" {
			params.Set("at", branchRef(q.Branch))
		}
	case "file":
		if projectKey == "" || repoSlug == "" || q.Path == "" {
			return withError(res, "project_key, repo_slug and path are required for Bitbucket raw file")
		}
		requestPath = "/rest/api/1.0/projects/" + escapePath(projectKey) + "/repos/" + escapePath(repoSlug) + "/raw/" + escapePathSegments(q.Path)
		if q.Branch != "" {
			params.Set("at", branchRef(q.Branch))
		}
	default:
		return withError(res, "unsupported target: "+q.Target)
	}
	fullURL := q.BaseURL + requestPath
	if enc := params.Encode(); enc != "" {
		fullURL += "?" + enc
	}
	if q.Target == "file" {
		status, body, err := doRequest(ctx, client, http.MethodGet, fullURL, q.Config)
		res.StatusCode = status
		res.RequestPath = requestPath
		if err != nil {
			return withError(res, err.Error())
		}
		res.OK = status >= 200 && status < 300
		res.Items = []map[string]any{{"path": q.Path, "branch": q.Branch, "size": len(body), "content_preview": preview(body)}}
		if !res.OK {
			res.Error = preview(body)
		}
		return res
	}
	status, body, err := doRequest(ctx, client, http.MethodGet, fullURL, q.Config)
	res.StatusCode = status
	res.RequestPath = requestPath
	if err != nil {
		return withError(res, err.Error())
	}
	raw, err := decodeJSON(body)
	if err != nil {
		return withError(res, err.Error())
	}
	res.OK = status >= 200 && status < 300
	res.Items = normalizeBitbucket(q.Target, raw)
	if !res.OK {
		res.Error = preview(body)
	}
	return res
}

func doRequest(ctx context.Context, client *http.Client, method, endpoint string, cfg Config) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/json")
	applyAuth(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(data), nil
}

func applyAuth(req *http.Request, cfg Config) {
	token := strings.TrimSpace(cfg.Token)
	if token == "" {
		return
	}
	switch normalizeProvider(cfg.Provider) {
	case "gitlab":
		req.Header.Set("PRIVATE-TOKEN", token)
	case "bitbucket_server":
		if strings.TrimSpace(cfg.Username) != "" {
			req.SetBasicAuth(strings.TrimSpace(cfg.Username), token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
}

func decodeJSON(body string) (any, error) {
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("empty provider response")
	}
	var raw any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func normalizeGitLab(target string, raw any) []map[string]any {
	arr := asArray(raw)
	out := make([]map[string]any, 0, len(arr))
	for _, v := range arr {
		m := asMap(v)
		switch target {
		case "projects", "repositories":
			out = append(out, map[string]any{
				"id":             stringify(m["id"]),
				"name":           str(m["name"]),
				"path":           str(m["path_with_namespace"]),
				"slug":           str(m["path"]),
				"default_branch": str(m["default_branch"]),
				"repo_url":       firstNonEmpty(str(m["http_url_to_repo"]), str(m["ssh_url_to_repo"]), str(m["web_url"])),
				"web_url":        str(m["web_url"]),
				"type":           "repository",
				"provider":       "gitlab",
			})
		case "branches":
			commit := asMap(m["commit"])
			out = append(out, map[string]any{
				"name":      str(m["name"]),
				"branch":    str(m["name"]),
				"commit":    str(commit["id"]),
				"protected": m["protected"],
				"merged":    m["merged"],
				"web_url":   str(m["web_url"]),
				"type":      "branch",
				"provider":  "gitlab",
			})
		case "tree":
			out = append(out, map[string]any{
				"id":       str(m["id"]),
				"name":     str(m["name"]),
				"path":     str(m["path"]),
				"type":     str(m["type"]),
				"mode":     str(m["mode"]),
				"provider": "gitlab",
			})
		}
	}
	return out
}

func normalizeBitbucket(target string, raw any) []map[string]any {
	container := asMap(raw)
	values := asArray(container["values"])
	if target == "tree" {
		children := asMap(container["children"])
		values = asArray(children["values"])
	}
	out := make([]map[string]any, 0, len(values))
	for _, v := range values {
		m := asMap(v)
		switch target {
		case "projects":
			out = append(out, map[string]any{
				"id":          stringify(m["id"]),
				"project_key": str(m["key"]),
				"name":        str(m["name"]),
				"type":        "project",
				"provider":    "bitbucket_server",
			})
		case "repositories":
			project := asMap(m["project"])
			out = append(out, map[string]any{
				"id":          stringify(m["id"]),
				"name":        str(m["name"]),
				"slug":        str(m["slug"]),
				"repo_slug":   str(m["slug"]),
				"project_key": str(project["key"]),
				"repo_url":    firstCloneLink(m),
				"web_url":     selfLink(m),
				"type":        "repository",
				"provider":    "bitbucket_server",
			})
		case "branches":
			out = append(out, map[string]any{
				"id":       str(m["id"]),
				"name":     firstNonEmpty(str(m["displayId"]), strings.TrimPrefix(str(m["id"]), "refs/heads/")),
				"branch":   firstNonEmpty(str(m["displayId"]), strings.TrimPrefix(str(m["id"]), "refs/heads/")),
				"type":     "branch",
				"provider": "bitbucket_server",
			})
		case "tree":
			p := asMap(m["path"])
			path := firstNonEmpty(str(p["toString"]), str(m["path"]))
			out = append(out, map[string]any{
				"name":     firstNonEmpty(str(p["name"]), path),
				"path":     path,
				"type":     strings.ToLower(firstNonEmpty(str(m["type"]), str(p["type"]))),
				"size":     m["size"],
				"provider": "bitbucket_server",
			})
		}
	}
	return out
}

func mockItems(q Query) []map[string]any {
	provider := normalizeProvider(q.Provider)
	switch normalizeTarget(q.Target) {
	case "projects":
		if provider == "bitbucket_server" {
			return []map[string]any{{"provider": provider, "project_key": "OPS", "name": "Operations Platform", "type": "project"}}
		}
		return []map[string]any{{"provider": provider, "id": "ops/platform", "name": "platform", "path": "ops/platform", "default_branch": "main", "repo_url": "https://gitlab.local/ops/platform.git", "type": "repository"}}
	case "repositories":
		return []map[string]any{{"provider": provider, "id": "ops/platform", "name": "platform", "project_key": "OPS", "repo_slug": "platform", "repo_url": "https://git.local/scm/ops/platform.git", "default_branch": "main", "type": "repository"}}
	case "branches":
		return []map[string]any{{"provider": provider, "name": "main", "branch": "main", "type": "branch"}, {"provider": provider, "name": "release/prod", "branch": "release/prod", "type": "branch"}}
	case "tree":
		return []map[string]any{{"provider": provider, "name": "deploy", "path": "deploy", "type": "tree"}, {"provider": provider, "name": "kustomization.yaml", "path": "deploy/prod/kustomization.yaml", "type": "blob"}}
	case "file":
		return []map[string]any{{"provider": provider, "path": firstNonEmpty(q.Path, "deploy/prod/kustomization.yaml"), "content_preview": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n", "type": "file"}}
	default:
		return []map[string]any{}
	}
}

func firstCloneLink(m map[string]any) string {
	links := asMap(m["links"])
	clones := asArray(links["clone"])
	for _, v := range clones {
		c := asMap(v)
		if strings.EqualFold(str(c["name"]), "http") || strings.EqualFold(str(c["name"]), "https") {
			return str(c["href"])
		}
	}
	if len(clones) > 0 {
		return str(asMap(clones[0])["href"])
	}
	return ""
}

func selfLink(m map[string]any) string {
	links := asMap(m["links"])
	self := asArray(links["self"])
	if len(self) > 0 {
		return str(asMap(self[0])["href"])
	}
	return ""
}

func bitbucketRepoRef(projectKey, repoSlug string) map[string]any {
	return map[string]any{
		"slug": repoSlug,
		"project": map[string]any{
			"key": projectKey,
		},
	}
}

func branchRef(branch string) string {
	branch = strings.TrimSpace(branch)
	if strings.HasPrefix(branch, "refs/") {
		return branch
	}
	return "refs/heads/" + branch
}

func normalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "bitbucket", "bitbucket-server", "bitbucket_server", "stash":
		return "bitbucket_server"
	case "gitlab":
		return "gitlab"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func normalizeTarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "repo", "repos", "repository", "repositories":
		return "repositories"
	case "branch", "branches":
		return "branches"
	case "browse", "tree", "paths":
		return "tree"
	case "raw", "file":
		return "file"
	case "project", "projects":
		return "projects"
	default:
		if strings.TrimSpace(target) == "" {
			return "projects"
		}
		return strings.ToLower(strings.TrimSpace(target))
	}
}

func isOffline(baseURL string) bool {
	l := strings.ToLower(strings.TrimSpace(baseURL))
	return strings.HasPrefix(l, "mock://") || strings.HasPrefix(l, "offline://")
}

func httpClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}

func withError(res CatalogResult, msg string) CatalogResult {
	res.OK = false
	res.Error = msg
	if res.Items == nil {
		res.Items = []map[string]any{}
	}
	return res
}

func escapePath(s string) string {
	return url.PathEscape(strings.Trim(strings.TrimSpace(s), "/"))
}

func escapePathSegments(s string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(s), "/"), "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, url.PathEscape(p))
	}
	return strings.Join(out, "/")
}

func preview(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 4000 {
		return s[:4000]
	}
	return s
}

func asArray(v any) []any {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		return arr
	}
	return nil
}

func asMap(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func stringify(v any) string {
	return str(v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
