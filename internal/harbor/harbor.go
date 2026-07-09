package harbor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

type PolicyFinding struct {
	Rule     string `json:"rule"`
	Decision string `json:"decision"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type LaunchManifestInput struct {
	RegistryURL     string
	Project         string
	Repository      string
	Tag             string
	Digest          string
	Namespace       string
	AppName         string
	ContainerName   string
	ImagePullSecret string
	Replicas        int
	Port            int
}

type SystemInfo struct {
	OK          bool           `json:"ok"`
	StatusCode  int            `json:"status_code"`
	URL         string         `json:"url"`
	Version     string         `json:"version"`
	Raw         map[string]any `json:"raw,omitempty"`
	Error       string         `json:"error,omitempty"`
	CheckedAt   string         `json:"checked_at"`
	OfflineNote string         `json:"offline_note,omitempty"`
}

type CatalogResult struct {
	OK          bool   `json:"ok"`
	Target      string `json:"target"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	Items       any    `json:"items"`
	Error       string `json:"error,omitempty"`
	QueriedAt   string `json:"queried_at"`
	OfflineNote string `json:"offline_note,omitempty"`
}

func NormalizeRegistryURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if !strings.Contains(v, "://") {
		v = "https://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return strings.TrimRight(v, "/")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func RegistryHost(raw string) string {
	v := NormalizeRegistryURL(raw)
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(strings.TrimRight(raw, "/"), "https://"), "http://")
	}
	return u.Host
}

func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func DockerConfigHash(registry, username, token string) string {
	doc := map[string]any{
		"auths": map[string]any{
			registry: map[string]any{
				"username": username,
				"auth":     base64.StdEncoding.EncodeToString([]byte(username + ":" + token)),
			},
		},
	}
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func DefaultSecretName(project string) string {
	base := sanitizeDNS("harbor-" + strings.TrimSpace(project) + "-pull")
	if base == "" || base == "harbor-pull" {
		return "harbor-pull"
	}
	if len(base) > 63 {
		base = strings.Trim(base[:63], "-")
	}
	return base
}

func ImageRef(registryURL, project, repository, tag, digest string) string {
	host := RegistryHost(registryURL)
	repo := strings.Trim(strings.TrimSpace(repository), "/")
	project = strings.Trim(strings.TrimSpace(project), "/")
	if project != "" && repo != "" && !strings.HasPrefix(repo, project+"/") {
		repo = project + "/" + repo
	}
	ref := strings.Trim(host+"/"+repo, "/")
	if d := strings.TrimSpace(digest); d != "" {
		if strings.Contains(d, ":") {
			return ref + "@" + d
		}
		return ref + "@sha256:" + d
	}
	if t := strings.TrimSpace(tag); t != "" {
		return ref + ":" + t
	}
	return ref
}

func RedactedPullSecretManifest(name, namespace, registryURL, username string) string {
	name = firstNonEmpty(strings.TrimSpace(name), DefaultSecretName(""))
	namespace = firstNonEmpty(strings.TrimSpace(namespace), "default")
	registry := RegistryHost(registryURL)
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: clustara
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: REDACTED_BY_CLUSTARA
stringData:
  note: "Generated from Harbor robot account %s for %s. The real token is never returned by Clustara."
`, yamlScalar(name), yamlScalar(namespace), yamlScalar(username), yamlScalar(registry))
}

func LaunchManifests(in LaunchManifestInput) (string, string) {
	if in.Replicas <= 0 {
		in.Replicas = 1
	}
	if in.Port <= 0 {
		in.Port = 8080
	}
	if strings.TrimSpace(in.ContainerName) == "" {
		in.ContainerName = "app"
	}
	if strings.TrimSpace(in.Namespace) == "" {
		in.Namespace = "default"
	}
	if strings.TrimSpace(in.ImagePullSecret) == "" {
		in.ImagePullSecret = DefaultSecretName(in.Project)
	}
	image := ImageRef(in.RegistryURL, in.Project, in.Repository, in.Tag, in.Digest)
	app := sanitizeDNS(firstNonEmpty(in.AppName, path.Base(strings.Trim(in.Repository, "/"))))
	if app == "" {
		app = "harbor-app"
	}
	manifest := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/managed-by: clustara
spec:
  replicas: %d
  selector:
    matchLabels:
      app.kubernetes.io/name: %s
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
    spec:
      imagePullSecrets:
        - name: %s
      containers:
        - name: %s
          image: %s
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: %d
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/managed-by: clustara
spec:
  selector:
    app.kubernetes.io/name: %s
  ports:
    - name: http
      port: %d
      targetPort: %d
`, yamlScalar(app), yamlScalar(in.Namespace), yamlScalar(app), in.Replicas, yamlScalar(app), yamlScalar(app),
		yamlScalar(in.ImagePullSecret), yamlScalar(in.ContainerName), yamlScalar(image), in.Port,
		yamlScalar(app), yamlScalar(in.Namespace), yamlScalar(app), yamlScalar(app), in.Port, in.Port)
	return manifest, image
}

func EvaluateLaunchPolicy(tag, digest, robotStatus, robotExpiresAt string) (string, []PolicyFinding) {
	findings := []PolicyFinding{}
	decision := "allow"
	if strings.TrimSpace(digest) == "" {
		findings = append(findings, PolicyFinding{Rule: "require_image_digest", Decision: "approval_required", Severity: "high", Message: "digest가 없는 tag-only 이미지는 운영 적용 전 추가 승인이 필요합니다."})
		decision = maxDecision(decision, "approval_required")
	}
	if strings.EqualFold(strings.TrimSpace(tag), "latest") {
		findings = append(findings, PolicyFinding{Rule: "disallow_latest_tag", Decision: "deny", Severity: "critical", Message: "latest 태그는 재현 가능한 배포가 아니므로 차단됩니다."})
		decision = maxDecision(decision, "deny")
	}
	if !strings.EqualFold(strings.TrimSpace(robotStatus), "verified") {
		findings = append(findings, PolicyFinding{Rule: "require_verified_robot", Decision: "approval_required", Severity: "medium", Message: "Harbor Robot Account pull 권한 검증이 완료되지 않았습니다."})
		decision = maxDecision(decision, "approval_required")
	}
	if exp := strings.TrimSpace(robotExpiresAt); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			if time.Until(t) < 7*24*time.Hour {
				findings = append(findings, PolicyFinding{Rule: "robot_expiry_window", Decision: "warn", Severity: "medium", Message: "Robot Account 만료가 7일 이내입니다. 배포 전 회전을 권장합니다."})
				decision = maxDecision(decision, "warn")
			}
			if time.Now().After(t) {
				findings = append(findings, PolicyFinding{Rule: "robot_expired", Decision: "deny", Severity: "critical", Message: "Robot Account가 만료되어 image pull 실패 가능성이 큽니다."})
				decision = maxDecision(decision, "deny")
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, PolicyFinding{Rule: "harbor_launch_baseline", Decision: "allow", Severity: "low", Message: "digest, robot account, imagePullSecret 기본 조건을 만족합니다."})
	}
	return decision, findings
}

func CheckSystemInfo(ctx context.Context, client *http.Client, registryURL string) SystemInfo {
	checkedAt := time.Now().UTC().Format(time.RFC3339Nano)
	base := NormalizeRegistryURL(registryURL)
	out := SystemInfo{URL: base, CheckedAt: checkedAt}
	if base == "" {
		out.Error = "registry url is required"
		return out
	}
	if strings.HasPrefix(base, "mock://") || strings.HasPrefix(base, "offline://") {
		out.OK = true
		out.StatusCode = http.StatusOK
		out.Version = "offline"
		out.OfflineNote = "offline/mock registry mode: network check skipped"
		return out
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/api/v2.0/systeminfo", nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	resp, err := client.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	out.StatusCode = resp.StatusCode
	out.OK = resp.StatusCode >= 200 && resp.StatusCode < 300
	var raw map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	out.Raw = raw
	if v, ok := raw["harbor_version"].(string); ok {
		out.Version = v
	} else if v, ok := raw["version"].(string); ok {
		out.Version = v
	}
	if !out.OK {
		out.Error = fmt.Sprintf("systeminfo returned HTTP %d", resp.StatusCode)
	}
	return out
}

func CheckRobotPull(ctx context.Context, client *http.Client, registryURL, robotName, token, project string) SystemInfo {
	base := NormalizeRegistryURL(registryURL)
	out := SystemInfo{URL: base, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if strings.TrimSpace(robotName) == "" || strings.TrimSpace(token) == "" || strings.TrimSpace(project) == "" {
		out.Error = "robot_name, token and project are required"
		return out
	}
	if strings.HasPrefix(base, "mock://") || strings.HasPrefix(base, "offline://") {
		out.OK = true
		out.StatusCode = http.StatusOK
		out.Version = "offline"
		out.OfflineNote = "offline/mock registry mode: robot pull check skipped"
		return out
	}
	if client == nil {
		client = http.DefaultClient
	}
	u := strings.TrimRight(base, "/") + "/api/v2.0/projects/" + url.PathEscape(project) + "/repositories?page_size=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.SetBasicAuth(robotName, token)
	resp, err := client.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	out.StatusCode = resp.StatusCode
	out.OK = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !out.OK {
		out.Error = fmt.Sprintf("robot pull check returned HTTP %d", resp.StatusCode)
	}
	return out
}

func QueryCatalog(ctx context.Context, client *http.Client, registryURL, target, project, repository, robotName, token string) CatalogResult {
	target = strings.ToLower(strings.TrimSpace(target))
	base := NormalizeRegistryURL(registryURL)
	out := CatalogResult{Target: target, URL: base, QueriedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if base == "" {
		out.Error = "registry url is required"
		return out
	}
	if target == "" {
		target = "projects"
		out.Target = target
	}
	if strings.HasPrefix(base, "mock://") || strings.HasPrefix(base, "offline://") {
		out.OK = true
		out.StatusCode = http.StatusOK
		out.OfflineNote = "offline/mock registry mode: catalog query returned sample data"
		switch target {
		case "repositories":
			out.Items = []map[string]any{{"name": strings.Trim(project, "/") + "/api", "artifact_count": 2, "pull_count": 12}}
		case "artifacts":
			out.Items = []map[string]any{{"digest": "sha256:abc", "tags": []string{"1.2.3"}, "size": 12345678}}
		default:
			out.Items = []map[string]any{{"name": "platform", "public": false}, {"name": "library", "public": true}}
		}
		return out
	}
	apiPath := "/api/v2.0/projects"
	switch target {
	case "repositories":
		if strings.TrimSpace(project) == "" {
			out.Error = "project is required for repositories"
			return out
		}
		apiPath = "/api/v2.0/projects/" + url.PathEscape(project) + "/repositories?page_size=100"
	case "artifacts":
		if strings.TrimSpace(project) == "" || strings.TrimSpace(repository) == "" {
			out.Error = "project and repository are required for artifacts"
			return out
		}
		apiPath = "/api/v2.0/projects/" + url.PathEscape(project) + "/repositories/" + url.PathEscape(repository) + "/artifacts?page_size=100&with_tag=true&with_scan_overview=true&with_signature=true"
	case "projects":
		apiPath = "/api/v2.0/projects?page_size=100"
	default:
		out.Error = "target must be projects, repositories or artifacts"
		return out
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+apiPath, nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if strings.TrimSpace(robotName) != "" || strings.TrimSpace(token) != "" {
		req.SetBasicAuth(robotName, token)
	}
	resp, err := client.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	out.StatusCode = resp.StatusCode
	out.OK = resp.StatusCode >= 200 && resp.StatusCode < 300
	var raw any
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	out.Items = raw
	if !out.OK {
		out.Error = fmt.Sprintf("catalog query returned HTTP %d", resp.StatusCode)
	}
	return out
}

var dnsBad = regexp.MustCompile(`[^a-z0-9-]+`)

func sanitizeDNS(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "_", "-")
	v = dnsBad.ReplaceAllString(v, "-")
	v = strings.Trim(v, "-")
	if len(v) > 63 {
		v = strings.Trim(v[:63], "-")
	}
	return v
}

func yamlScalar(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "''"
	}
	if regexp.MustCompile(`^[A-Za-z0-9._:/@-]+$`).MatchString(v) {
		return v
	}
	return strconvQuote(v)
}

func strconvQuote(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func maxDecision(a, b string) string {
	rank := map[string]int{"allow": 0, "warn": 1, "approval_required": 2, "deny": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
