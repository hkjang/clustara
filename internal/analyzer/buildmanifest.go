package analyzer

import (
	"fmt"
	"strings"
)

// Build runner manifest generation (CLU-NEXT-04/05 execution, safe path).
//
// Rather than a new cluster-mutating build executor, Clustara generates the standard in-cluster
// build Job manifest (Kaniko by default) from a build definition. The generated Job is then run
// through the EXISTING Stack Apply path (Server-Side Apply + policy + approval) — reusing a verified
// executor instead of writing an unverifiable pod-spawner. Pure string generation.

// BuildJobRequest is the parsed build definition needed to render a build Job.
type BuildJobRequest struct {
	Name         string
	Namespace    string // build namespace; defaults to clustara-builds
	GitURL       string
	Branch       string
	ContextPath  string
	Dockerfile   string // path within the context; defaults to Dockerfile
	OutputImage  string
	Provider     string // kaniko | buildkit
	RegistrySecret string // docker config secret name for registry auth (optional)
}

// BuildJobManifest is the generated runner Job + requirements.
type BuildJobManifest struct {
	Provider string   `json:"provider"`
	Manifest string   `json:"manifest"`
	JobName  string   `json:"job_name"`
	Notes    []string `json:"notes"`
}

// GenerateBuildJobManifest renders an in-cluster build Job (Kaniko/BuildKit) for a definition.
func GenerateBuildJobManifest(req BuildJobRequest) BuildJobManifest {
	name := sanitizeName(orDefault(req.Name, "build"))
	ns := orDefault(req.Namespace, "clustara-builds")
	branch := orDefault(req.Branch, "main")
	dockerfile := orDefault(req.Dockerfile, "Dockerfile")
	provider := orDefault(req.Provider, "kaniko")
	jobName := "build-" + name
	out := BuildJobManifest{Provider: provider, JobName: jobName, Notes: []string{}}

	if req.OutputImage == "" {
		out.Notes = append(out.Notes, "output_image가 비어 있습니다 — 대상 이미지를 지정하세요.")
	}
	if req.GitURL == "" {
		out.Notes = append(out.Notes, "git_url이 비어 있습니다 — 소스 저장소를 지정하세요.")
	}

	var creds, credsVol, credsMount string
	if req.RegistrySecret != "" {
		creds = "      volumes:\n        - name: docker-config\n          secret:\n            secretName: " + req.RegistrySecret + "\n            items: [{key: .dockerconfigjson, path: config.json}]\n"
		credsVol = "          volumeMounts:\n            - name: docker-config\n              mountPath: /kaniko/.docker\n"
		_ = credsMount
	} else {
		out.Notes = append(out.Notes, "registry_secret 미지정 — push 인증을 위해 kubernetes.io/dockerconfigjson Secret이 필요합니다(Pull Secret 생성기 참고).")
	}

	switch provider {
	case "buildkit":
		out.Manifest = fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    clustara.io/build: "%s"
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: buildkit
          image: moby/buildkit:master-rootless
          command: [buildctl-daemonless.sh]
          args:
            - build
            - --frontend=dockerfile.v0
            - --opt
            - context=%s#%s
            - --opt
            - filename=%s
            - --output
            - type=image,name=%s,push=true
`, jobName, ns, name, gitContext(req.GitURL), branch, dockerfile, req.OutputImage)
		out.Notes = append(out.Notes, "BuildKit rootless는 노드/보안 설정(seccomp·user namespaces)이 필요할 수 있습니다.")
	default: // kaniko
		sub := ""
		if req.ContextPath != "" {
			sub = "\n            - \"--context-sub-path=" + req.ContextPath + "\""
		}
		out.Manifest = fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    clustara.io/build: "%s"
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: kaniko
          image: gcr.io/kaniko-project/executor:latest
          args:
            - "--context=git://%s#refs/heads/%s"%s
            - "--dockerfile=%s"
            - "--destination=%s"
%s%s`, jobName, ns, name, gitContext(req.GitURL), branch, sub, dockerfile, req.OutputImage, credsVol, creds)
	}
	out.Notes = append(out.Notes, "생성된 Job은 앱 배포(Stack)로 검증→승인→적용하여 실행하세요. Clustara는 직접 기동하지 않습니다.")
	return out
}

// gitContext strips a scheme prefix so it can be embedded in a git:// context arg.
func gitContext(url string) string {
	u := strings.TrimSpace(url)
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "git://")
	return u
}

// sanitizeName lowercases + replaces non-DNS chars for a Job name.
func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "build"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
