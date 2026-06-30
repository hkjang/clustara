package analyzer

import (
	"sort"
	"strings"
)

// Build Job Center — analysis core (CLU-OCP-05).
//
// Clustara does not run builds (that needs Kaniko/BuildKit/Tekton execution infra). But the
// *analysis* that makes a build center useful is pure and valuable: classify a build failure from
// its log, and gate a Dockerfile for security issues before it is ever built. Pure.

// BuildFailureCategory values.
const (
	BuildFailGitClone  = "git_clone"
	BuildFailDockerfile = "dockerfile"
	BuildFailDeps      = "dependencies"
	BuildFailRegistry  = "registry_push"
	BuildFailQuota     = "quota"
	BuildFailNetwork   = "network"
	BuildFailTimeout   = "timeout"
	BuildFailUnknown   = "unknown"
)

// BuildFailure is the classified cause of a build failure.
type BuildFailure struct {
	Category    string `json:"category"`
	Title       string `json:"title"`
	Remediation string `json:"remediation"`
	Confidence  string `json:"confidence"`
}

// ClassifyBuildFailure classifies a build log/error into a likely cause.
func ClassifyBuildFailure(log string) BuildFailure {
	e := strings.ToLower(log)
	switch {
	case e == "":
		return BuildFailure{Category: BuildFailUnknown, Title: "원인 미상", Remediation: "빌드 로그를 확인하세요.", Confidence: "low"}
	case containsAny(e, "could not read from remote repository", "repository not found", "authentication failed", "git clone", "fatal: could not"):
		return BuildFailure{Category: BuildFailGitClone, Title: "Git 소스 가져오기 실패", Remediation: "Git URL·브랜치·자격증명(deploy key/token)을 확인하세요.", Confidence: "high"}
	case containsAny(e, "dockerfile", "unknown instruction", "failed to solve", "no such file or directory") && containsAny(e, "dockerfile", "copy ", "add ", "instruction"):
		return BuildFailure{Category: BuildFailDockerfile, Title: "Dockerfile 오류", Remediation: "Dockerfile 명령·COPY 경로·base image 태그를 확인하세요.", Confidence: "high"}
	case containsAny(e, "npm err", "pip install", "could not resolve dependencies", "go: ", "mvn ", "yarn", "package not found", "could not find a version"):
		return BuildFailure{Category: BuildFailDeps, Title: "의존성 설치 실패", Remediation: "의존성 매니페스트(lock 파일)·프록시/미러 레지스트리 접근을 확인하세요.", Confidence: "medium"}
	case containsAny(e, "denied: requested access", "unauthorized: authentication required", "push", "manifest blob unknown", "error pushing"):
		return BuildFailure{Category: BuildFailRegistry, Title: "레지스트리 push 실패", Remediation: "대상 레지스트리 자격증명·repository 권한·경로를 확인하세요.", Confidence: "high"}
	case containsAny(e, "no space left", "quota exceeded", "exceeded quota", "evicted", "oomkilled"):
		return BuildFailure{Category: BuildFailQuota, Title: "리소스/쿼터 부족", Remediation: "빌드 Pod 리소스·디스크·namespace quota를 확인하세요.", Confidence: "high"}
	case containsAny(e, "timeout", "deadline exceeded", "timed out"):
		return BuildFailure{Category: BuildFailTimeout, Title: "타임아웃", Remediation: "빌드 시간 제한·느린 단계(의존성/네트워크)를 확인하세요.", Confidence: "medium"}
	case containsAny(e, "connection refused", "no route to host", "dial tcp", "i/o timeout", "tls handshake"):
		return BuildFailure{Category: BuildFailNetwork, Title: "네트워크 오류", Remediation: "레지스트리/프록시 도달성·방화벽·DNS를 확인하세요.", Confidence: "medium"}
	default:
		return BuildFailure{Category: BuildFailUnknown, Title: "분류되지 않은 빌드 오류", Remediation: "전체 빌드 로그를 확인하세요.", Confidence: "low"}
	}
}

// DockerfileFinding is one security/quality issue in a Dockerfile.
type DockerfileFinding struct {
	Line     int    `json:"line"`
	Severity string `json:"severity"` // high | medium | low
	Rule     string `json:"rule"`
	Message  string `json:"message"`
}

// DockerfileReport is the gate result.
type DockerfileReport struct {
	Findings   []DockerfileFinding `json:"findings"`
	HasUser    bool                `json:"has_user"`    // a non-root USER is set
	RootUser   bool                `json:"root_user"`   // runs as root (no USER or USER root)
	MutableBase bool               `json:"mutable_base"` // FROM ...:latest or no tag
	Pass       bool                `json:"pass"`        // no high-severity findings
}

// AnalyzeDockerfile gates a Dockerfile string for common security issues before build.
func AnalyzeDockerfile(content string) DockerfileReport {
	rep := DockerfileReport{Findings: []DockerfileFinding{}, RootUser: true}
	lines := strings.Split(content, "\n")
	lastUser := ""
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		up := strings.ToUpper(line)
		ln := i + 1
		switch {
		case strings.HasPrefix(up, "FROM "):
			ref := strings.Fields(line)[1]
			if !strings.Contains(ref, ":") || strings.HasSuffix(ref, ":latest") {
				rep.MutableBase = true
				rep.Findings = append(rep.Findings, DockerfileFinding{Line: ln, Severity: "medium", Rule: "mutable-base", Message: "base image 태그 미고정(:latest) — 재현성 위험: " + ref})
			}
		case strings.HasPrefix(up, "USER "):
			lastUser = strings.TrimSpace(line[5:])
			rep.HasUser = true
		case strings.HasPrefix(up, "ADD ") && containsAny(strings.ToLower(line), "http://", "https://"):
			rep.Findings = append(rep.Findings, DockerfileFinding{Line: ln, Severity: "medium", Rule: "add-remote", Message: "ADD로 원격 URL 사용 — COPY/검증된 다운로드 권장"})
		case containsAny(up, "SUDO "):
			rep.Findings = append(rep.Findings, DockerfileFinding{Line: ln, Severity: "low", Rule: "sudo", Message: "이미지 내 sudo 사용"})
		}
		// Secret-looking ENV/ARG values.
		if (strings.HasPrefix(up, "ENV ") || strings.HasPrefix(up, "ARG ")) && containsAny(up, "PASSWORD", "SECRET", "TOKEN", "APIKEY", "API_KEY", "PRIVATE_KEY") {
			rep.Findings = append(rep.Findings, DockerfileFinding{Line: ln, Severity: "high", Rule: "secret-in-image", Message: "ENV/ARG에 비밀값으로 보이는 항목 — 빌드 시 secret mount 사용 권장"})
		}
	}
	if lastUser != "" && lastUser != "root" && lastUser != "0" {
		rep.RootUser = false
	}
	if rep.RootUser {
		rep.Findings = append(rep.Findings, DockerfileFinding{Line: 0, Severity: "high", Rule: "root-user", Message: "비-root USER 미설정 — 컨테이너가 root로 실행됩니다"})
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		rank := map[string]int{"high": 0, "medium": 1, "low": 2}
		return rank[rep.Findings[i].Severity] < rank[rep.Findings[j].Severity]
	})
	rep.Pass = true
	for _, f := range rep.Findings {
		if f.Severity == "high" {
			rep.Pass = false
		}
	}
	return rep
}
