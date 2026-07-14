package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/kube"
)

var podEvidenceAllowedPaths = map[string]bool{
	"/app": true, "/workspace": true, "/opt/app": true, "/srv": true, "/usr/src/app": true,
}

var podEvidenceControlChars = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)

type podEvidenceSearchRequest struct {
	ClusterID            string `json:"cluster_id"`
	Container            string `json:"container"`
	Query                string `json:"query"`
	Path                 string `json:"path"`
	MaxResults           int    `json:"max_results"`
	AcknowledgeSensitive bool   `json:"acknowledge_sensitive"`
	Reason               string `json:"reason"`
}

type podEvidenceMatch struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Preview    string `json:"preview"`
	Category   string `json:"category"`
	Redacted   bool   `json:"redacted"`
	Repository string `json:"repository_hint,omitempty"`
}

func validatePodEvidenceSearch(in *podEvidenceSearchRequest) error {
	in.Query, in.Path, in.Reason = strings.TrimSpace(in.Query), strings.TrimSpace(in.Path), strings.TrimSpace(in.Reason)
	if in.Path == "" {
		in.Path = "/app"
	}
	if !podEvidenceAllowedPaths[in.Path] {
		return fmt.Errorf("path is not allow-listed")
	}
	if len([]rune(in.Query)) < 2 || len([]rune(in.Query)) > 120 || strings.ContainsAny(in.Query, "\r\n") || podEvidenceControlChars.MatchString(in.Query) {
		return fmt.Errorf("query must be 2..120 printable characters on one line")
	}
	if !in.AcknowledgeSensitive {
		return fmt.Errorf("sensitive source search acknowledgement is required")
	}
	if len([]rune(in.Reason)) < 4 {
		return fmt.Errorf("reason must be at least 4 characters")
	}
	if in.MaxResults <= 0 {
		in.MaxResults = 100
	}
	if in.MaxResults > 200 {
		in.MaxResults = 200
	}
	return nil
}

func podEvidenceCommand(path, query string, maxResults int) []string {
	// User values are positional parameters, never interpolated into the fixed shell program.
	// find is constrained to one allow-listed filesystem root and small regular files.
	script := `find "$1" -xdev -type f -size -2048k -exec grep -nH -F -m 5 -- "$2" {} + 2>/dev/null | head -n "$3"`
	return []string{"sh", "-c", script, "clustara-evidence", path, query, strconv.Itoa(maxResults)}
}

func parsePodEvidenceMatches(raw string) ([]podEvidenceMatch, int) {
	out := []podEvidenceMatch{}
	redacted := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		lineNo, err := strconv.Atoi(parts[1])
		if err != nil || lineNo <= 0 {
			continue
		}
		masked := analyzer.MaskSensitive(parts[2])
		wasRedacted := masked != parts[2]
		if wasRedacted {
			redacted++
		}
		out = append(out, podEvidenceMatch{File: parts[0], Line: lineNo, Preview: truncateRunes(strings.TrimSpace(masked), 500), Category: podEvidenceCategory(parts[0]), Redacted: wasRedacted})
	}
	return out, redacted
}

func podEvidenceCategory(file string) string {
	ext := strings.ToLower(filepath.Ext(file))
	base := strings.ToLower(filepath.Base(file))
	switch {
	case strings.Contains(base, "package") || strings.Contains(base, "requirements") || strings.Contains(base, "pom.xml") || strings.Contains(base, "go.mod") || strings.Contains(base, "lock"):
		return "dependency"
	case ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".xml" || ext == ".properties" || ext == ".conf" || ext == ".ini" || ext == ".toml":
		return "config"
	case ext == ".log" || ext == ".out":
		return "runtime"
	default:
		return "source"
	}
}

func podEvidenceInsights(matches []podEvidenceMatch, query string) []map[string]any {
	counts := map[string]int{}
	for _, match := range matches {
		counts[match.Category]++
	}
	out := []map[string]any{}
	if counts["config"] > 0 {
		out = append(out, map[string]any{"type": "configuration", "confidence": "high", "title": "실행 설정에서 검색어 발견", "detail": fmt.Sprintf("설정 파일 %d개 라인에서 발견했습니다. ConfigMap·환경변수·Manifest revision과 값의 출처를 비교하세요.", counts["config"])})
	}
	if counts["source"] > 0 {
		out = append(out, map[string]any{"type": "implementation", "confidence": "medium", "title": "애플리케이션 구현 위치 후보", "detail": fmt.Sprintf("소스/스크립트 %d개 라인이 관련됩니다. 이미지 digest에 대응하는 Git commit과 비교해야 정확한 수정 위치를 확정할 수 있습니다.", counts["source"])})
	}
	if counts["dependency"] > 0 {
		out = append(out, map[string]any{"type": "dependency", "confidence": "medium", "title": "의존성 정의에서 검색어 발견", "detail": "SBOM·이미지 취약점·lock 파일 버전을 함께 확인하세요."})
	}
	if len(matches) == 0 {
		out = append(out, map[string]any{"type": "coverage", "confidence": "high", "title": "허용 경로에서 결과 없음", "detail": "운영 이미지에 소스가 없거나 다른 경로에 있을 수 있습니다. 이미지 SBOM 또는 연결된 Git 저장소 검색을 권장합니다."})
	}
	return out
}

func (s *Server) handleK8sPodEvidenceSearch(w http.ResponseWriter, r *http.Request, namespace, pod string) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in podEvidenceSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if err := validatePodEvidenceSearch(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_evidence_search")
		return
	}
	item, err := s.db.GetK8sInventoryItem(r.Context(), in.ClusterID, "Pod", namespace, pod)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "pod not found", "invalid_request_error", "pod_not_found")
		return
	}
	cluster, err := s.db.GetK8sCluster(r.Context(), in.ClusterID)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found", "invalid_request_error", "cluster_not_found")
		return
	}
	client, err := s.k8sClientForCluster(r.Context(), cluster)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "Kubernetes 연결 준비 실패: "+err.Error(), "invalid_request_error", "k8s_client_failed")
		return
	}
	execClient, ok := client.(kube.PodCommandExecutor)
	if !ok {
		writeOpenAIError(w, http.StatusNotImplemented, "cluster client does not support Pod exec", "invalid_request_error", "exec_unsupported")
		return
	}
	container := firstNonEmpty(strings.TrimSpace(in.Container), defaultContainerName(item))
	command := podEvidenceCommand(in.Path, in.Query, in.MaxResults)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	started := time.Now()
	result, execErr := execClient.PodExec(ctx, namespace, pod, kube.PodExecOptions{Container: container, CommandArg: command, LimitBytes: 128 * 1024})
	if execErr != nil && strings.TrimSpace(result.Stdout) == "" {
		writeOpenAIError(w, http.StatusBadGateway, analyzer.MaskSensitive(execErr.Error()), "server_error", "pod_evidence_search_failed")
		return
	}
	matches, redacted := parsePodEvidenceMatches(result.Stdout)
	s.auditAdmin(r, "k8s.pod.evidence_search", pod, auditJSON(map[string]any{"cluster_id": in.ClusterID, "namespace": namespace, "pod": pod, "container": container, "path": in.Path, "query_hash": shortHash(in.Query), "matches": len(matches), "redacted": redacted, "reason": in.Reason}))
	s.recordPodAccess(r, in.ClusterID, namespace, pod, "evidence_search", "path="+in.Path+" query_hash="+shortHash(in.Query))
	writeJSON(w, http.StatusOK, map[string]any{
		"matches": matches, "count": len(matches), "redacted_count": redacted, "insights": podEvidenceInsights(matches, in.Query),
		"scope":          map[string]any{"path": in.Path, "container": container, "max_results": in.MaxResults, "max_file_bytes": 2 * 1024 * 1024, "timeout_seconds": 20},
		"excluded_paths": []string{"/proc", "/sys", "/dev", "/var/run/secrets", "/run/secrets"}, "duration_ms": time.Since(started).Milliseconds(),
		"note": "검색 결과는 민감정보 마스킹 후 반환됩니다. 전체 소스 원문은 저장하거나 LLM으로 전송하지 않습니다.",
	})
}
