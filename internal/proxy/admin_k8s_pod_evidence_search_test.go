package proxy

import (
	"strings"
	"testing"
)

func TestValidatePodEvidenceSearchEnforcesSafeScope(t *testing.T) {
	valid := podEvidenceSearchRequest{Query: "connectionTimeout", Path: "/app", Reason: "DB 장애 분석", AcknowledgeSensitive: true}
	if err := validatePodEvidenceSearch(&valid); err != nil {
		t.Fatalf("valid search rejected: %v", err)
	}
	for _, tc := range []podEvidenceSearchRequest{
		{Query: "token", Path: "/var/run/secrets", Reason: "보안 검색", AcknowledgeSensitive: true},
		{Query: "x\ncat /etc/passwd", Path: "/app", Reason: "장애 분석", AcknowledgeSensitive: true},
		{Query: "token", Path: "/app", Reason: "장애 분석", AcknowledgeSensitive: false},
	} {
		if err := validatePodEvidenceSearch(&tc); err == nil {
			t.Fatalf("unsafe search should be rejected: %+v", tc)
		}
	}
}

func TestPodEvidenceCommandKeepsUserInputAsPositionalArgument(t *testing.T) {
	query := `timeout'; cat /etc/passwd; #`
	args := podEvidenceCommand("/app", query, 50)
	if len(args) != 7 || args[0] != "sh" || args[1] != "-c" || args[4] != "/app" || args[5] != query || args[6] != "50" {
		t.Fatalf("structured command arguments changed: %#v", args)
	}
	if strings.Contains(args[2], query) {
		t.Fatal("user query must never be interpolated into shell program")
	}
}

func TestParsePodEvidenceMatchesMasksSecretsAndClassifies(t *testing.T) {
	matches, redacted := parsePodEvidenceMatches("/app/application.yaml:12:password=supersecret123\n/app/main.go:44:connectionTimeout := 30\n")
	if len(matches) != 2 || matches[0].Category != "config" || matches[1].Category != "source" {
		t.Fatalf("unexpected matches: %+v", matches)
	}
	if redacted != 1 || strings.Contains(matches[0].Preview, "supersecret123") {
		t.Fatalf("secret was not masked: redacted=%d match=%+v", redacted, matches[0])
	}
	if len(podEvidenceInsights(matches, "timeout")) < 2 {
		t.Fatal("config and source evidence should produce structured insights")
	}
}

func TestPodEvidenceSearchUXAndOpenAPIContract(t *testing.T) {
	for _, marker := range []string{"Pod Evidence Search", "podev-query", "evidence-search", "전체 원문을 저장하거나 LLM에 전송하지 않습니다"} {
		if !containsAdminHTML(marker) {
			t.Fatalf("Pod evidence search contract missing %q", marker)
		}
	}
}
