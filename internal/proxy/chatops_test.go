package proxy

import (
	"strings"
	"testing"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func TestParseSlashText(t *testing.T) {
	cases := []struct {
		in   string
		sub  string
		args []string
	}{
		{"", "help", nil},
		{"   ", "help", nil},
		{"incidents", "incidents", nil},
		{"RCA payments", "rca", []string{"payments"}},
		{"  slo 99.5 7 ", "slo", []string{"99.5", "7"}},
	}
	for _, c := range cases {
		sub, args := parseSlashText(c.in)
		if sub != c.sub || len(args) != len(c.args) {
			t.Fatalf("parseSlashText(%q) = (%q,%v), want (%q,%v)", c.in, sub, args, c.sub, c.args)
		}
		for i := range args {
			if args[i] != c.args[i] {
				t.Fatalf("parseSlashText(%q) arg %d = %q, want %q", c.in, i, args[i], c.args[i])
			}
		}
	}
}

func TestFormatIncidents(t *testing.T) {
	if got := formatIncidents(nil); !strings.Contains(got, "없습니다") {
		t.Fatalf("empty incidents: %q", got)
	}
	incs := []store.K8sIncident{
		{Namespace: "pay", Name: "api", Condition: "CrashLoopBackOff", Severity: "critical", Title: "재시작 폭주"},
	}
	got := formatIncidents(incs)
	if !strings.Contains(got, "CRITICAL") || !strings.Contains(got, "pay/api") || !strings.Contains(got, "CrashLoopBackOff") {
		t.Fatalf("incident format missing fields: %q", got)
	}
}

func TestFormatRCAFiltersSeverityAndNamespace(t *testing.T) {
	findings := []analyzer.RCAFinding{
		{Namespace: "a", ResourceName: "x", Condition: "OOMKilled", Severity: "high", Cause: "메모리 부족"},
		{Namespace: "b", ResourceName: "y", Condition: "Info", Severity: "low", Cause: "무시"},
		{Namespace: "a", ResourceName: "z", Condition: "ImagePullBackOff", Severity: "critical", Cause: "이미지 없음"},
	}
	all := formatRCA(findings, "")
	if strings.Contains(all, "무시") { // low severity dropped
		t.Fatalf("low severity should be filtered: %q", all)
	}
	if !strings.Contains(all, "OOMKilled") || !strings.Contains(all, "ImagePullBackOff") {
		t.Fatalf("high/critical should be kept: %q", all)
	}
	nsB := formatRCA(findings, "b")
	if !strings.Contains(nsB, "없습니다") { // b only had a low finding
		t.Fatalf("namespace filter b should yield none: %q", nsB)
	}
}

func TestCommaIntChatOps(t *testing.T) {
	if commaInt(1234567) != "1,234,567" {
		t.Fatalf("commaInt = %q", commaInt(1234567))
	}
}
