package analyzer

import (
	"fmt"
	"strings"
)

// Report digest: a compact, Mattermost-friendly operations summary built from the report center's
// KPIs, for scheduled auto-delivery (리포트 자동 발송). Pure formatter.

// ReportDigestInput carries the KPIs the report center already computes.
type ReportDigestInput struct {
	ClusterID       string
	GeneratedAt     string
	Workloads       int
	HighFailures    int
	SecurityScore   int
	OpenActions     int
	MonthlyCostKRW  float64
	TopCostIncrease string // e.g. "payments +35%"
	SLOBreaches     int
}

// FormatReportDigest renders the digest as Markdown. Severity-aware headline so a channel reader
// sees at a glance whether attention is needed.
func FormatReportDigest(in ReportDigestInput) string {
	cluster := in.ClusterID
	if cluster == "" {
		cluster = "전체 클러스터"
	}
	mark := "🟢"
	if in.HighFailures > 0 || in.SLOBreaches > 0 || in.OpenActions > 0 {
		mark = "🟡"
	}
	if in.HighFailures > 0 && in.SLOBreaches > 0 {
		mark = "🔴"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s **Clustara 운영 리포트** — %s\n", mark, cluster)
	fmt.Fprintf(&b, "• 워크로드 %d · high/critical 장애 %d · 미해결 액션 %d\n", in.Workloads, in.HighFailures, in.OpenActions)
	fmt.Fprintf(&b, "• 보안 점수 %d/100 · SLO 위반 %d\n", in.SecurityScore, in.SLOBreaches)
	fmt.Fprintf(&b, "• 월 추정 비용 %s KRW", commaIntDigest(in.MonthlyCostKRW))
	if strings.TrimSpace(in.TopCostIncrease) != "" {
		fmt.Fprintf(&b, " · 최대 증가 %s", in.TopCostIncrease)
	}
	if strings.TrimSpace(in.GeneratedAt) != "" {
		fmt.Fprintf(&b, "\n_생성: %s_", in.GeneratedAt)
	}
	return b.String()
}

func commaIntDigest(v float64) string {
	n := int64(v + 0.5)
	if n < 0 {
		n = -n
	}
	s := fmt.Sprintf("%d", n)
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	if v < 0 {
		return "-" + string(out)
	}
	return string(out)
}
