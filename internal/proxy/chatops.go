package proxy

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// ChatOps: receive Mattermost slash commands (read-only operational queries) and reply in the
// Mattermost slash-command response format. Mattermost POSTs application/x-www-form-urlencoded
// with token/command/text/... and expects {response_type, text} back. Verification is a shared
// token (configured under Mattermost settings); no admin auth — this is an inbound integration.

// chatOpsHelp is the usage text shown for `help` / unknown subcommands.
func chatOpsHelp() string {
	return strings.Join([]string{
		"**Clustara ChatOps** — 사용법:",
		"`/clustara incidents` — 미해결 인시던트 목록",
		"`/clustara rca [namespace]` — high/critical 장애 분석 후보",
		"`/clustara slo [target] [days]` — 서비스별 SLO·에러버짓",
		"`/clustara cost` — 월 추정 비용 TOP namespace",
		"`/clustara help` — 이 도움말",
		"_읽기 전용입니다 — 조치는 Clustara 콘솔에서 승인하세요._",
	}, "\n")
}

// parseSlashText splits the slash-command text into a lowercased subcommand and the remaining args.
func parseSlashText(text string) (sub string, args []string) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return "help", nil
	}
	return strings.ToLower(fields[0]), fields[1:]
}

// handleMattermostCommand is the inbound slash-command endpoint.
// POST /integrations/mattermost/command  (application/x-www-form-urlencoded)
func (s *Server) handleMattermostCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid form body", "invalid_request_error", "invalid_body")
		return
	}
	cfg := s.mattermostConfig(r.Context())
	// Verification: a slash token must be configured and match (constant-time).
	got := r.PostForm.Get("token")
	if cfg.slashToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(cfg.slashToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"response_type": "ephemeral",
			"text":          "ChatOps 토큰이 일치하지 않거나 미설정입니다. Clustara 설정에서 slash token을 구성하세요.",
		})
		return
	}

	sub, args := parseSlashText(r.PostForm.Get("text"))
	clusterID := r.PostForm.Get("cluster_id") // optional, rarely sent by Mattermost
	text, ephemeral := s.chatOpsReply(r, sub, args, clusterID)

	respType := "in_channel"
	if ephemeral {
		respType = "ephemeral"
	}
	s.auditAdmin(r, "k8s.chatops.command", "", auditJSON(map[string]any{
		"sub": sub, "user": r.PostForm.Get("user_name"), "channel": r.PostForm.Get("channel_name"),
	}))
	writeJSON(w, http.StatusOK, map[string]any{"response_type": respType, "text": text})
}

// chatOpsReply runs a read-only query for the subcommand and returns (text, ephemeral).
// Errors and help are ephemeral; data answers post in-channel.
func (s *Server) chatOpsReply(r *http.Request, sub string, args []string, clusterID string) (string, bool) {
	ctx := r.Context()
	switch sub {
	case "incidents", "incident":
		incs, err := s.db.ListK8sIncidents(ctx, store.K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 20})
		if err != nil {
			return "인시던트 조회 실패: " + err.Error(), true
		}
		return formatIncidents(incs), false
	case "rca":
		ns := ""
		if len(args) > 0 {
			ns = args[0]
		}
		items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Limit: 4000})
		if err != nil {
			return "RCA 조회 실패: " + err.Error(), true
		}
		events, _ := s.db.ListK8sEvents(ctx, clusterID, 1000)
		findings := analyzer.AnalyzeRCA(items, events)
		return formatRCA(findings, ns), false
	case "slo":
		target, days := 99.9, 30
		if len(args) > 0 {
			target = floatParam(args[0], 99.9)
		}
		if len(args) > 1 {
			days = intParam(args[1], 30)
		}
		incs, err := s.db.ListK8sIncidents(ctx, store.K8sIncidentFilter{ClusterID: clusterID, Limit: 1000})
		if err != nil {
			return "SLO 조회 실패: " + err.Error(), true
		}
		lines := analyzer.ComputeSLO(incs, time.Now().UTC(), time.Duration(days)*24*time.Hour, target)
		return formatSLO(lines, target, days), false
	case "cost":
		items, prices, nsTeam, nsCostCenter, clusterGroup, err := s.costContext(ctx, clusterID)
		if err != nil {
			return "비용 조회 실패: " + err.Error(), true
		}
		rep := analyzer.EstimateCost(items, prices, nsTeam, nsCostCenter, clusterGroup)
		return formatCost(rep), false
	case "help", "":
		return chatOpsHelp(), true
	default:
		return "알 수 없는 명령: `" + sub + "`\n\n" + chatOpsHelp(), true
	}
}

func formatIncidents(incs []store.K8sIncident) string {
	if len(incs) == 0 {
		return "✅ 미해결 인시던트가 없습니다."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**미해결 인시던트 %d건**\n", len(incs))
	for i, inc := range incs {
		if i >= 10 {
			fmt.Fprintf(&b, "_…외 %d건_\n", len(incs)-10)
			break
		}
		sev := strings.ToUpper(firstNonEmpty(inc.Severity, "?"))
		fmt.Fprintf(&b, "• [%s] %s/%s — %s (%s)\n", sev, firstNonEmpty(inc.Namespace, "-"), inc.Name, inc.Condition, inc.Title)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatRCA(findings []analyzer.RCAFinding, ns string) string {
	filtered := findings[:0:0]
	for _, f := range findings {
		if f.Severity != "high" && f.Severity != "critical" {
			continue
		}
		if ns != "" && f.Namespace != ns {
			continue
		}
		filtered = append(filtered, f)
	}
	if len(filtered) == 0 {
		scope := ""
		if ns != "" {
			scope = " (namespace=" + ns + ")"
		}
		return "✅ high/critical 장애 후보가 없습니다" + scope + "."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**장애 분석 후보 %d건**\n", len(filtered))
	for i, f := range filtered {
		if i >= 10 {
			fmt.Fprintf(&b, "_…외 %d건_\n", len(filtered)-10)
			break
		}
		fmt.Fprintf(&b, "• [%s] %s/%s %s — %s\n", strings.ToUpper(f.Severity), firstNonEmpty(f.Namespace, "-"), f.ResourceName, f.Condition, f.Cause)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatSLO(lines []analyzer.SLOLine, target float64, days int) string {
	if len(lines) == 0 {
		return fmt.Sprintf("✅ 최근 %d일 인시던트가 없습니다 — 모든 서비스가 목표(%.3g%%)를 충족합니다.", days, target)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**SLO (목표 %.3g%%, 최근 %d일)**\n", target, days)
	for i, l := range lines {
		if i >= 10 {
			fmt.Fprintf(&b, "_…외 %d건_\n", len(lines)-10)
			break
		}
		mark := "✅"
		if l.Breached {
			mark = "🔴"
		}
		fmt.Fprintf(&b, "%s %s — 가용성 %.2f%% · 버짓잔여 %.1f%% · MTTR %.0f분 · 인시던트 %d\n",
			mark, l.Namespace, l.AvailabilityPct, l.ErrorBudgetRemainingPct, l.MTTRMinutes, l.Incidents)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatCost(rep analyzer.CostReport) string {
	if rep.TotalMonthlyKRW <= 0 || len(rep.ByNamespace) == 0 {
		return "비용 데이터가 없습니다 — 인벤토리에 request가 설정된 워크로드가 필요합니다."
	}
	lines := append([]analyzer.CostLine(nil), rep.ByNamespace...)
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].MonthlyKRW > lines[j].MonthlyKRW })
	var b strings.Builder
	fmt.Fprintf(&b, "**월 추정 비용 %s KRW** (TOP namespace)\n", commaInt(rep.TotalMonthlyKRW))
	for i, l := range lines {
		if i >= 8 {
			break
		}
		fmt.Fprintf(&b, "• %s — %s KRW (%.1f vCPU · %.1f GB)\n", l.Key, commaInt(l.MonthlyKRW), l.CPUCores, l.MemGB)
	}
	return strings.TrimRight(b.String(), "\n")
}
