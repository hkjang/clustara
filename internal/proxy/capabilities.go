package proxy

import (
	"net/http"
	"strings"
)

// Capability is a curated catalog entry describing one major gateway feature and everything
// it touches — APIs, UI tabs, scopes, runtime setting keys, DB tables, background workers, and
// docs. It is the "map" that lets a new operator/developer understand where a feature lives.
//
// This is intentionally a code-defined registry (not a DB table): it is static system metadata
// that ships with the binary and is kept honest by living next to the code it describes.
type Capability struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Group       string   `json:"group"`
	APIs        []string `json:"apis"`
	UITabs      []string `json:"ui_tabs"`
	Scopes      []string `json:"scopes"`
	SettingKeys []string `json:"setting_keys"`
	Tables      []string `json:"tables"`
	Workers     []string `json:"workers"`
	Docs        []string `json:"docs"`
}

// capabilityRegistry is the ordered catalog of gateway capabilities.
var capabilityRegistry = []Capability{
	{
		Key: "chat_proxy", Name: "Chat 프록시", Group: "core",
		Description: "OpenAI 호환 채팅/모델/임베딩 중계 + 사용량·토큰·비용 추적.",
		APIs:        []string{"POST /v1/chat/completions", "GET /v1/models", "POST /v1/embeddings"},
		UITabs:      []string{"requests", "llm", "chat-test"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"request_logs", "token_usage", "prompt_logs", "response_logs"},
		Workers:     []string{"async_logger"},
	},
	{
		Key: "routing", Name: "라우팅", Group: "core",
		Description: "vibe/auto 등 가상 모델의 복잡도·위험·헬스 기반 업스트림 선택 + 학습 루프.",
		APIs:        []string{"GET /admin/routing/decisions", "GET /admin/routing/health"},
		UITabs:      []string{"routing"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"routing_decisions"},
	},
	{
		Key: "mcp_gateway", Name: "MCP Gateway", Group: "core",
		Description: "단일 /mcp로 여러 MCP 업스트림 통합 + vibe/grounded·research·all-mcp agentic discovery.",
		APIs:        []string{"POST /mcp", "GET /admin/mcp/agentic-runs"},
		UITabs:      []string{"mcp"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"tool_invocations", "mcp_route_decisions", "domain_routing_decisions", "domain_routing_signals"},
	},
	{
		Key: "text2sql", Name: "Text2SQL", Group: "data",
		Description: "vibe/text2sql-* 가상 모델: 자연어→SQL 생성·검증·실행·마스킹·골든·위험 큐.",
		APIs:        []string{"POST /v1/chat/completions (vibe/text2sql-*)", "GET /admin/text2sql/*"},
		UITabs:      []string{"text2sql"},
		Scopes:      []string{"admin:read"},
		SettingKeys: []string{"text2sql.*"},
		Tables:      []string{"text2sql_query_logs", "text2sql_saved_reports", "text2sql_permissions", "text2sql_spans"},
		Workers:     []string{"text2sql_report_scheduler"},
	},
	{
		Key: "governance", Name: "거버넌스", Group: "security",
		Description: "정책 결정, 시크릿 탐지, 승인 큐, 이상 탐지 — 요청 단위 차단/경고/승인.",
		APIs:        []string{"GET /admin/governance/*", "POST /admin/policies/*"},
		UITabs:      []string{"safety", "security"},
		Scopes:      []string{"security:read"},
		Tables:      []string{"policy_decisions", "secret_events", "approvals", "anomaly_events"},
	},
	{
		Key: "k8s_security_vulnerability", Name: "K8s 취약점·SBOM·런타임 보안", Group: "security",
		Description: "Trivy/Grype 스캔 결과 import, 이미지 digest 기준 CVE 원장, SBOM 분석, Admission 이미지 정책 평가, Falco 런타임 이벤트, kube-bench CIS 결과와 만료형 예외 승인.",
		APIs: []string{
			"GET /admin/k8s/security/vuln/summary", "GET /admin/k8s/security/vuln/images", "GET /admin/k8s/security/vuln/workloads",
			"GET/POST /admin/k8s/security/scans", "POST /admin/k8s/security/scans/import", "GET/POST /admin/k8s/security/sboms",
			"GET/POST /admin/k8s/security/exceptions", "POST /admin/k8s/security/admission/evaluate", "POST /admin/k8s/security/admission/review",
			"GET/POST /admin/k8s/security/runtime/events", "GET/POST /admin/k8s/security/benchmarks/job-manifest", "GET/POST /admin/k8s/security/benchmarks/runs",
		},
		UITabs: []string{
			"k8s-security", "k8s-security-vulnerabilities", "k8s-security-sbom", "k8s-security-cluster-scan",
			"k8s-security-admission", "k8s-security-runtime", "k8s-security-benchmark", "k8s-security-exceptions", "k8s-policy",
		},
		Scopes: []string{"security:read", "security:scan", "security:policy", "security:exception", "security:runtime"},
		Tables: []string{
			"k8s_security_scan_runs", "k8s_image_vulnerabilities", "k8s_sboms", "k8s_sbom_packages",
			"k8s_security_exceptions", "k8s_admission_decisions", "k8s_runtime_events", "k8s_benchmark_runs", "k8s_benchmark_results",
		},
	},
	{
		Key: "harbor_app_launch", Name: "Harbor 앱 런칭", Group: "ops",
		Description: "Harbor Registry, Project, Robot Account, namespace 매핑, imagePullSecret preview, digest 기반 Deployment/Service manifest preview, 런칭 요청 원장, Manifest Change 초안 전환을 제공하는 안전한 애플리케이션 런칭 체계.",
		APIs: []string{
			"GET/POST /admin/harbor/registries", "GET/POST/DELETE /admin/harbor/registries/{id}", "POST /admin/harbor/registries/{id}/test",
			"GET/POST /admin/harbor/robots", "GET/POST/DELETE /admin/harbor/robots/{id}", "POST /admin/harbor/robots/verify",
			"GET/POST /admin/harbor/mappings", "GET/POST/DELETE /admin/harbor/mappings/{id}",
			"POST /admin/harbor/catalog/query", "POST /admin/harbor/pull-secret/preview", "POST /admin/harbor/launches/preview", "GET/POST /admin/harbor/launches", "POST /admin/harbor/launches/{id}/manifest-change",
		},
		UITabs: []string{"harbor", "harbor-robots", "app-launcher", "app-launch-history", "k8s-security-image-launch"},
		Scopes: []string{"admin:read", "admin:write", "security:read"},
		Tables: []string{"harbor_registries", "harbor_robot_accounts", "harbor_project_mappings", "harbor_launch_requests"},
		Docs:   []string{"docs/K8S_OPERATIONS_HUB.md", "docs/ADMIN_GUIDE.md"},
	},
	{
		Key: "skill_studio", Name: "Skill Studio", Group: "assets",
		Description: "Skill 등록·정책 enforce·보안 스캔·승격 게이트(모델 적합성 포함)·후보 추천.",
		APIs:        []string{"GET/POST /admin/skills", "POST /admin/skills/promote", "GET /admin/skill-studio/readiness", "GET/POST /admin/skills/fitness"},
		UITabs:      []string{"skills", "skill-studio"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"skills", "skill_runs", "skill_promotions", "skill_fitness_evidence"},
	},
	{
		Key: "prompt_assets", Name: "프롬프트 자산", Group: "assets",
		Description: "프롬프트 템플릿·버전·A/B·골든 연결·상품(Prompt Product)·자산 관리소.",
		APIs:        []string{"GET/POST /admin/prompt-templates", "GET /admin/prompt-products"},
		UITabs:      []string{"prompts", "prompt-assets"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"prompt_templates", "prompt_template_history", "prompt_products"},
	},
	{
		Key: "prompt_lab", Name: "Prompt Lab", Group: "assets",
		Description: "실험·테스트케이스·출력계약·rubric로 프롬프트를 재사용 가능한 검증 자산으로 전환.",
		APIs:        []string{"GET/POST /admin/prompt-lab/experiments", "POST /admin/prompt-lab/test-cases/{id}/run"},
		UITabs:      []string{"prompt-lab"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"prompt_experiments", "prompt_test_cases", "prompt_rubrics", "prompt_contracts", "prompt_test_case_runs"},
	},
	{
		Key: "multimodel_console", Name: "멀티 모델 콘솔", Group: "assets",
		Description: "동일 프롬프트 N개 모델 병렬 비교·Diff·rubric 자동평가·Golden 승격·리더보드.",
		APIs:        []string{"POST /admin/chat-test/multi-run", "POST .../judge", "GET .../runs/{id}/diff", "GET .../leaderboard"},
		UITabs:      []string{"chat-test"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"multi_model_test_runs", "multi_model_test_results", "multi_model_test_judgements", "model_usage_tags"},
	},
	{
		Key: "clickhouse_dw", Name: "ClickHouse DW", Group: "data",
		Description: "요청·tool·routing·eval·feedback·policy·skill·multimodel fact 적재 + 지표 사전.",
		APIs:        []string{"GET /admin/dw/*", "GET/POST /admin/dw/metrics"},
		UITabs:      []string{"dwdashboard", "dwmetrics"},
		Scopes:      []string{"admin:read"},
		SettingKeys: []string{"clickhouse.*"},
		Tables:      []string{"metric_catalog", "clickhouse_fact_retry", "clickhouse_sink_state"},
		Workers:     []string{"clickhouse_fact_queue", "clickhouse_sink", "clickhouse_fact_retry"},
	},
	{
		Key: "okf", Name: "OKF 지식", Group: "data",
		Description: "조직 지식 프레임(Org Knowledge Frame): Text2SQL/Clustara 지식 주입 + 자기개선 루프.",
		APIs:        []string{"GET/POST /admin/okf/*"},
		UITabs:      []string{"okf"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"okf_frames", "okf_entries"},
	},
	{
		Key: "personalization", Name: "개인화", Group: "users",
		Description: "Personal AI Profile·My AI Home·추천·모델/MCP affinity·코칭·내 추천 모델.",
		APIs:        []string{"GET /me/dashboard", "GET /me/recommended-models", "GET /me/report", "GET /admin/personalization/*"},
		UITabs:      []string{"me", "personalization"},
		Scopes:      []string{"self"},
		Tables:      []string{"personal_profiles", "personalization_recommendations"},
	},
	{
		Key: "work_apps", Name: "AI 업무 앱", Group: "users",
		Description: "Skill·프롬프트 상품·Text2SQL 리포트·MCP·추천 모델을 묶은 사용자용 업무 앱.",
		APIs:        []string{"GET/POST /admin/apps", "GET /v1/apps", "POST /v1/apps/{id}/run"},
		UITabs:      []string{"apps"},
		Scopes:      []string{"admin:read"},
		Tables:      []string{"work_apps"},
	},
	{
		Key: "runtime_settings", Name: "런타임 설정", Group: "ops",
		Description: "env 위에 admin 오버레이로 런타임 설정·역할별 권한·import/export·effective view·Change Set.",
		APIs:        []string{"GET/PUT /admin/settings", "POST /admin/settings/bulk", "GET/POST /admin/change-sets"},
		UITabs:      []string{"settings", "runtimesettings", "changesets"},
		Scopes:      []string{"admin:write"},
		Tables:      []string{"admin_settings", "admin_settings_history", "change_sets"},
	},
	{
		Key: "sso", Name: "Keycloak SSO", Group: "security",
		Description: "OIDC Auth Code+PKCE 로그인·API Bearer·back/front-channel logout·DB provider config·role 매핑.",
		APIs:        []string{"GET /auth/keycloak/login", "GET /auth/keycloak/callback", "GET/PUT /admin/sso/keycloak/config"},
		UITabs:      []string{"settings"},
		Scopes:      []string{"admin:write"},
		SettingKeys: []string{"SSO_KEYCLOAK_*"},
		Tables:      []string{"auth_identities", "sso_provider_config", "auth_sessions"},
	},
	{
		Key: "k8s_operations", Name: "K8s 운영 허브", Group: "ops",
		Description: "클러스터 등록, 카테고리형 리소스 관리(워크로드·네트워크·스토리지·구성요소·개발자 도구·인증/권한), Pod 관리·노드 관리·최근 restart 신호 보정·북마크·최근 이력·로그 분석·실시간 tail·로그 스냅샷·증적 번들·Golden Pod Diff·Health Replay·정책 기반 exec/debug 세션 요청, 터미널 정책, Event/Metric 스냅샷 적재, realtime watch delta 수신, health/security finding, 역할별 개발자 요청, 승인형 액션 요청, Action Flow Navigator, Manifest Change Studio(YAML 요청·검증·승인·drift guard·SSA 적용·증적).",
		APIs:        []string{"GET/POST /admin/k8s/clusters", "POST /admin/k8s/snapshot", "POST /admin/k8s/agent/events", "GET /admin/k8s/agent/status", "GET /admin/k8s/pods", "GET/POST /admin/k8s/pod-bookmarks", "GET /admin/k8s/pod-accesses", "GET /admin/k8s/pods/{namespace}/{pod}/logs", "GET /admin/k8s/pods/{namespace}/{pod}/logs/presets", "POST /admin/k8s/pods/{namespace}/{pod}/logs/masking-report", "POST /admin/k8s/pods/{namespace}/{pod}/logs/snapshot", "GET /admin/k8s/pods/{namespace}/{pod}/logs/merge", "POST /admin/k8s/pods/{namespace}/{pod}/logs/analyze", "GET /admin/k8s/pods/{namespace}/{pod}/logs/stream", "POST /admin/k8s/pods/{namespace}/{pod}/evidence-bundle", "GET /admin/k8s/pods/{namespace}/{pod}/golden-diff", "GET /admin/k8s/pods/{namespace}/{pod}/health-replay", "GET /admin/k8s/pods/{namespace}/{pod}/action-safety", "GET /admin/k8s/pods/{namespace}/{pod}/runbook", "GET /admin/k8s/pods/{namespace}/{pod}/exec/briefing", "POST /admin/k8s/pods/{namespace}/{pod}/exec/sessions", "GET /admin/k8s/exec/sessions", "GET /admin/k8s/exec/sessions/{id}", "GET /admin/k8s/exec/sessions/{id}/export", "POST /admin/k8s/exec/sessions/{id}/approve|reject|execute", "GET /admin/k8s/debug/catalog", "POST /admin/k8s/pods/{namespace}/{pod}/debug/sessions", "POST /admin/k8s/debug/sessions/{id}/approve|reject", "GET/POST /admin/k8s/terminal-policies", "GET /admin/k8s/terminal/templates", "POST /admin/k8s/terminal-policies/evaluate", "GET /admin/k8s/inventory", "GET /admin/k8s/findings", "GET /admin/k8s/action-flow", "GET/POST /admin/k8s/actions", "GET/POST /admin/k8s/dev-requests", "GET /admin/k8s/manifests/editor", "GET /admin/k8s/manifests/live", "GET/POST /admin/k8s/manifest-changes", "GET /admin/k8s/manifest-changes/{id}/brief", "POST /admin/k8s/manifest-changes/{id}/validate|approve|reject|apply|verify|rollback", "GET /admin/k8s/manifest-changes/{id}/evidence|git-patch"},
		UITabs:      []string{"k8s", "k8s-collector", "k8s-resources", "k8s-workloads", "k8s-network", "k8s-storage", "k8s-components", "k8s-devtools", "k8s-auth", "k8s-pods", "k8s-nodes", "k8s-developer", "k8s-stacks", "k8s-manifest-changes", "k8s-actions", "k8s-settings"},
		Scopes:      []string{"admin:read", "admin:write"},
		Tables:      []string{"k8s_clusters", "k8s_inventory", "k8s_events", "k8s_watch_events", "k8s_agent_heartbeats", "k8s_collector_offsets", "k8s_pod_bookmarks", "k8s_pod_accesses", "k8s_pod_log_queries", "k8s_pod_log_snapshots", "k8s_terminal_policies", "k8s_pod_exec_sessions", "k8s_debug_sessions", "k8s_security_findings", "k8s_action_requests", "k8s_manifest_change_requests", "k8s_collector_status"},
		Workers:     []string{"k8s_snapshot_ingest", "k8s_agent_delta_ingest", "k8s_analyzer"},
	},
	{
		Key: "ops_visibility", Name: "운영 가시성", Group: "ops",
		Description: "Flow Map·MCP Agentic Timeline·운영 홈·워커 상태판으로 요청·워커·우선순위를 한눈에. 워커 상태판은 queue depth, last success, last error, error count, lag seconds를 노출합니다.",
		APIs:        []string{"GET /admin/flow-map", "GET /admin/ops/home", "GET /admin/ops/workers", "GET /admin/workers", "GET /healthz", "GET /readyz", "GET /admin/capabilities"},
		UITabs:      []string{"ops-home"},
		Scopes:      []string{"admin:read"},
		Workers:     []string{"async_logger", "retention", "alert_worker", "clickhouse_fact_queue", "clickhouse_sink", "text2sql_report_scheduler"},
	},
}

// handleCapabilities lists the capability catalog. GET /admin/capabilities
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	// Group counts for the UI.
	groups := map[string]int{}
	for _, c := range capabilityRegistry {
		groups[c.Group]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"capabilities": capabilityRegistry,
		"count":        len(capabilityRegistry),
		"groups":       groups,
		"note":         "코드 정의 레지스트리(시스템 메타데이터). 기능 추가 시 capabilities.go에 항목을 더하세요.",
	})
}

// handleCapabilityByKey returns one capability. GET /admin/capabilities/{key}
func (s *Server) handleCapabilityByKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/admin/capabilities/")
	for _, c := range capabilityRegistry {
		if c.Key == key {
			writeJSON(w, http.StatusOK, c)
			return
		}
	}
	writeOpenAIError(w, http.StatusNotFound, "capability not found: "+key, "invalid_request_error", "not_found")
}
