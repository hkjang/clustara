package proxy

import (
	"sort"
	"strings"
)

// gatewayAPIOperation is the LLM-facing projection of the authoritative OpenAPI catalog.
// The catalog is discoverable through MCP, but an entry is executable only when mcp_tools is
// non-empty and the named tool is present in tools/list.
type gatewayAPIOperation struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Tag         string   `json:"tag"`
	Summary     string   `json:"summary"`
	Access      string   `json:"access"`
	Risk        string   `json:"risk"`
	MCPTools    []string `json:"mcp_tools"`
	MCPExposure string   `json:"mcp_exposure"`
}

func gatewayAPICatalog() []gatewayAPIOperation {
	out := make([]gatewayAPIOperation, 0, len(apiEndpoints))
	seen := map[string]bool{}
	for _, endpoint := range apiEndpoints {
		for _, method := range endpoint.methods {
			method = strings.ToUpper(strings.TrimSpace(method))
			key := method + " " + endpoint.path
			if method == "" || seen[key] {
				continue
			}
			seen[key] = true
			tools := gatewayMCPToolsForOperation(endpoint.path, method)
			exposure := "reference_only"
			if len(tools) > 0 {
				exposure = "dedicated_tool"
			}
			out = append(out, gatewayAPIOperation{
				Method: method, Path: endpoint.path, Tag: endpoint.tag, Summary: endpoint.summary,
				Access: gatewayAPIAccess(endpoint), Risk: gatewayAPIRisk(method, endpoint.summary),
				MCPTools: tools, MCPExposure: exposure,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func gatewayAPIAccess(endpoint apiEndpoint) string {
	if endpoint.public {
		return "public"
	}
	switch {
	case strings.HasPrefix(endpoint.path, "/admin/") || endpoint.path == "/admin":
		return "admin_authorized"
	case strings.HasPrefix(endpoint.path, "/me/") || strings.HasPrefix(endpoint.path, "/team/"):
		return "caller_scoped"
	default:
		return "api_key_or_session"
	}
}

func gatewayAPIRisk(method, summary string) string {
	if method == "GET" || method == "HEAD" || method == "OPTIONS" {
		return "read_only"
	}
	text := strings.ToLower(method + " " + summary)
	for _, signal := range []string{"delete", "revoke", "execute", "apply", "restore", "rotate", "reset", "import", "approve", "reject"} {
		if strings.Contains(text, signal) {
			return "high"
		}
	}
	return "state_change"
}

func gatewayMCPToolsForOperation(path, method string) []string {
	key := method + " " + path
	mapping := map[string][]string{
		"POST /v1/chat/completions":             {"gateway_chat", "gateway_run_skill", "gateway_run_text2sql_preview"},
		"GET /v1/models":                        {"gateway_list_models"},
		"GET /me/requests/{id}/receipt":         {"gateway_explain_request"},
		"GET /me/dashboard":                     {"gateway_get_usage_summary", "gateway_check_quota"},
		"GET /admin/k8s/clusters":               {"k8s_list_clusters"},
		"GET /admin/k8s/incidents":              {"k8s_list_incidents"},
		"GET /admin/k8s/pods":                   {"k8s_pod_health"},
		"GET /admin/k8s/nodes/monitoring":       {"k8s_node_metrics"},
		"GET /admin/k8s/pods/{namespace}/{pod}": {"k8s_pod_metrics"},
		"POST /admin/k8s/manifest-changes":      {"k8s_create_manifest_change"},
		"POST /admin/k8s/manifest-changes/{id}": {"k8s_validate_manifest_change", "k8s_approve_manifest_change", "k8s_apply_manifest_change", "k8s_verify_manifest_change"},
		"POST /v1/workflows/{id}/run":           {"gateway_run_workflow"},
		"POST /v1/apps/{id}/run":                {"gateway_create_app_run"},
		"GET /admin/gateway-mcp/info":           {"gateway_search_api_catalog"},
	}
	return append([]string(nil), mapping[key]...)
}

func searchGatewayAPICatalog(query, tag, method string, limit int) []gatewayAPIOperation {
	query = strings.ToLower(strings.TrimSpace(query))
	tag = strings.ToLower(strings.TrimSpace(tag))
	method = strings.ToUpper(strings.TrimSpace(method))
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	out := []gatewayAPIOperation{}
	for _, operation := range gatewayAPICatalog() {
		if tag != "" && strings.ToLower(operation.Tag) != tag {
			continue
		}
		if method != "" && operation.Method != method {
			continue
		}
		haystack := strings.ToLower(operation.Method + " " + operation.Path + " " + operation.Tag + " " + operation.Summary)
		if query != "" {
			matched := true
			for _, term := range strings.Fields(query) {
				termMatched := false
				for _, candidate := range gatewayAPISearchAliases(term) {
					if strings.Contains(haystack, candidate) {
						termMatched = true
						break
					}
				}
				if !termMatched {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
		}
		out = append(out, operation)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func gatewayAPISearchAliases(term string) []string {
	term = strings.ToLower(strings.TrimSpace(term))
	aliases := map[string][]string{
		"yaml": {"yaml", "manifest"}, "매니페스트": {"manifest"}, "변경": {"change", "update", "apply", "manifest"},
		"파드": {"pod"}, "노드": {"node"}, "클러스터": {"cluster"}, "네임스페이스": {"namespace"},
		"로그": {"log"}, "모니터링": {"monitoring", "metrics", "observability"}, "지표": {"metric", "monitoring"},
		"서비스": {"service"}, "백업": {"backup"}, "복구": {"restore", "recovery"}, "승인": {"approve", "approval"},
		"정책": {"policy"}, "보안": {"security"}, "취약점": {"vulnerability", "vuln", "cve"}, "비용": {"cost", "finops"},
		"사용량": {"usage", "metric"}, "장애": {"incident", "problem", "failure"}, "캘린더": {"calendar"},
	}
	if values := aliases[term]; len(values) > 0 {
		return values
	}
	return []string{term}
}

func gatewayAPICoverage() map[string]any {
	catalog := gatewayAPICatalog()
	tags := map[string]int{}
	dedicated := 0
	mutating := 0
	for _, operation := range catalog {
		tags[operation.Tag]++
		if operation.MCPExposure == "dedicated_tool" {
			dedicated++
		}
		if operation.Risk != "read_only" {
			mutating++
		}
	}
	return map[string]any{
		"openapi_paths": len(apiEndpoints), "openapi_operations": len(catalog),
		"mcp_cataloged_operations": len(catalog), "mcp_catalog_coverage_percent": 100,
		"dedicated_mcp_operations": dedicated, "advertised_mcp_tools": len(gatewayToolDefs()),
		"mutating_operations": mutating, "tags": tags,
		"execution_policy": "API catalog entries are reference-only unless mcp_exposure=dedicated_tool and the named tool is present in tools/list.",
	}
}

func gatewayMCPInstructions() string {
	return "Clustara 기능을 찾을 때 gateway_search_api_catalog을 먼저 사용하세요. " +
		"검색 결과의 mcp_exposure=dedicated_tool인 경우에만 mcp_tools의 전용 도구를 호출하세요. " +
		"reference_only API는 기능 설명이며 MCP에서 직접 실행할 수 있다고 가정하지 마세요. " +
		"Kubernetes 작업은 k8s_list_clusters로 cluster_id를 확인한 뒤 읽기 도구로 증거를 수집하세요. " +
		"YAML 변경은 create draft, validate dry-run, 필요 시 approve, apply, verify 순서를 지키고 Secret 원문은 요청하거나 출력하지 마세요."
}

func gatewayOperatorGuideMarkdown() string {
	return "# Clustara MCP 사용 가이드\n\n" +
		"## 권장 순서\n\n" +
		"1. `gateway_search_api_catalog`으로 Clustara가 해당 기능을 제공하는지 확인합니다.\n" +
		"2. 결과의 `mcp_exposure`와 `mcp_tools`를 확인합니다.\n" +
		"3. `dedicated_tool`만 실제 MCP 호출 대상으로 사용합니다. `reference_only`는 OpenAPI/관리 화면 참고 정보입니다.\n" +
		"4. K8s 진단은 `k8s_list_clusters` → `k8s_list_incidents` → `k8s_pod_health` → `k8s_node_metrics`/`k8s_pod_metrics` 순서로 증거를 좁힙니다.\n" +
		"5. YAML 변경은 `k8s_create_manifest_change` → `k8s_validate_manifest_change` → 필요 시 `k8s_approve_manifest_change` → `k8s_apply_manifest_change` → `k8s_verify_manifest_change` 순서를 지킵니다.\n\n" +
		"## 데이터 안전\n\n- API Key, Secret, 비밀번호, 토큰 원문을 프롬프트나 도구 인자에 넣지 않습니다.\n" +
		"- 읽기 결과와 추론을 구분하고, 확인하지 않은 상태를 사실로 표현하지 않습니다.\n" +
		"- 전체 HTTP 계약은 `gateway://api/catalog`, 커버리지는 `gateway://api/coverage`에서 확인합니다.\n"
}
