package analyzer

import "strings"

// Collect Gap RCA (CLU-REQ-03).
//
// When a scheduled/manual inventory collect fails, the operator's first question is "is the
// cluster in trouble, or did only the collection fail?". This classifies a collect error (plus
// the pipeline stage it failed at) into a concrete cause — auth, RBAC, timeout, network, rate
// limit, TLS, config, not-found, agent-offline — with a likely explanation, a remediation hint,
// and crucially whether it points at the cluster itself or just our collection path.
//
// Pure string classification: callers pass the recorded stage + error text.

// Collect gap categories.
const (
	CollectGapAuth         = "auth"
	CollectGapRBAC         = "rbac"
	CollectGapTimeout      = "timeout"
	CollectGapNetwork      = "network"
	CollectGapRateLimit    = "ratelimit"
	CollectGapTLS          = "tls"
	CollectGapNotFound     = "notfound"
	CollectGapConfig       = "config"
	CollectGapAgentOffline = "agent_offline"
	CollectGapUnknown      = "unknown"
)

// CollectGap is the classified cause of a failed collect attempt.
type CollectGap struct {
	Category     string `json:"category"`
	Title        string `json:"title"`         // short Korean label
	Likely       string `json:"likely"`        // what likely happened
	Remediation  string `json:"remediation"`   // suggested next step
	Confidence   string `json:"confidence"`    // high | medium | low
	ClusterIssue bool   `json:"cluster_issue"` // true: points at the cluster/infra; false: collection-side
}

// ClassifyCollectGap maps a collect failure (stage + error text) to a cause. stage is the pipeline
// step that failed (client | probe | collect | snapshot); errText is the recorded error.
func ClassifyCollectGap(stage, errText string) CollectGap {
	e := strings.ToLower(strings.TrimSpace(errText))

	// A failure building the client (before any network call) is a credential/config problem.
	if strings.TrimSpace(stage) == "client" {
		return CollectGap{
			Category: CollectGapConfig, Title: "수집 설정/자격증명 오류",
			Likely:      "클러스터 credential 또는 접속 설정이 없거나 잘못돼 Kubernetes 클라이언트를 생성하지 못했습니다.",
			Remediation: "클러스터 등록 정보(server_url·auth_mode)와 credential을 확인하세요.",
			Confidence:  "high", ClusterIssue: false,
		}
	}
	if e == "" {
		return CollectGap{
			Category: CollectGapUnknown, Title: "원인 미상",
			Likely:      "오류 메시지가 기록되지 않았습니다.",
			Remediation: "수집 상태 화면의 최근 실패 항목과 서버 로그를 확인하세요.",
			Confidence:  "low", ClusterIssue: false,
		}
	}

	switch {
	case containsAny(e, "401", "unauthorized", "token is expired", "token has expired", "authentication", "invalid bearer", "credentials"):
		return CollectGap{
			Category: CollectGapAuth, Title: "인증 실패/만료",
			Likely:      "토큰 또는 자격증명이 만료되었거나 유효하지 않습니다.",
			Remediation: "ServiceAccount 토큰/ kubeconfig 자격증명을 갱신하고 클러스터 credential을 다시 등록하세요.",
			Confidence:  "high", ClusterIssue: false,
		}
	case containsAny(e, "forbidden", "is forbidden", "cannot list", "cannot get", "cannot watch", "rbac", "403"):
		return CollectGap{
			Category: CollectGapRBAC, Title: "RBAC 권한 부족",
			Likely:      "수집 주체에 get/list/watch 권한이 없어 일부 리소스를 읽지 못했습니다.",
			Remediation: "수집용 ServiceAccount에 필요한 ClusterRole(get·list·watch)을 부여하세요.",
			Confidence:  "high", ClusterIssue: false,
		}
	case containsAny(e, "429", "too many requests", "throttl", "rate limit", "client rate limiter"):
		return CollectGap{
			Category: CollectGapRateLimit, Title: "레이트리밋",
			Likely:      "API server 또는 클라이언트 레이트리미터가 요청을 제한했습니다.",
			Remediation: "수집 주기를 늘리거나(collect-config) 동시 수집 범위를 줄이세요.",
			Confidence:  "high", ClusterIssue: false,
		}
	case containsAny(e, "x509", "certificate", "tls", "certificate signed by unknown authority", "certificate has expired"):
		return CollectGap{
			Category: CollectGapTLS, Title: "TLS/인증서 문제",
			Likely:      "API server 인증서를 검증하지 못했습니다(만료·CA 불일치·SNI 등).",
			Remediation: "CA 번들과 server_url을 확인하고 인증서 만료 여부를 점검하세요.",
			Confidence:  "high", ClusterIssue: false,
		}
	case containsAny(e, "timeout", "deadline exceeded", "context deadline", "i/o timeout", "timed out"):
		return CollectGap{
			Category: CollectGapTimeout, Title: "API server 응답 지연/타임아웃",
			Likely:      "API server가 제한 시간 내에 응답하지 않았습니다 — apiserver 과부하 또는 네트워크 지연일 수 있습니다.",
			Remediation: "apiserver 상태와 네트워크 경로를 확인하세요. 반복되면 수집 타임아웃을 조정하세요.",
			Confidence:  "medium", ClusterIssue: true,
		}
	case containsAny(e, "connection refused", "no route to host", "dial tcp", "no such host", "network is unreachable", "connection reset", "eof"):
		return CollectGap{
			Category: CollectGapNetwork, Title: "네트워크 단절",
			Likely:      "API server 엔드포인트에 연결하지 못했습니다 — 엔드포인트 다운, DNS, 방화벽 문제일 수 있습니다.",
			Remediation: "server_url 도달성(DNS·방화벽·VPN)과 apiserver 가용성을 확인하세요.",
			Confidence:  "medium", ClusterIssue: true,
		}
	case containsAny(e, "not found", "404", "could not find"):
		return CollectGap{
			Category: CollectGapNotFound, Title: "대상 없음",
			Likely:      "클러스터 또는 대상 리소스를 찾지 못했습니다.",
			Remediation: "클러스터 등록 정보와 server_url 경로를 확인하세요.",
			Confidence:  "medium", ClusterIssue: false,
		}
	default:
		return CollectGap{
			Category: CollectGapUnknown, Title: "분류되지 않은 오류",
			Likely:      "알려진 패턴에 해당하지 않는 오류입니다.",
			Remediation: "원문 오류와 서버 로그를 확인하세요.",
			Confidence:  "low", ClusterIssue: false,
		}
	}
}
