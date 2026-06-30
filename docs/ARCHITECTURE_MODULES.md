# Domain Module Map (CLU-REQ-12)

> **버전: v0.9.22** · `internal/proxy`(203개 파일)와 `internal/store`(121개 파일)가 커지면서, 이후 기능 추가 시 충돌·회귀 위험을 줄이기 위한 **점진 분리(incremental split)** 의 경계와 계획을 정의합니다.

## 왜 빅뱅 분리가 아니라 점진 분리인가

`internal/proxy`의 핸들러는 대부분 `*Server`의 메서드이고 공유 헬퍼(`writeJSON`·`authorizeAdmin`·`firstNonEmpty`·`parseK8sHomeTime`·`asMapAny` 등)와 `s.db`(단일 `*store.SQLStore`)에 의존합니다. 패키지를 한 번에 물리적으로 쪼개면:

- `*Server` 메서드를 도메인 패키지로 옮기려면 거대한 인터페이스 plumbing 또는 순환 의존이 생깁니다.
- 324개 파일의 package 선언·상호 참조를 동시에 바꿔야 해 **대규모 회귀 위험**이 있고 **기능 가치는 0**입니다.
- 리뷰도 이 항목을 **P2 · "점진 분리"** 로 규정합니다.

따라서 **경계를 먼저 합의하고**, 새 코드는 그 경계에 맞춰 배치하며, 기존 코드는 도메인별로 **하나씩** 추출하는 전략을 택합니다. 이 문서가 그 기준입니다.

## 목표 도메인 (논리적 경계)

| 도메인 | 책임 | 현재 파일 prefix(예) |
| --- | --- | --- |
| **core** | 서버 부트스트랩, 라우팅(mux), 인증/파이프라인, 공용 헬퍼 | `server.go`, `pipeline.go`, `admin.go`, `openapi*.go` |
| **gateway** | OpenAI 호환 `/v1` 프록시, 라우팅, MCP 게이트웨이, chat-test | `mcp_gateway_local.go`, `intelligent_routing.go`, `admin_chat_*.go`, `text2sql_*.go` |
| **k8sops** | 클러스터·인벤토리·Pod·RCA·incident·stack·config·수집 | `admin_k8s*.go`, `k8s_collect_*.go`, `collector/`, store `k8s_*.go` |
| **agentops** | 플로팅 Ops Agent, 평가 센터, Action Card, 회귀 스위트 | `admin_agent*.go`, store `k8s_agent_*.go` |
| **mcpops** | MCP 도구 스코프·레지스트리·디스커버리 | `admin_mcp*.go`, `mcp_*.go` |
| **finops** | 비용·chargeback·budgets·rightsizing·collection cost | `admin_cost.go`, `admin_budgets.go`, `admin_chargeback.go`, `admin_k8s_cost.go`, `admin_k8s_collection_cost.go` |
| **governance** | 정책·감사·RBAC·canary·change-set·kill-switch | `admin_governance.go`, `admin_audit_*.go`, `admin_change_*.go`, `admin_canary.go` |
| **observability** | 로깅·메트릭·ClickHouse·flow-map·trace | `admin_clickhouse.go`, `admin_dw.go`, `admin_flow_map.go`, `metrics*.go` |

## 분석 계층은 이미 분리됨

`internal/analyzer`는 **순수 함수 + 단위 테스트**로 도메인별 파일이 잘 나뉘어 있습니다(예: `freshness.go`, `collectslo.go`, `collectgap.go`, `collectpolicy.go`, `collectioncost.go`, `serviceimpact.go`, `resourceadvisor.go`, `actionoutcome.go`, `agentregression.go`, `podhealth.go`, `restartstorm.go`, `confidence.go`, `rightsizing.go`, …). 신규 비즈니스 로직은 **핸들러가 아니라 analyzer에 순수 함수로** 두는 현재 관례를 유지하면, proxy 패키지의 부피 증가를 자연히 억제합니다.

## 점진 추출 전략 (순서)

1. **공용 헬퍼 안정화** — `writeJSON`·`writeOpenAIError`·`authorizeAdmin`·`firstNonEmpty`·`asMapAny`·`parseK8sHomeTime` 등을 core 헬퍼로 명시(이미 사실상 그러함). 도메인 패키지가 의존할 표면을 고정.
2. **store 먼저** — `internal/store`의 `k8s_*.go`는 이미 도메인 파일로 나뉘어 있어 가장 먼저 `store/k8sstore` 서브패키지로 추출 가능(데이터 계층은 `*Server` 의존이 없음).
3. **analyzer 유지** — 추가 분리 불필요. 도메인 로직의 정착지.
4. **handler는 마지막** — `*Server` 메서드를 도메인 핸들러 구조체로 옮기는 것은 가장 위험하므로, 위 1~2가 끝나고 도메인 인터페이스가 안정된 뒤에만 착수.

## 규칙(신규 코드)

- K8s 운영 핸들러는 `admin_k8s_*.go`, 에이전트는 `admin_agent*.go`, 수집은 `k8s_collect_*.go`로 파일명을 도메인에 맞춰 둔다.
- 비즈니스 로직은 `internal/analyzer`에 순수 함수로 두고 핸들러는 조립·IO만 담당한다.
- store 접근 함수는 `internal/store`의 도메인 파일(`k8s_*.go` 등)에 둔다.

이 경계가 정착되면, 위 순서대로 패키지를 하나씩 떼어내도 회귀 위험을 최소화할 수 있습니다.
