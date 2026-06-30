# K8s Operations Hub

> **버전: v0.9.32** · 이 문서는 Clustara Kubernetes 운영 허브 API를 설명합니다. (바이너리 `AppVersion`과 최신 릴리즈 태그가 동일하게 정렬됩니다.)

## 기능 상태 (v0.9.32)

| 기능 | 상태 |
| --- | --- |
| 클러스터 등록(kubeconfig/token AES-GCM 암호화) · 연결 테스트 · 라이브 수집(client-go) | ✅ |
| 인벤토리(spec+status)·이벤트·메트릭 적재, 리소스 리비전·Diff·타임라인·Manifest 마스킹 | ✅ |
| RCA 01~10 (probe·DNS·NodePressure·Config 변경·배포 후 오류·latency) | ✅ |
| 연결성(Service/Ingress/PVC) · Rollout/Job · 용량(HPA·할당·packing·GPU·예측·시뮬) | ✅ |
| 보안·정책(Pod Security·RBAC·RBAC Diff·이미지·Secret·NetworkPolicy·TLS·감사이상·정책센터) | ✅ |
| **액션 승인 + 실클러스터 executor**(scale/rollout restart/cordon/uncordon/delete pod) | ✅ |
| 비용(FinOps) · 비용 증가 추세 · Mattermost 알림 · AI 분석 · 운영 홈 · 리포트 센터 | ✅ |
| Incident Workspace 상세 근거(이벤트·리비전·finding·액션) · Resource Graph 영향도 | ✅ |
| 조치 어드바이저(Remediation) · FinOps Rightsizing · SLO·에러버짓 센터 | ✅ (v0.4.0) |
| Incident Confidence Score(원인 신뢰도 — 변경/이벤트/재시작/근거/영향 합산, 워룸 상세에 설명) | ✅ |
| ChatOps(Mattermost slash 명령) · Policy as Code(Kyverno/Rego export·import) | ✅ (v0.4.0) |
| ClickHouse 장기 적재(sink/bootstrap/report) | ✅ (CH 연결 시) |
| 실시간 수집 — 서버측 delta 수신 API, watch event 원장, resourceVersion checkpoint, agent 하트비트/수집 상태 화면 | ✅ (v0.4.0) |
| 실시간 수집 — 인클러스터 `clustara-agent` 바이너리, 읽기 전용 RBAC, 재시작 checkpoint, offline queue | ✅ |
| Pod 관리 센터 — 목록·상세·위험 Pod 자동 북마크·최근 접근·현재/previous 로그·로그 프리셋·마스킹 리포트·스냅샷·동일 workload 병합·증적 번들·Golden Pod Diff·Health Replay·조치 안전성·플레이북 | ✅ |
| Pod Health Score(0~100) + 문제 유형 자동 태깅(CrashLoop/OOM/ImagePull/Pending/ProbeFailing 등) · Health 낮은 순 정렬 | ✅ |
| Restart Storm 탐지 — 같은 workload 다수 Pod 재시작/비정상 시 서비스 단위 장애로 묶어 경고(POD-RULE-06) · critical storm은 워크로드 incident 자동 생성 | ✅ |
| Pod 상세 One-Page 진단 요약 — 증상별 원인 후보·먼저 볼 것·최근 변경(롤백 검토)·참고 신호 합성(규칙 기반) | ✅ |
| 워크로드 묶음 보기 — owner(ReplicaSet/StatefulSet/DaemonSet) 단위 Pod 상태·Health·증상 집계, 위험 순 정렬 | ✅ |
| Pod Compare Matrix — 같은 워크로드 Pod를 필드 단위 비교, 다른 값·소수(outlier) Pod 강조 | ✅ |
| Pod Watch List — 중요 namespace/워크로드 감시 등록, 현재 위험 상태(밴드·위험 Pod·증상) 집계 | ✅ |
| K8s MCP Toolset — `/mcp/gateway`에 read-only 운영 도구(`k8s_list_clusters`·`k8s_list_incidents`·`k8s_pod_health`) 노출, admin:read 게이트 | ✅ |
| Runbook Orchestrator — 증상별 단계형 플랜(사전점검→진단→조치(승인)→확인→롤백), 최근 변경 시 롤백 후보 노출 | ✅ |
| 리포트 자동 발송 — 운영 다이제스트를 주기(interval)로 Mattermost 채널에 자동 발송 + 즉시 발송 | ✅ |
| Env Source Map — Pod 선언 env의 출처(literal/ConfigMap/Secret/Downward) 추적 + Secret 위생 점검(값 미노출·민감 평문 마스킹) | ✅ |
| Env Change Timeline — Pod가 참조하는 ConfigMap/Secret 변경 + Pod 리비전을 시간순 병합(장애 직전 설정 변경 탐지) | ✅ |
| Command Risk Parser — exec 명령 토큰화 위험도 분석(파이프-셸·시스템경로 리다이렉트·서브셸·체이닝·파괴적 명령), 터미널 정책 게이트 연계 | ✅ |
| Terminal Access Mode — read_only/guided/full_tty 3단계 분류, 인터랙티브 셸(full TTY)은 정책 무관 승인 필수 | ✅ |
| Application Stack 검증(dry-run) — 멀티 문서 매니페스트 적용 전 리소스 목록·정책 위반·승인 필요 변경 분석(클러스터 미적용) | ✅ |
| Application Stack 저장·리비전 — 검증한 매니페스트를 버전 관리되는 Stack으로 저장(앱 배포 메뉴), 매니페스트 변경 시 리비전 누적 | ✅ |
| 이미지 사용 현황 — 이미지→워크로드 매핑 + 공급망 위험(mutable :latest·digest 미고정), 보안 화면 노출(REG-REQ-04) | ✅ |
| Stack Drift 탐지 — 저장된 Stack 선언 리소스 vs 클러스터 인벤토리(존재/누락) 비교(GIT-REQ-05, 존재 레벨) | ✅ |
| 운영 RBAC 참조 모델 — capability 카탈로그 + 역할(viewer/developer/operator/approver/security/finops/admin)↔권한 매트릭스 + preflight(SEC-REQ-03/04/05, 강제 아님) | ✅ |
| Pull Secret 생성기 — 사설 레지스트리 imagePullSecret(dockerconfigjson) 매니페스트 생성, 자격증명 미저장(REG-REQ-03) | ✅ |
| Config Impact(blast radius) — ConfigMap/Secret 변경 전 참조 워크로드(env/envFrom/volume) + 재시작 필요 여부(CFG-REQ-04) | ✅ |
| Config Change Control Center — ConfigMap/Secret 변경 요청 생성, 영향도 자동 첨부, 승인 게이트, 적용 기록, 사후 검증 | ✅ |
| Terminal Policy Builder + Exec 세션 승인함 — role·namespace·label·명령 allow/deny·승인·세션 시간·감사 정책·Risk Briefing·명령 템플릿·세션 상세/리포트·Debug Container 요청 이력 | ✅ |
| Ops Agent 평가 센터 — 답변별 intent·도구 계획·사용 API·응답시간·폴백·근거 점수(인용·근거 수·도구·폴백 가중)·👍/👎 피드백 저장 + intent별 품질 대시보드(CLU-REQ-02/03) | ✅ (v0.9.10) |
| Action Card Lifecycle — 제안→승인대기→승인→실행→실패→롤백/재발 상태 전이 영속화 + Action Center 요청 연계(CLU-REQ-04) | ✅ (v0.9.10) |
| Stack Field-level Drift — 선언 매니페스트 vs 라이브 객체를 image·replicas·env·resources·probe·label·annotation 필드 단위 비교(`?fields=true`, CLU-REQ-07) | ✅ (v0.9.10) |
| Stack Apply/Promotion/Rollback — Server-Side Apply 적용(정책 Deny 차단·승인 게이트·dry-run)·환경 간 승격(diff)·이전 revision 롤백·배포 이력(CLU-REQ-08/09/10) | ✅ (v0.9.10) |
| 런타임 설정 롤백 센터 — 변경 이력·변경자·이전 값, 직전/특정 시점 값 롤백, 멀티 파드 수렴 상태(CLU-REQ-06) | ✅ (v0.9.10) |
| MCP Tool Scope Enforcement — 도구별 role·namespace·cluster 허용목록·masking level·approval rule(opt-in 최소권한, 게이트웨이 호출 시 강제, CLU-REQ-11) | ✅ (v0.9.10) |
| 적응형 자동 수집 스케줄러 — 실시간 agent 없는 클러스터는 자주(기본 60s), agent 있으면 보정 주기로만(기본 30m) 자동 수집. 멀티 파드 중복 방지·런타임 설정(`/admin/k8s/collect-config`) | ✅ (v0.9.11) |
| 운영 리스트 Pod 딥링크·자원 태그 — 장애 후보·Restart Storm·워크로드 묶음·Pod 목록에 Pod 상세 바로가기 + CPU/메모리 요청·상한 태그(OOMKilled 할당 자원 즉시 확인) | ✅ (v0.9.11) |
| Inventory Freshness Score + Stale Warning — 마지막 수집 시각·수집 주기·agent 생존·수집 실패를 종합한 scope(클러스터·namespace·kind)별 0~100 데이터 신선도/stale 판정(`/admin/k8s/freshness`, CLU-REQ-01·10) | ✅ (v0.9.12) |
| Collector SLO Dashboard + Collect Gap RCA — 수집 시도 이력 기반 성공률·p50/p95 지연·실패 밴드 + 실패 원인 분류(auth·rbac·timeout·network·ratelimit·tls·config)·클러스터 vs 수집 신호 구분(`/admin/k8s/collect-slo`, CLU-REQ-02·03) | ✅ (v0.9.13) |
| Change-Aware Burst Collection — Config 적용·Stack 적용·Action 실행 직후 해당 클러스터를 짧은 기간 고빈도 수집(burst)해 변경 검증 가속, 창 만료 시 자동 복귀(`/admin/k8s/collect-bursts`, CLU-REQ-05) | ✅ (v0.9.14) |
| Resource Request Advisor — OOMKilled·Pending(자원 부족)·CPU throttling·반복 재시작 증상을 현재 request/limit·사용량과 연결해 워크로드별 request/limit 권장값 제시(증상 기반, Rightsizing 보완, `/admin/k8s/resource-advisor`, CLU-REQ-06) | ✅ (v0.9.15) |
| Action Outcome Analytics — AI 제안 Action Card의 채택률·실행 성공률·롤백률·재발률을 조치 유형·위험도별로 집계(Action Card lifecycle 기반, `/admin/agent/action-outcomes`, CLU-REQ-09) | ✅ (v0.9.16) |
| Agent Regression Suite — 대표 운영 질문 세트로 에이전트의 결정적 동작(intent 분류·도구 계획) 회귀 검증 + baseline 대비 통과율 하락 감지(`/admin/agent/regression`, CLU-REQ-08) | ✅ (v0.9.17) |
| Service Impact Home — 워크로드 중심 카드(Pod 헬스 + Service/Ingress 노출 + HPA + 최근 변경 + 미해결 incident)로 서비스 blast radius를 위험 순으로 표시(`/admin/k8s/service-impact`, CLU-REQ-07) | ✅ (v0.9.18) |
| Adaptive Collection Policy — agent 생존에 더해 클러스터 우선순위(label priority)·미해결 incident·watch 등록을 반영해 수집 주기 자동 조정(incident 시 강제 단축, 하한 15s, `/admin/k8s/collect-config` cadences, CLU-REQ-04) | ✅ (v0.9.19) |
| Collection Cost Guard — 클러스터별 수집 저장 footprint(행 수×테이블별 평균 크기) 추정 + 수집 주기 기반 월 증가 예측 + 예산 초과 경고(`/admin/k8s/collection-cost`, CLU-REQ-11) | ✅ (v0.9.20) |
| Release Quality Gate 2.0 — AppVersion↔changelog↔문서 헤더/기능 상태 일치, changelog 중복·정렬·자기 버전 언급을 `go test`에서 강제하는 영구 게이트(CLU-REQ-13) | ✅ (v0.9.21) |
| Domain Module Map — proxy/store 점진 분리를 위한 목표 도메인 경계·파일 매핑·추출 순서 정의(`docs/ARCHITECTURE_MODULES.md`, CLU-REQ-12) | ✅ (v0.9.22) |
| K8s API Discovery + Schema Registry — aggregated discovery(`/apis`·`/api`)와 `/openapi/v3` root를 수집해 클러스터별 API resource 카탈로그·OpenAPI 문서 인덱스 캐싱(동적 리소스 인식·CRD 인식 토대, `/admin/k8s/discovery`, `/clusters/{id}/discover`, CLU-DISC-01/02/04/05/13) | ✅ (v0.9.23) |
| Dynamic Inventory Target + CRD Auto + MCP Tool Candidate Generator — discovery 카탈로그에서 list/watch 가능 수집 대상 후보(핵심 권장·민감 제외·CRD 선택)와 read-only MCP 도구 후보(`k8s_list_*`·`k8s_get_*`·`k8s_explain_*`) 자동 생성(CLU-DISC-06/07/11) | ✅ (v0.9.24) |
| API Compatibility Radar — 발견된 카탈로그의 deprecated/removed API group-version 탐지(제거 버전·대체 안내) + 두 클러스터/스냅샷 카탈로그 diff(added/removed/changed)(`/admin/k8s/discovery/compare`, CLU-DISC-12) | ✅ (v0.9.25) |
| Workspace Center — namespace를 업무 Workspace로 묶어 Pod 헬스·미해결 incident·Quota·외부 노출·런타임 보안 위험을 합산한 0~100 Health Score(OpenShift Project 스타일, 운영 홈, `/admin/k8s/workspaces`, CLU-OCP-01) | ✅ (v0.9.26) |
| Exposure Center — Ingress·LoadBalancer/NodePort Service 외부 노출 + TLS 미적용·wildcard·민감 경로 위험 분석(OpenShift Route 스타일, `/admin/k8s/exposures`, CLU-OCP-02) | ✅ (v0.9.27) |
| Runtime Security Profile — Pod의 privileged·host namespace·hostPath·위험 capability·root·privesc 점수화 + Pod Security 프로파일(restricted/baseline/privileged) 분류(OpenShift SCC 스타일, `/admin/k8s/runtime-security`, CLU-OCP-03) | ✅ (v0.9.27) |
| Image Stream Ledger — 워크로드별 이미지 digest 원장 + mutable 태그 위험 + tag drift(같은 repo:tag·다른 digest) 탐지(OpenShift ImageStream 스타일, `/admin/k8s/image-ledger`, CLU-OCP-04) | ✅ (v0.9.28) |
| Platform Lifecycle Center — 업그레이드 준비도(deprecated API·kubelet skew·critical incident 종합)(OpenShift ClusterVersion 스타일, `/admin/k8s/lifecycle`, CLU-OCP-08) | ✅ (v0.9.29) |
| Built-in Observability Profile — 서비스 유형별 ServiceMonitor·Alert·SLO 템플릿 생성기(클러스터 미변경, OpenShift Monitoring 스타일, `/admin/k8s/observability`, CLU-OCP-10) | ✅ (v0.9.29) |
| Build·Add-on·Node 분석 코어 — 빌드 실패 RCA + Dockerfile 보안 게이트 / add-on install-plan 위험 미리보기 / 노드 drain 영향 분석(실행 제외·분석만, `/admin/k8s/build/analyze`·`/extensions/install-plan`·`/node-drain`, CLU-OCP-05/06/07 코어) | ✅ (v0.9.30) |
| Developer Workspace View — 개발자 관점 화면(워크스페이스 건강도·노출·이미지 원장·위험 Pod 통합, OpenShift Developer Console 스타일, `#/k8s-developer`, CLU-OCP-09) | ✅ (v0.9.31) |
| Developer Self-Service Request Center — 개발자 뷰에서 재시작·스케일·롤백·cordon·Config 변경·로그 요청 생성 → 기존 승인 흐름(Action Center·Config Change) 연결(`/admin/k8s/dev-requests`, CLU-NEXT-01·02) | ✅ (v0.9.32) |

수집은 Kubernetes API 기반 주기 폴링이며, 외부 collector가 보낼 표준 스냅샷(`POST /admin/k8s/snapshot`)을 지원합니다. v0.4.0부터 **실시간 watch delta 수신**(`POST /admin/k8s/agent/events`)도 지원합니다 — 인클러스터 `clustara-agent`가 watch 이벤트(ADDED/MODIFIED/DELETED)와 하트비트를 보내면 수동 수집 없이 인벤토리/리비전/incident가 즉시 갱신됩니다. 서버는 watch event를 `k8s_watch_events`에 idempotency key로 저장해 재전송 중복을 제거하고, `k8s_collector_offsets`에 kind별 resourceVersion checkpoint를 누적합니다. agent는 로컬 상태 파일과 offline queue로 재시작/일시 단절을 복구합니다. `수집 상태` 화면에서는 agent 하트비트·watch lag·resourceVersion·중복 이벤트·재연결·최근 watch 이벤트를 추적합니다. 배포 절차는 [K8s Agent 가이드](K8S_AGENT.md)를 참고하세요.

## API

| Method | Path | 설명 |
| --- | --- | --- |
| GET | `/admin/k8s/overview` | 클러스터, 인벤토리, warning event, finding, action 요약 |
| GET | `/admin/k8s/home` | 운영 홈 집계: 클러스터 위험 TOP5, 장애 후보 TOP10, 최근 변경 TOP10, 비용 증가 TOP10 |
| GET | `/admin/k8s/reports` | 리포트 센터: 일간 장애·주간 비용·월간 안정성(SLO) 요약 (로컬 데이터) |
| GET/POST | `/admin/k8s/report-schedules` | 리포트 자동 발송 예약 목록/생성: `cluster_id`·`interval`(예 24h)·`channel` |
| DELETE/POST | `/admin/k8s/report-schedules/{id}` `/{id}/send` | 예약 삭제 / 즉시 발송(Mattermost) |
| GET/POST | `/admin/k8s/incidents` | 장애 워룸: 목록 / (POST)현재 high·critical RCA를 incident로 스캔·묶기 |
| GET | `/admin/k8s/incidents/{id}` | 장애 상세 워크스페이스: RCA 근거, 관련 이벤트·리비전·finding·액션, 영향도 그래프, `POST /{id}/resolve` 해결 처리 |
| GET/POST | `/admin/k8s/clusters` | 클러스터 목록/등록 (`group_id`로 그룹 지정 가능) |
| GET/POST | `/admin/k8s/groups` | 클러스터 그룹 목록(롤업)/생성, `DELETE /groups/{id}` |
| GET/POST | `/admin/k8s/ownership` | 네임스페이스 오너십(담당팀·담당자·서비스·중요도·비용센터) 조회/설정 |
| GET | `/admin/k8s/clusters/{id}` | 클러스터 상세 |
| POST | `/admin/k8s/clusters/{id}/test` | API Server 연결 테스트, 버전/노드/네임스페이스 수 갱신 |
| POST | `/admin/k8s/clusters/{id}/collect` | Kubernetes API에서 라이브 인벤토리·이벤트·메트릭 수집 |
| GET | `/admin/k8s/collect-slo` | Collector SLO: 클러스터별 수집 성공률·p50/p95 지연·실패 밴드 + 최근 실패 원인 분류(RCA). `?cluster_id=&window_hours=` |
| GET/POST | `/admin/k8s/collect-bursts` | 변경 직후 고빈도 수집 burst: 활성 burst 목록·설정 조회(GET) / 수동 burst 등록(POST `{cluster_id, namespace, reason}`) |
| GET/POST | `/admin/k8s/collect-config` | 적응형 수집 스케줄러 설정: agent 유무별 주기 + burst 주기/창(`burst_secs`·`burst_window_secs`) |
| GET | `/admin/k8s/resource-advisor` | Resource Request Advisor: OOMKilled·Pending·throttling 증상 기반 워크로드별 request/limit 권장값. `?cluster_id=&namespace=` |
| POST | `/admin/k8s/snapshot` | 리소스, 이벤트, 메트릭 스냅샷 적재 |
| GET | `/admin/k8s/inventory` | 리소스 인벤토리 조회 |
| GET | `/admin/k8s/images` | 이미지→워크로드 사용 현황 + 공급망 위험(mutable :latest / digest 고정) |
| GET | `/admin/k8s/rbac` `/rbac/check?role=&capability=` | 운영 RBAC 참조: capability 카탈로그·역할 매트릭스·preflight 점검(강제 아님) |
| POST | `/admin/k8s/registries/pull-secret` | 사설 레지스트리 imagePullSecret 매니페스트 생성(자격증명 미저장·미감사) |
| GET | `/admin/k8s/config-impact?kind=&namespace=&name=` | ConfigMap/Secret 변경 영향: 참조 워크로드(env/envFrom/volume) + 재시작 필요 여부 |
| GET/POST | `/admin/k8s/config-changes` | ConfigMap/Secret 변경 요청 목록/생성. 생성 시 Config Impact 스냅샷 자동 첨부, Secret 또는 영향 workload가 있으면 승인 필요 |
| GET | `/admin/k8s/config-changes/{id}` | 변경 요청 상세: 승인/적용/검증 상태, 영향 workload, 검증 이력 |
| POST | `/admin/k8s/config-changes/{id}/approve`, `/reject`, `/apply`, `/verify` | 변경 요청 승인/반려, 외부/GitOps 적용 기록, 사후 검증. Secret 원문 payload는 저장하지 않음 |
| GET | `/admin/k8s/pods` | Pod 관리 목록: 클러스터·namespace·node·owner·status·risk·검색 필터, restart/warning 요약 |
| GET | `/admin/k8s/pods/{namespace}/{pod}` | Pod 상세: 상태, 컨테이너 상태, 관련 이벤트, Pod 메트릭, 로그 감사, 마스킹 manifest |
| GET | `/admin/k8s/pods/{namespace}/{pod}/logs` | Pod 로그 조회: `cluster_id`, `container`, `previous`, `tail_lines`, `since`, `since_time`, `q`, `error_only`, `timestamps` |
| POST | `/admin/k8s/pods/{namespace}/{pod}/logs/analyze` | current/previous 로그를 마스킹 후 에러 패턴·근거 라인·조치 후보로 분석 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/logs/stream` | Pod 실시간 로그 tail(SSE): `follow=true`, `container`, `tail_lines`, `since`, `q`, `error_only`, `timestamps` |
| POST | `/admin/k8s/pods/{namespace}/{pod}/logs/export` | 마스킹된 Pod 로그를 text 파일로 다운로드하고 조회 감사 기록 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/logs/presets` | Spring Boot, Java, Node.js, Nginx, DB, 공통 오류용 로그 검색 프리셋 |
| POST | `/admin/k8s/pods/{namespace}/{pod}/logs/masking-report` | 로그 샘플 또는 실제 로그에서 민감정보 패턴 탐지·마스킹 미리보기 |
| POST | `/admin/k8s/pods/{namespace}/{pod}/logs/snapshot` | 장애 시점 로그를 마스킹 스냅샷으로 고정 저장 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/logs/snapshots` | Pod 로그 스냅샷 이력 조회 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/logs/merge` | 같은 owner/workload Pod 로그를 시간순 병합 조회 |
| POST | `/admin/k8s/pods/{namespace}/{pod}/evidence-bundle` | Pod 증적 ZIP 생성: current/previous 로그, 이벤트, 메트릭, manifest, 리비전, RCA, 로그 감사 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/golden-diff` | 같은 owner/label의 정상 Pod와 image, env, resource, probe, node, restart 차이 비교 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/compare-matrix` | 같은 워크로드 Pod 전체를 필드 단위로 비교, 다른 값·소수(outlier) Pod 표시 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/env` | 선언 env의 출처(literal/ConfigMap/Secret/Downward) 맵 + Secret 위생 위험(값 미노출) |
| GET | `/admin/k8s/pods/{namespace}/{pod}/env-timeline` | 참조 ConfigMap/Secret 변경 + Pod 리비전 시간순 병합(설정 변경↔장애 상관) |
| GET | `/admin/k8s/pods/{namespace}/{pod}/health-replay` | Pod 상태·컨테이너 상태·이벤트·메트릭·리비전·로그 감사·RCA 후보를 시간순으로 재생 |
| POST | `/admin/k8s/pods/{namespace}/{pod}/bookmark` | 운영자 Pod 북마크 저장 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/action-safety` | delete/evict/restart/scale/debug 전 owner, replica, HPA, PDB, 최근 이벤트 기반 안전성 점검 |
| GET | `/admin/k8s/pods/{namespace}/{pod}/runbook` | 표준 대응 플레이북 + 증상별 오케스트레이션 플랜(`plan`: 사전점검→진단→조치(승인)→확인→롤백) |
| GET/POST | `/admin/k8s/pods/{namespace}/{pod}/exec/sessions` | Pod별 정책 기반 exec 세션 요청/이력: role, container, command, reason, `ready`/`pending_approval`/`denied` |
| GET | `/admin/k8s/pods/{namespace}/{pod}/exec/briefing` | 터미널 접속 전 대상 Pod 중요도, 최근 이벤트, 명령 위험도, 정책 경고 요약 |
| GET/POST | `/admin/k8s/pods/{namespace}/{pod}/debug/sessions` | Ephemeral debug container 요청/이력. 실제 주입 전 승인·이미지 allowlist·권한 제한을 적용 |
| GET/POST | `/admin/k8s/pod-bookmarks` | 사용자별 Pod 북마크 목록·생성, 위험 Pod 자동 북마크 포함 |
| DELETE | `/admin/k8s/pod-bookmarks/{id}` | Pod 북마크 삭제 |
| GET/POST | `/admin/k8s/pod-watches` | 감시 목록 조회(현재 위험 상태 집계)/등록: cluster_id·namespace·owner(선택) |
| DELETE | `/admin/k8s/pod-watches/{id}` | 감시 삭제 |
| GET | `/admin/k8s/pod-accesses` | 사용자별 최근 Pod 상세·로그·exec·debug 접근 이력 |
| GET | `/admin/k8s/exec/sessions` | 전체 Pod exec 세션 요청 이력 조회: cluster, namespace, pod, status 필터 |
| GET | `/admin/k8s/exec/sessions/{id}` | 단일 exec 세션 상세 조회: 정책 평가 결과, 요청·승인·실행 리플레이, exit code, 마스킹 출력 샘플 |
| GET | `/admin/k8s/exec/sessions/{id}/export` | 단일 exec 세션 감사 리포트(Markdown) 다운로드: 대상 Pod, 정책 결과, 리플레이, 마스킹 출력 샘플 |
| POST | `/admin/k8s/exec/sessions/{id}/approve`, `/reject`, `/execute` | `pending_approval` 세션 승인/반려, `ready` 세션의 단일 제한 명령 실행. 실행 결과는 `completed`/`failed`, exit code, 마스킹 출력 샘플로 감사 기록 |
| GET | `/admin/k8s/debug/catalog` | 허용된 debug image 카탈로그와 상황별 추천 템플릿 |
| GET | `/admin/k8s/debug/sessions` | 전체 debug container 요청 이력 |
| POST | `/admin/k8s/debug/sessions/{id}/approve`, `/reject` | debug container 요청 승인/반려. v0.8.0에서는 감사 가능한 요청·manifest preview까지 관리 |
| GET | `/admin/k8s/terminal/templates` | 읽기 전용 확인 명령 템플릿(ps/env/df/DNS/HTTP 등) |
| GET/POST | `/admin/k8s/terminal-policies` | Pod web terminal/exec 사전 정책 목록·생성: role, cluster, namespace glob, label selector, allow/deny 명령, 승인·감사 설정 |
| DELETE | `/admin/k8s/terminal-policies/{id}` | 터미널 정책 삭제 |
| POST | `/admin/k8s/terminal-policies/evaluate` | 특정 role/namespace/pod labels/command를 실제 exec 전에 정책으로 평가(`access_mode`·`command_risk_findings` 포함) |
| GET | `/admin/k8s/revisions` | 리소스 spec 변경 리비전 이력 (`cluster_id`,`kind`,`namespace`,`name`,`limit`) |
| GET | `/admin/k8s/diff` | 두 리비전의 필드 단위 diff (`from`/`to` 미지정 시 최근 2개 비교, 민감값 자동 마스킹) |
| GET | `/admin/k8s/timeline` | 리비전·이벤트·액션을 시간순 병합한 변경 타임라인 |
| GET | `/admin/k8s/manifest` | 현재 리소스 manifest YAML 조회 (Secret/token/env 민감값 자동 마스킹) |
| GET | `/admin/k8s/resource-graph` | 인벤토리 selector/backend/volume/node/HPA 관계 기반 리소스 그래프·blast radius (`cluster_id`,`kind`,`namespace`,`name`,`radius`) |
| GET | `/admin/k8s/security` | Pod Security 등급, RBAC 위험, 이미지 태그, Secret 참조, NetworkPolicy 공백 포스처 |
| GET | `/admin/k8s/capacity` | HPA 현황·확장한계, 과소/과다 할당, 노드 bin-packing, GPU, 노드 용량 예측(SCALE-05) |
| GET | `/admin/k8s/capacity/simulate` | replica 시뮬레이션 (SCALE-06): `kind`,`namespace`,`name`,`replicas` |
| GET | `/admin/k8s/rbac-diff` | Role/ClusterRole 권한 확대 추적 (SEC-08, 리비전 기반) |
| GET/POST | `/admin/k8s/stacks` | Application Stack 목록/저장(검증 후 버전 관리, 매니페스트 변경 시 리비전 누적) |
| GET/DELETE | `/admin/k8s/stacks/{id}` | Stack 상세(+리비전 이력)/삭제 |
| GET | `/admin/k8s/stacks/{id}/drift` | Stack 선언 리소스 vs 클러스터 인벤토리 존재/누락 드리프트 |
| POST | `/admin/k8s/stacks/validate` | Application Stack dry-run: 멀티 문서 매니페스트(YAML/JSON) 리소스·정책 위반·승인 필요 분석(미적용) |
| GET/POST | `/admin/k8s/policies` | 정책 팩 목록/생성 (SEC-10), `DELETE /policies/{id}` |
| POST | `/admin/k8s/policies/simulate` | manifest 적용 전 정책 위반 검증 (SEC-05 Admission 시뮬레이터) |
| GET | `/admin/k8s/policies/compliance` | 현재 인벤토리의 정책 위반 목록 |
| GET | `/admin/k8s/cost` | request×단가 월 비용 추정 (namespace/team/group/cost-center), `cost/config`로 단가 조정 |
| POST | `/admin/k8s/cost/snapshot` | 일별 비용 스냅샷 기록 (비용 증가율 추세용, 로컬 누적) |
| GET | `/admin/k8s/cost/trend` | namespace별 전일 대비 비용 증가/감소 |
| GET | `/admin/k8s/cost/recommendations` | Rightsizing 권장(request 대비 usage) — down=절감액·up=증설 권고 |
| GET | `/admin/k8s/slo` | 서비스(namespace)별 SLO·에러버짓 — 가용성/MTTR/다운타임/잔여 버짓 (`days`, `target` 파라미터) |
| POST | `/admin/k8s/ai/ask` | 자연어 장애 질문 — RCA·이벤트·diff 근거 기반 답변(LLM 미구성 시 근거만) |
| POST | `/admin/k8s/ai/report` | 클러스터 운영 상태 AI 요약 리포트 |
| POST | `/admin/k8s/agent/events` | **실시간 수집** — 인클러스터 agent의 watch delta(ADDED/MODIFIED/DELETED) + 하트비트 배치 수신, watch 원장·offset 저장, 인벤토리/리비전/incident 즉시 갱신 |
| GET | `/admin/k8s/agent/status` | Collector agent 하트비트(버전·resourceVersion·watch lag·재연결·수신수), stale(90s), resourceVersion checkpoint, 최근 watch 이벤트 |
| GET | `/admin/k8s/freshness` | Inventory Freshness Score — scope(클러스터·namespace·kind)별 0~100 데이터 신선도/stale 판정 + summary. `?cluster_id=` 지정 시 namespace·kind 분해 |
| POST | `/admin/k8s/dw/sink` | K8s fact(change/event/health/security/cost/action/metric)를 ClickHouse 적재 (미구성 시 no-op) |
| POST | `/admin/k8s/dw/bootstrap` | ClickHouse에 K8s fact 테이블 생성 (미구성 시 no-op) |
| POST | `/admin/k8s/actions/{id}/execute` | 승인된 액션을 실클러스터에 실행 (scale/rollout_restart/cordon/uncordon/delete_pod) |
| GET | `/healthz`, `/readyz`, `/admin/ops/workers`, `/admin/workers` | liveness/readiness와 background worker 상태(queue depth, last success, last error, error count, lag seconds) |
| POST | `/admin/k8s/notify/scan` | 현재 high/critical 장애·보안을 평가해 Mattermost 알림(중복제거·조용한시간·담당팀 라우팅·딥링크) |
| GET/POST | `/admin/k8s/notify/config` | 조용한 시간(`quiet_hours` HH-HH) + 팀→채널 매핑(`team_channels` JSON) |
| GET/POST | `/admin/notifications/mattermost` | Mattermost 알림 설정(webhook/channel/events) + ChatOps slash 검증 토큰(`slash_token`) |
| POST | `/integrations/mattermost/command` | **ChatOps 수신**(공개·토큰검증, x-www-form-urlencoded) — `incidents`/`rca [ns]`/`slo [목표] [일수]`/`cost`/`help` 읽기전용 조회, Mattermost 응답 포맷 |
| GET | `/admin/k8s/events` | 이벤트 조회 |
| GET | `/admin/k8s/findings` | health/security finding 조회 |
| GET | `/admin/k8s/rca` | Pending, CrashLoop, ImagePull, OOM, unavailable + Readiness/Liveness probe, DNS, NodePressure, 직전 config 변경·배포 후 오류·배포 후 latency 회귀 연계 원인 후보 |
| GET | `/admin/k8s/remediation/advice` | RCA별 권장 조치 Advisor — 권장 액션·근거·위험도·승인 필요·롤백 가능성·우선순위 |
| POST | `/admin/k8s/latency/collect` | Prometheus에서 워크로드 latency 수집·적재 (RCA-10 latency, `PROMETHEUS_URL` 필요) |
| GET/POST | `/admin/k8s/latency/config` | latency PromQL + 라벨 매핑(namespace/workload) 설정 |
| GET | `/admin/k8s/connectivity` | Service selector↔Pod endpoint, Ingress backend/host/TLS, PVC Pending 점검 |
| GET/POST | `/admin/k8s/actions` | 액션 요청 목록/생성. 생성 시 `idempotency_key`, `target_uid`, `target_resource_version`, `command_hash` 저장 |
| POST | `/admin/k8s/actions/{id}/approve` | 액션 승인 (요청 생성 시 영향도 자동 산출 → dry_run_diff, blocker 시 승인 강제). 허용 전이: `pending|approval_required -> approved` |
| POST | `/admin/k8s/actions/{id}/reject` | 액션 반려 |

## 클러스터 등록

### 개발 PC: minikube 등록

현재 개발 PC에서 minikube를 쓰는 경우에는 로컬 kubeconfig를 그대로 등록하는 방식이 가장 빠릅니다.

```powershell
minikube status
kubectl config use-context minikube

$server = kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
kubectl config view --raw --minify --flatten | Set-Content .\minikube-clustara.kubeconfig
```

관리자 UI의 `K8s 운영` 메뉴에서 다음처럼 입력합니다.

| 입력 | 값 |
| --- | --- |
| 클러스터 이름 | `local-minikube` |
| API Server URL | `$server` 출력값 |
| 인증 방식 | `kubeconfig` |
| kubeconfig/token | `minikube-clustara.kubeconfig` 파일 내용 전체 |

등록 후 `연결 테스트`를 눌러 Kubernetes 버전, 노드 수, 네임스페이스 수가 갱신되는지 확인합니다. 그 다음 `수집`을 누르면 namespace, node, pod, deployment, service, event, metrics-server 메트릭이 가능한 범위에서 저장됩니다.

`tls: failed to verify certificate: x509: certificate signed by unknown authority`가 나오면 kubeconfig 안에 CA가 포함되지 않았거나 파일 경로를 Clustara 프로세스가 읽지 못하는 상태입니다. 위 명령처럼 `--flatten`을 붙여 `certificate-authority-data`, `client-certificate-data`, `client-key-data`가 포함된 kubeconfig를 다시 등록하세요.

게이트웨이를 Docker 컨테이너 안에서 실행하는 경우 minikube API server 주소가 `127.0.0.1`로 잡혀 있으면 컨테이너에서 접근하지 못할 수 있습니다. 이때는 host 접근 주소나 네트워크 구성을 별도로 맞춘 kubeconfig를 등록해야 합니다.

### 운영망: 실제 K8s cluster 등록

운영망에서는 개인 kubeconfig를 그대로 등록하지 말고, Clustara 전용 ServiceAccount를 만들어 최소 권한으로 등록하는 것을 권장합니다.

```powershell
kubectl create namespace clustara-system
kubectl -n clustara-system create serviceaccount clustara-reader

@"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: clustara-readonly
rules:
- apiGroups: [""]
  resources: ["namespaces", "nodes", "pods", "services", "persistentvolumeclaims", "events"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch"]
# (선택) TLS 인증서 만료 분석(SEC-07)을 쓰려면 secrets read 추가 — 권한 없으면 해당 분석만 생략됨
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["pods", "nodes"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["get", "list", "watch"]
"@ | kubectl apply -f -

kubectl create clusterrolebinding clustara-reader `
  --clusterrole=clustara-readonly `
  --serviceaccount=clustara-system:clustara-reader
```

사설 CA를 쓰는 운영 클러스터까지 고려하면 token만 붙이는 것보다 CA와 token이 함께 들어간 전용 kubeconfig를 만드는 편이 안전합니다.

```powershell
$server = kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
$ca = kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[0].cluster.certificate-authority-data}'
$token = kubectl -n clustara-system create token clustara-reader --duration=8760h

@"
apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: $server
    certificate-authority-data: $ca
users:
- name: clustara-reader
  user:
    token: $token
contexts:
- name: prod
  context:
    cluster: prod
    user: clustara-reader
current-context: prod
"@ | Set-Content .\clustara-prod.kubeconfig
```

관리자 UI에는 다음처럼 입력합니다.

| 입력 | 값 |
| --- | --- |
| 클러스터 이름 | 예: `prod-kr-a`, `stage-kr-a` |
| API Server URL | `$server` 출력값 |
| 인증 방식 | `kubeconfig` |
| kubeconfig/token | `clustara-prod.kubeconfig` 파일 내용 전체 |

읽기 전용 수집과 실제 조치 권한은 분리하는 편이 좋습니다. `scale`, `rollout restart`, `delete pod`, `cordon`, `drain` 같은 액션은 별도 ServiceAccount와 승인 워크플로우를 둔 뒤 단계적으로 열어야 합니다.

### API로 직접 등록

```powershell
curl.exe -X POST http://localhost:9090/admin/k8s/clusters `
  -H "Content-Type: application/json" `
  -d '{
    "name": "prod-a",
    "server_url": "https://k8s.example.test",
    "auth_mode": "kubeconfig",
    "kubeconfig": "apiVersion: v1\nclusters: []",
    "labels": { "env": "prod" }
  }'
```

`kubeconfig` 또는 `token`은 `GATEWAY_SECRET` 기반 AES-GCM 암호화 값으로 저장되고 API 응답에는 원문이 반환되지 않습니다.

등록 후 연결 테스트:

```powershell
curl.exe -X POST http://localhost:9090/admin/k8s/clusters/k8scl_.../test
```

라이브 수집:

```powershell
curl.exe -X POST http://localhost:9090/admin/k8s/clusters/k8scl_.../collect
```

## Pod 관리와 증적 번들

`Pod 관리` 화면은 수집된 Pod 인벤토리 위에서 목록·상세·로그·조치 안전성·디버그 요청을 제공합니다. 목록에서는 클러스터, namespace, node, owner, status, risk, 검색어로 필터링하고 CrashLoop/OOM/ImagePull/Pending/Evicted 계열 Pod를 위험 Pod로 강조합니다. 위험 Pod, restart가 많은 Pod, Warning 이벤트가 붙은 Pod는 `system:auto` 북마크로 자동 고정되며, 상세·로그·exec·debug 접근은 최근 이력에 남아 운영자가 보던 흐름으로 바로 돌아갈 수 있습니다.

상세에서는 ready, restart, node, owner, QoS, Pod IP, 컨테이너별 상태, 관련 이벤트, 최근 메트릭, 최근 로그 감사, 마스킹 manifest를 확인합니다. `Golden Pod Diff`는 같은 owner 또는 label workload 안에서 Running/Ready 상태가 좋고 restart/warning이 적은 Pod를 자동 기준으로 골라 장애 Pod와 비교합니다. `Pod Health Replay`는 상태 스냅샷, 컨테이너 상태, 이벤트, 메트릭, 리비전, 로그 조회 감사, RCA 후보를 하나의 시간축으로 묶어 장애 흐름을 재생합니다. `조치 안전성`은 delete/evict/restart/scale/debug 전에 owner 존재 여부, replica 여유, HPA, 최근 Warning 이벤트, restart 횟수를 함께 계산하고, `플레이북`은 Pod 상태와 이벤트에 맞는 확인·조치 순서를 제안합니다.

로그 조회와 실시간 tail은 Kubernetes API의 `pods/log` subresource를 사용합니다. minikube처럼 관리자 kubeconfig를 등록한 경우 바로 사용할 수 있고, 운영망 전용 ServiceAccount를 쓰는 경우 위 RBAC 예시처럼 `pods/log`의 `get` 권한이 필요합니다. 로그 응답과 증적 번들 안의 로그는 서버에서 token, password, Authorization, 주민등록번호, 카드번호 등 민감 패턴을 마스킹한 뒤 반환합니다. 로그 분석은 current/previous 로그를 함께 읽어 Exception, OOM, timeout, DNS, network, auth, probe, image pull 계열 패턴을 그룹핑하고 근거 라인과 조치 후보를 반환합니다. v0.8.0부터는 로그 검색 프리셋, 마스킹 리포트/미리보기, 장애 시점 로그 스냅샷, 같은 workload의 다중 Pod 로그 병합도 제공합니다.

```powershell
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/logs?cluster_id=k8scl_...&container=nginx&tail_lines=200"
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/logs?cluster_id=k8scl_...&previous=true&q=Exception&error_only=true"
curl.exe -X POST "http://localhost:9090/admin/k8s/pods/default/nginx/logs/analyze?cluster_id=k8scl_...&container=nginx&tail_lines=500"
curl.exe -N "http://localhost:9090/admin/k8s/pods/default/nginx/logs/stream?cluster_id=k8scl_...&tail_lines=50"
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/logs/presets?cluster_id=k8scl_..."
curl.exe -X POST "http://localhost:9090/admin/k8s/pods/default/nginx/logs/masking-report?cluster_id=k8scl_..." `
  -H "Content-Type: application/json" `
  -d '{"text":"Authorization: Bearer token\npassword=secret"}'
curl.exe -X POST "http://localhost:9090/admin/k8s/pods/default/nginx/logs/snapshot?cluster_id=k8scl_...&tail_lines=500"
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/logs/snapshots?cluster_id=k8scl_..."
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/logs/merge?cluster_id=k8scl_...&tail_lines=100&q=ERROR"
curl.exe -X POST "http://localhost:9090/admin/k8s/pods/default/nginx/evidence-bundle?cluster_id=k8scl_...&tail_lines=1000" -o nginx-evidence.zip
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/golden-diff?cluster_id=k8scl_..."
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/golden-diff?cluster_id=k8scl_...&golden=nginx-healthy"
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/health-replay?cluster_id=k8scl_...&window_minutes=60"
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/action-safety?cluster_id=k8scl_...&action=delete_pod"
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/runbook?cluster_id=k8scl_..."
```

증적 ZIP에는 `summary.md`, `pod.json`, `manifest.json`, `events.json`, `metrics.json`, `revisions.json`, `rca.json`, `log-audit.json`, `logs/current.log`, `logs/previous.log`가 포함됩니다. previous 로그가 없는 경우에는 `logs/previous.error.txt`로 원인을 기록합니다. 로그 스냅샷은 ZIP 번들보다 가벼운 “그 시점 로그 고정” 용도로 `k8s_pod_log_snapshots`에 보관합니다.

## Terminal Policy Builder

`운영 설정` 화면의 Terminal Policy Builder는 실제 Pod exec/web terminal 기능을 켜기 전에 접속 정책을 먼저 정의하는 안전장치입니다. 정책은 role, cluster, namespace glob, Pod label selector, 허용 명령, 차단 명령, 승인 필요 여부, 최대 세션 시간, 감사 저장 여부를 포함합니다. 내장 차단 규칙은 `rm -rf`, `dd`, `mkfs`, `shutdown/reboot`, `curl|sh`, `kubectl delete`, 패키지 설치 명령 등을 기본적으로 차단합니다.

Pod 상세 화면의 `터미널 요청`은 이 정책을 통과한 단일 명령 요청을 `k8s_pod_exec_sessions`에 저장합니다. 정책이 허용하고 승인이 필요 없으면 `ready`, 승인이 필요하면 `pending_approval`, 내장 차단 또는 정책 미일치면 `denied`가 됩니다. 운영 설정의 `Exec 세션 승인함`에서 `pending_approval` 요청을 승인하면 `ready`, 반려하면 `rejected`로 전환되고 `decided_by`, `decided_at`, `decision_note`가 남습니다. `ready` 세션은 실행 직전 `running`으로 선점된 뒤 무입력·무TTY 단일 명령으로만 실행되며, 완료 후 `completed` 또는 `failed`로 닫히고 `executed_by`, `executed_at`, `exit_code`, 마스킹된 출력 샘플이 기록됩니다. 허용 상태 전이는 `pending_approval -> ready|rejected`, `ready -> running`, `running -> completed|failed`뿐이며, 중복 승인·중복 실행은 DB와 API에서 409로 차단됩니다. 각 세션의 `상세`는 요청, 승인/반려, 실행 결과를 시간순 리플레이로 보여 주며, `리포트`는 동일 내용을 Markdown 감사 증적으로 내려받습니다. `Risk Briefing`은 exec 요청 전 대상 Pod의 namespace, node, owner, 최근 Warning 이벤트, 명령 위험도, 정책 차단 가능성을 요약합니다. `터미널 명령 템플릿`은 ps/env/df/DNS/HTTP 등 읽기 전용 진단 명령을 버튼으로 제공합니다.

Debug Container 기능은 운영망에서 위험도가 높으므로 v0.8.0에서는 “요청·승인·감사·manifest preview” 흐름을 먼저 제공합니다. 허용 이미지는 catalog에 고정하고, privileged/hostPID/hostNetwork는 기본 차단합니다. 승인된 요청은 누가, 어떤 Pod/target container에, 어떤 debug image와 사유로 요청했는지 `k8s_debug_sessions`에 기록됩니다. 실제 ephemeral container 주입 executor는 별도 운영 정책과 함께 확장할 수 있도록 분리되어 있습니다.

```powershell
curl.exe -X POST "http://localhost:9090/admin/k8s/terminal-policies" `
  -H "Content-Type: application/json" `
  -d '{"name":"prod read only","role":"viewer","cluster_id":"k8scl_...","namespace_pattern":"prod-*","pod_selector":"app=api","command_allowlist":["ls","cat *","grep *"],"require_approval":true,"max_session_minutes":10,"audit_enabled":true,"enabled":true}'

curl.exe -X POST "http://localhost:9090/admin/k8s/terminal-policies/evaluate" `
  -H "Content-Type: application/json" `
  -d '{"role":"viewer","cluster_id":"k8scl_...","namespace":"prod-api","pod":"api-1","pod_labels":{"app":"api"},"command":"ls /app"}'

curl.exe "http://localhost:9090/admin/k8s/terminal/templates"
curl.exe "http://localhost:9090/admin/k8s/pods/default/nginx/exec/briefing?cluster_id=k8scl_...&role=operator&command=ps%20ef"
curl.exe "http://localhost:9090/admin/k8s/debug/catalog"
curl.exe -X POST "http://localhost:9090/admin/k8s/pods/default/nginx/debug/sessions?cluster_id=k8scl_..." `
  -H "Content-Type: application/json" `
  -d '{"target_container":"nginx","debug_image":"nicolaka/netshoot:latest","reason":"DNS reachability 확인"}'
```

## 스냅샷 적재

```powershell
curl.exe -X POST http://localhost:9090/admin/k8s/snapshot `
  -H "Content-Type: application/json" `
  -d '{
    "cluster_id": "k8scl_...",
    "resources": [
      {
        "kind": "Deployment",
        "namespace": "default",
        "name": "api",
        "status": "Available",
        "api_version": "apps/v1",
        "spec": {
          "template": {
            "spec": {
              "containers": [
                { "name": "api", "image": "example/api:latest" }
              ]
            }
          }
        }
      }
    ],
    "events": [
      {
        "namespace": "default",
        "involved_kind": "Pod",
        "involved_name": "api-123",
        "type": "Warning",
        "reason": "BackOff",
        "message": "Back-off restarting failed container"
      }
    ],
    "metrics": [
      {
        "namespace": "default",
        "resource_kind": "Pod",
        "resource_name": "api-123",
        "cpu_millicores": 120,
        "memory_bytes": 268435456
      }
    ]
  }'
```

스냅샷 적재 시 `privileged`, `hostNetwork`, `hostPath`, `latest` 이미지 태그, CrashLoop/ImagePull/OOM/Pending 상태, Warning 이벤트를 기반으로 finding이 생성됩니다.
`root` 실행과 wildcard RBAC 권한도 보안 finding으로 분류합니다.

## 액션 요청

```powershell
curl.exe -X POST http://localhost:9090/admin/k8s/actions `
  -H "Content-Type: application/json" `
  -d '{
    "cluster_id": "k8scl_...",
    "namespace": "default",
    "resource_kind": "Pod",
    "resource_name": "api-123",
    "action": "delete_pod"
  }'
```

`delete_pod`, `cordon`, `scale`, `rollout_restart` 같은 위험 액션은 기본적으로 승인 대기 상태가 됩니다. 승인된 `scale`/`rollout_restart`/`cordon`/`uncordon`/`delete_pod`는 실클러스터 executor로 실행되며, `drain`/`apply_manifest` 계열은 별도 안전성 검증 후속 범위로 남겨둡니다.
