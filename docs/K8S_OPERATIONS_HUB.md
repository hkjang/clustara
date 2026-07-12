# K8s Operations Hub

> **버전: v0.9.128** · 이 문서는 Clustara Kubernetes 운영 허브 API를 설명합니다. (바이너리 `AppVersion`과 최신 릴리즈 태그가 동일하게 정렬됩니다.)

## 기능 상태 (v0.9.128)

| 기능 | 상태 |
| --- | --- |
| Service Platform Phase 1 — 배포 상품 카탈로그, 버전·자원 프로파일, 서비스 인스턴스, 검증/미리보기, Application Stack 변환, Action Center 운영 요청, `service:*` capability | ✅ (v0.9.124) |
| Service Platform Phase 2 기반 — Stack/인벤토리 구성요소 동기화, 가중 Health Score, Endpoint 파생, Secret 참조, 비용 추정 및 화면 내 검증 | ✅ (v0.9.125) |
| Service Platform 자동 운영 — 런타임 설정형 주기 reconcile, DB lease 중복 방지, 수집 실패/실제 장애 분리, PostgreSQL 백업 Job 승인 초안 | ✅ (v0.9.126) |
| Service Platform 복구·스냅샷 — Restore Preview, 대상 서비스 복구 Job 승인 초안, 복구 원장, CSI VolumeSnapshot 백업·상태 추적 | ✅ (v0.9.127) |
| Service Platform Snapshot Clone Restore — readyToUse 스냅샷에서 비파괴 새 PVC 생성, 충돌·용량·범위 검증, 승인 초안과 Bound 완료 추적 | ✅ (v0.9.128) |
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
| Personal Workspace UX — 로그아웃 메뉴 위와 상단 `내 영역` 메뉴에서 내 홈, 업무 캘린더, 개인 키, 나의 외부연동, 개인화 설정을 제공하고 `/me/work-calendar`로 나와 관련된 운영 업무를 날짜별 집계 | ✅ (v0.9.113) |
| Manifest Change Risk Explain & Verification Sync — K8s Action 및 Manifest 변경 요청에 필드/정책 기반 위험도 사유(Reason) 설명 모달을 연동하고, 검증 완료 시 백그라운드 수집 주기 격차(timing gap)로 인한 대기 상태에 대해 passed_pending_observation으로 자동 정합 | ✅ (v0.9.114) |
| Manifest Change Live API Verification — 백그라운드 인벤토리 수집 주기 딜레이를 우회하도록 API 서버에 실시간 직접 읽기(ResourceGetter)를 연동해 timing gap 오탐을 최소화하고, Job과 Pod warning 관계 매핑 및 상세 판정 사유(execution_failed, verified_with_warning, observation_pending 등) UI 연동 | ✅ (v0.9.115) |
| Admin Work Calendar — 전체 클러스터·네임스페이스·역할 대상 운영 액션/Config/YAML/Exec/Debug 작업을 월별/날짜별 달력과 대규모 목록으로 모니터링하는 통합 운영 캘린더 제공 | ✅ (v0.9.116) |
| Reasoning Agent Stream & Calendar Names — Ollama 등 추론형 모델의 생각 과정(thinking) 스트리밍 토글 렌더링을 보강하고, 전체 업무 캘린더의 담당자 ID(UUID/Email)를 실시간 사용자 디렉토리(User Directory)와 결합해 인체공학적인 담당자 실명으로 매핑 표시 | ✅ (v0.9.118) |
| Manifest Studio Secret Guard & Policy UX — Manifest 생성/변경 화면에 data/stringData 페이로드 탐지 및 저장 차단(Secret 안전 경로 유도 모달)을 추가하고, 정책 센터에 각 규칙 유형(Rule Type)의 해설 카탈로그(Help UI) 및 정책 토글 스위치 제공 | ✅ (v0.9.119) |
| Node & GPU Operations Monitoring — 60초 CPU/Memory 실사용·추세·장애 선행 경보, GPU/MIG/DCGM 워크로드·낭비·VRAM·XID/ECC/NVLink·비용, 승인형 격리, YAML/타임라인/그래프 딥링크 | ✅ (v0.9.120) |
| Admin Access UX Redirect & Mutation Exceptions — 관리자 API 인가(Authorization)를 고도화하여 401/403 응답을 정합하고 브라우저 직접 접근 시 SPA의 Access Denied 화면으로 리다이렉트 지원, 보안(security_admin) 및 비용(billing_admin) 관리 역할에 대해 각각 쓰기(admin:write) 권한 예외 세분화 및 모니터링 테스트 연동 | ✅ (v0.9.121) |
| Safe Cluster Deletion — 클러스터 목록에 삭제 버튼 추가, 이름 확인(Name Confirmation) 안전장치, `DELETE /admin/k8s/clusters/{id}` API로 21개 관련 테이블 Cascade Delete 트랜잭션 처리 | ✅ (v0.9.123) |
| GPU Monitor Typo Fix & Auth Guide — GPU 모니터링 화면에서 비용 KPI 함수 won 미정의 오류를 해결하고 브라우저 다이렉트 API 요청에 대한 401 인가 명세 및 SPA 헤더 처리 가이드 추가 | ✅ (v0.9.122) |
| Cluster Group Membership CRUD — 추가한 클러스터를 그룹에 배정·변경·해제하고, 그룹 수정/삭제·오너십 수정/삭제까지 `#/k8s-meta`에서 처리 | ✅ (v0.9.112) |
| External Integration Credential Vault — 설정 그룹의 외부연동 설정 메뉴에서 GitLab·Bitbucket·Harbor·Mattermost Token/Password를 사용자별 암호화 저장하고 GitOps/Harbor 화면에서 `credential_id`로 재사용 | ✅ (v0.9.111) |
| Internal Git Provider Integration — 사내 GitLab·Bitbucket Server 6.x provider 원장, 사용자별 저장 Credential 또는 일회성 token 연결 확인, project/repo/branch/tree/file catalog picker, PR API payload preview | ✅ (v0.9.109) |
| GitOps Change Manager UX Guide — GitOps 개념 가이드 모달, Stack→Git Source→Drift→PR Draft→Rollout/Evidence 흐름 카드, 빠른 등록 폼, 전용 운영 가이드 문서 | ✅ (v0.9.108) |
| Resource Graph Topology UX — 리소스 관계를 SVG 토폴로지 맵으로 표시, YAML 링크 옆 토폴로지 모달 진입, 기본 2-hop 포커스, 고립 RBAC 노이즈 억제 | ✅ (v0.9.107) |
| 리소스 카테고리 센터 — 워크로드·네트워크·스토리지·구성요소·개발자 도구·인증/권한별 인벤토리, 위험 리소스, Kind 분포, YAML/타임라인/그래프 딥링크, 네트워크 경로 맵 및 스토리지 생명주기 맵 시각화 연동 | ✅ (v0.9.117) |
| Harbor Management UX — Harbor registry·Robot Account·Project mapping 개별 조회/수정/삭제, registry force delete 안전장치, Harbor catalog 기반 project/repository/tag·digest select picker | ✅ (v0.9.106) |
| Harbor Launch Draft Set — Harbor registry 등록·연결 테스트, Robot Account token hash 원장·pull 검증, project→namespace imagePullSecret 매핑, redacted pull secret preview, digest 기반 Deployment/Service 런칭 요청 원장, Manifest Change Studio Deployment/Service 초안 전환, 이미지 런칭 보안 판정 제공 | ✅ (v0.9.105) |
| Security User Guide Modal — 보안 하위 화면 공통 사용자 상세 가이드 모달, 화면별 운영 순서·업로드 예시·판단 기준 제공 | ✅ (v0.9.103) |
| Security Manifest & SBOM Ops — multi-document YAML Admission 이미지 추출, 원본 CycloneDX/SPDX SBOM 직접 업로드, query metadata 보정 | ✅ (v0.9.102) |
| Security Admission & Benchmark Ops — AdmissionReview 응답 audit/warning 보강, 만료 예외 자동 표기, kube-bench Job manifest 생성 API/UI | ✅ (v0.9.101) |
| Security Operator Correlation Plus — 원본 scanner JSON 직접 업로드, Trivy Operator VulnerabilityReport import 맥락 보정, 스캔 신선도/stale 요약, 런타임 이벤트↔취약 이미지 digest 상관분석, Admission decision 우선순위 보강 | ✅ (v0.9.100) |
| Security Vulnerability Foundation — Trivy/Grype import, digest 기준 CVE 원장, SBOM 업로드, Admission 이미지 정책 평가, Falco 런타임 이벤트, kube-bench CIS 결과, 만료형 예외 승인과 보안 하위 메뉴 7종 | ✅ (v0.9.99) |
| Pod 관리 센터 — 목록·상세·위험 Pod 자동 북마크·최근 접근·현재/previous 로그·로그 프리셋·마스킹 리포트·스냅샷·동일 workload 병합·증적 번들·Golden Pod Diff·Health Replay·조치 안전성·플레이북 | ✅ |
| Pod Health Score(0~100) + 문제 유형 자동 태깅(CrashLoop/OOM/ImagePull/Pending/ProbeFailing/RecentRestart 등) · Health 낮은 순 정렬 | ✅ |
| Restart Storm 탐지 — 같은 workload 다수 Pod의 **최근** 재시작/비정상 신호를 서비스 단위 장애로 묶어 경고(POD-RULE-06) · critical storm은 워크로드 incident 자동 생성 | ✅ |
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
| Security Exception Workflow — 런타임 보안 위험 예외 요청·승인·자동 만료(`/admin/k8s/security-exceptions`, CLU-NEXT-12) | ✅ (v0.9.33) |
| Image Promotion — 환경 간 digest 기반 이미지 승격 요청·승인(mutable 태그 거부, `/admin/k8s/image-promotions`, CLU-NEXT-13) | ✅ (v0.9.33) |
| Discovery 활성화 (Dynamic Target + MCP Candidate Activation) — 발견된 수집 대상·MCP 도구 후보를 클러스터별 활성화 allow-list로 큐레이션(enforcement는 후속, `/admin/k8s/discovery/activate`, CLU-NEXT-15·16) | ✅ (v0.9.34) |
| Workspace Template + Exposure/Observability Apply Bridge — 신규 Workspace 표준 매니페스트 생성 + 노출/관측 변경을 Stack Apply 승인 흐름으로 연결(`/admin/k8s/workspace-template`, CLU-NEXT-10·11·14) | ✅ (v0.9.35) |
| Build Job Center 관리 계층 — 빌드 정의 저장 + Dockerfile 보안 게이트된 실행 요청 lifecycle(실제 러너 실행은 후속, `/admin/k8s/build-definitions`·`/build-runs`, CLU-NEXT-03·05) | ✅ (v0.9.36) |
| 실행 브리지 (Extension 설치 · Node cordon) — install-plan→Stack Apply(SSA) / drain→Action Center cordon 등 기존 검증 executor로 연결(CLU-NEXT-06/07 브리지) | ✅ (v0.9.37) |
| Build Runner (Kaniko/BuildKit Job 생성 + Stack Apply 실행) — 빌드 정의에서 인클러스터 빌드 Job 매니페스트 생성 후 기존 Stack Apply(SSA)로 실행(별도 executor 불필요, `/admin/k8s/build-runs`, CLU-NEXT-04/05) | ✅ (v0.9.38) |
| Pod Restart Recency 보정 — `restartCount` 누적값은 표시용으로 유지하고 컨테이너 `startedAt`/현재 상태 기반 `recent_restart_count`·`restart_signal`로 알람·Health·Storm을 판단 | ✅ (v0.9.39) |
| Action Center 가시성 + 역할별 개발자 요청 처리 — 액션 승인함 상단 노출, 개발자 뷰 `request`/`approve`/`execute` 모드, super_admin/admin 즉시 승인·실행, legacy `pending_approval` 호환 | ✅ (v0.9.40) |
| Manifest Change Studio — live YAML 편집 요청, before/after diff·impact, schema/policy/server dry-run 검증, 승인 게이트, Server-Side Apply, burst 수집, 사후 검증, 롤백 요청, evidence/git patch export | ✅ (v0.9.41) |
| Manifest Change Drift Guard + Approval Brief — 적용 직전 live manifest hash/UID drift 차단, force_drift 감사, 승인자 브리핑(`/brief`) | ✅ (v0.9.42) |
| Action Flow Navigator — Action/Config/YAML/Exec/Debug 요청을 다음 행동 레인(확인 필요·승인 대기·실행 가능·검증 필요·준비/검증·완료)으로 집계해 액션 승인함 상단에 표시 | ✅ (v0.9.43) |
| Node & GPU Operations — 60초 CPU/Memory 실사용·추세·장애 선행 경보, GPU/MIG/DCGM 워크로드·낭비·VRAM·XID/ECC/NVLink·비용, 승인형 격리, YAML/타임라인/그래프 딥링크 | ✅ (v0.9.48) |
| Manifest Change Studio 대상 확장 — ConfigMap, Secret, ServiceAccount 지원 및 UI 자동완성/정렬 보강 | ✅ (v0.9.45) |
| Enterprise Operations Hubs — Enterprise Foundation, FleetOps, SecOps, AIOps, FinOps, AI Gateway Governance, GitOps overview API/UI + 전역 빠른 이동·최근/자주 쓰는 메뉴·상황별 액션 바 | ✅ (v0.9.46) |
| Enterprise Enforcement Plus — Access Binding 전역 enforcement middleware, tenant/scope envelope, enterprise evidence ledger, Governance Hub, FleetOps/SecOps/AIOps/FinOps/GitOps 상세 API 확장. AI Gateway 신규 확장은 제외하고 기존 overview만 유지 | ✅ (v0.9.47) |
| Enterprise Operations UI Plus — Enterprise enforcement/ownership coverage, 서비스 카탈로그 운영 진입점·runtime 상세·runtime 후보 등록·coverage·gap queue·gap exception·scorecard·셀프서비스 액션 초안, Governance Hub gap exception debt/audit/report, FleetOps global search catalog enrichment/cluster compare/blast radius/action dry-run/progressive action, 액션 승인함 nav 배지, 빠른 이동 고정/최근/자주 사용/처리 대기 큐(Action/Config/YAML 상태 변경과 Dev/Node/Exec/Debug 요청 생성 시 즉시 캐시 무효화)/고정 리소스/최근 리소스 UX와 Fleet 리소스 미리보기·직접 진입 자동 기록·리소스 작업 카드·상단 현재 리소스 고정/해제(Pod 상세·카탈로그·YAML·타임라인·그래프, Gateway 단축 진입 제외), Action Center·YAML 변경·Config 변경·Catalog·Node 조치 toast 피드백, SecOps admission simulator/exception, AIOps problem detail/runbook/postmortem, FinOps/GitOps 상세 ledger를 화면에 연결. AI Gateway 신규 확장은 제외 | ✅ (v0.9.48) |
| Operator Path UX Refinement — 모든 화면 상단 빠른 작업에 현재 링크 복사, 헤더 링크 복사 버튼, 빠른 이동 처리 대기 큐 수동 새로고침을 추가해 승인·YAML·Pod·노드 화면을 공유하고 대기 상태를 즉시 재조회할 수 있게 개선 | ✅ (v0.9.49) |
| Action Flow CTA Clarity — 액션 승인함과 빠른 이동 처리 대기 큐의 CTA를 `승인 화면으로 이동`, `실행 화면으로 이동`, `검증 화면으로 이동`처럼 실제 작업과 화면 이동을 구분해 표시하고, Action/Config/YAML/Exec/Debug 요청으로 이동 시 `focus_id`로 대상 행 자동 스크롤·하이라이트, 새 요청 생성 직후 대상 요청 바로가기, 작업 ID·대상 복사 버튼을 제공 | ✅ (v0.9.50) |
| Action Flow SLA Visibility — Action/Config/YAML/Exec/Debug 요청에 대기 시간과 SLA 상태(`ok`/`warning`/`breached`)를 계산해 API summary·액션 승인함 KPI·흐름판 카드·빠른 이동 처리 대기 큐에 표시하고, 오래 방치된 승인/실행/검증 대기를 같은 레인 안에서 우선 노출 | ✅ (v0.9.51) |
| Action Flow Actor Guidance — 요청 레인·위험도·요청 유형 기준으로 다음 담당(`requester`, `approver/operator`, `operator/admin`, `security/admin`)과 담당 사유를 계산해 API·액션 흐름판·빠른 이동 처리 대기 큐에 표시 | ✅ (v0.9.52) |
| Action Flow Handoff Text — 각 운영 작업에 표준 인계 문구(`handoff_text`)를 생성하고 액션 흐름판 복사 버튼으로 작업·대상·위험도·다음 단계·다음 담당·SLA·처리 화면을 바로 공유 | ✅ (v0.9.53) |
| Quick Access Handoff Copy — 빠른 이동 패널의 처리 대기 큐에서 대상 화면으로 이동하지 않고도 각 작업의 표준 인계 문구를 즉시 복사 | ✅ (v0.9.54) |
| Action Flow Handoff Summary — 액션 승인함에서 SLA 초과·승인·실행·검증 대기 작업을 우선순위대로 묶은 운영 인계 요약을 한 번에 복사 | ✅ (v0.9.55) |
| Quick Access Handoff Summary — 빠른 이동 패널의 처리 대기 큐에서도 전체 운영 인계 요약을 즉시 복사 | ✅ (v0.9.56) |
| Action Flow Role Filters — 액션 승인함 흐름판을 전체·내 역할·SLA·승인·실행·검증·확인 필요 관점으로 즉시 필터링 | ✅ (v0.9.57) |
| Action Flow Filtered Handoff — 필터링된 현재 관점만 별도 인계 요약으로 복사하고 전체 요약과 명확히 구분 | ✅ (v0.9.58) |
| Action Flow Table Sync — 흐름판 필터를 Action 요청 표에도 동일하게 적용하고 클러스터 변경 시 필터 상태를 유지 | ✅ (v0.9.59) |
| Quick Access My Queue — 빠른 이동 처리 대기 큐를 내 역할 작업 우선으로 정렬하고 내 역할·SLA·전체 큐 진입 링크 제공 | ✅ (v0.9.60) |
| Action Flow Filter Persistence — 액션 승인함 마지막 필터 관점을 브라우저에 저장하고 URL 쿼리가 없을 때 자동 복원 | ✅ (v0.9.61) |
| Action Badge My Work — 상단 액션 승인함 배지가 내 역할 처리 대기 건수를 우선 표시하고 전체/레인별 건수를 tooltip에 제공 | ✅ (v0.9.62) |
| Action Badge Deep Link — 상단 액션 승인함 배지 클릭 시 내 역할 또는 SLA 지연 큐로 바로 진입 | ✅ (v0.9.63) |
| Action Flow Filter Counts — 액션 승인함 필터 버튼에 전체·내 역할·SLA·승인·실행·검증·확인 필요 건수를 직접 표시 | ✅ (v0.9.64) |
| Action Flow Empty Recovery — 현재 필터 결과가 0건일 때 전체·내 역할·SLA 큐로 즉시 전환하는 복구 링크 제공 | ✅ (v0.9.65) |
| Action Flow Shareable Filter — 저장된 선호 필터가 복원될 때 URL에도 `flow=`를 반영해 현재 링크 공유 시 같은 관점 유지 | ✅ (v0.9.66) |
| Action Flow First Item CTA — 현재 필터의 첫 처리 대상 화면으로 바로 이동하는 `첫 작업 열기` 제공 | ✅ (v0.9.67) |
| Quick Access First Work CTA — 빠른 이동 처리 대기 큐에서 내 역할·SLA 우선순위 첫 작업으로 즉시 이동 | ✅ (v0.9.68) |
| Action Flow Priority Brief — 액션 승인함과 빠른 이동 큐에 우선 처리 대상의 제목·대상·담당·SLA 요약 표시 | ✅ (v0.9.69) |
| Action Flow Priority Reason — 우선 처리 브리프에 내 역할 대상·SLA 초과/임박·확인/승인/실행/검증 필요 근거 표시 | ✅ (v0.9.70) |
| Action Flow Handoff Priority Reason — 개별/전체/필터 인계 문구에 우선 사유를 포함해 공유 시 처리 우선순위 근거 전달 | ✅ (v0.9.71) |
| Action Flow Role Match Explain — 액션 승인함과 빠른 이동 큐에 현재 역할과 `내 역할` 매칭 기준 설명을 표시해 승인/실행 담당 판단 혼동 완화 | ✅ (v0.9.72) |
| Action Flow My Work Badge — 액션 흐름판 카드에 `내 역할` 배지와 배경 강조를 추가해 전체/SLA 관점에서도 자기 담당 작업 즉시 식별 | ✅ (v0.9.73) |
| Action Flow Priority Ordering — 빠른 이동 큐와 액션 승인함 카드·첫 작업·필터 인계 요약을 동일한 `내 역할 → SLA → 레인` 기준으로 정렬 | ✅ (v0.9.74) |
| Action Flow Lane Quick Entry — 각 레인 헤더에서 해당 레인의 첫 처리 대상 화면으로 바로 이동하는 `첫 작업` CTA 제공 | ✅ (v0.9.75) |
| Action Flow Lane Handoff Copy — 각 레인 헤더에서 해당 단계 작업만 묶은 인계 요약을 즉시 복사 | ✅ (v0.9.76) |
| Action Flow Lane Filter Entry — 각 레인 헤더에서 해당 단계만 보는 `레인 보기` 필터 전환 제공 | ✅ (v0.9.77) |
| Action Flow Filter Label Clarity — 현재 관점 표시와 필터 인계 요약 제목을 내부 값 대신 한국어 단계명으로 통일 | ✅ (v0.9.78) |
| Action Flow Refresh Context — Action Flow API `generated_at`과 액션 승인함 `마지막 갱신`·`새로고침` 제공 | ✅ (v0.9.79) |
| Action Flow Refresh Feedback — 액션 승인함 새로고침 버튼에 busy 상태와 성공/실패 toast notice 제공 | ✅ (v0.9.80) |
| Action Flow Inline Refresh Notice — 액션 승인함 새로고침/승인/실행 결과 notice를 toast와 본문 슬롯에 즉시 표시 | ✅ (v0.9.81) |
| Action Flow Post-Action Next Step — 승인/반려/실행/승인+실행 완료 notice에 다음 확인 단계 안내 포함 | ✅ (v0.9.82) |
| Action Flow Notice Queue Links — 액션 결과 notice에 실행 큐·검증 큐·전체 보기 후속 이동 버튼 제공 | ✅ (v0.9.83) |
| Action Flow Dismissible Notice — 액션 승인함 본문 notice에 `닫기` 버튼을 추가해 처리 후 화면 정리 가능 | ✅ (v0.9.84) |
| Action Flow Notice Target Focus — 액션 결과 notice의 후속 큐 링크에 `focus_id`를 포함해 방금 처리한 요청 행 자동 강조 | ✅ (v0.9.85) |
| Action Flow Done Queue Entry — 실행 완료 Action의 후속 링크를 `완료 보기`로 보정하고 흐름판 필터에 `완료` 관점 추가 | ✅ (v0.9.86) |
| Action Flow Done Count Visibility — 액션 승인함 KPI와 인계 요약에 `완료` 건수 표시 | ✅ (v0.9.87) |
| Action Flow Focused Lane Board — 승인/실행/검증/완료 등 레인 필터 선택 시 해당 레인만 표시해 빈 레인 노이즈 제거 | ✅ (v0.9.88) |
| Action Flow Table Priority Sync — 액션 요청 표 정렬을 흐름판 우선순위와 동기화해 카드와 표의 첫 처리 대상 일치 | ✅ (v0.9.89) |
| Action Flow Table Context Column — 액션 요청 표에 흐름 레인·SLA·다음 담당·우선 사유 컬럼 추가 | ✅ (v0.9.90) |
| Action Flow Table Handoff Copy — 액션 요청 표의 흐름 컬럼에서 표준 인계 문구 즉시 복사 | ✅ (v0.9.91) |
| Action Flow Table Target Link — 액션 요청 표의 흐름 컬럼에서 대상 처리 화면으로 즉시 이동 | ✅ (v0.9.92) |
| Action Flow Table Batch Tools — 액션 요청 표 상단에서 첫 행 처리와 현재 표 인계 요약 복사 제공 | ✅ (v0.9.93) |
| Contract Audit & Runtime Hardening — API surface audit가 `cmd/clustara-cli/main.go`와 `sdk/typescript/clustara.ts` 실제 경로를 필수로 읽고 누락 시 실패하며, CLI/SDK 경로 불일치와 OpenAPI 누락·낡은 문서 경로를 모두 hard fail로 검증, 누락됐던 K8s/Agent/MCP Tool Scope/Mattermost 라우트를 OpenAPI 카탈로그에 보강하고 `go test`에서 repository zero-gap을 강제, README/Docker/CLI/SDK 기본 포트를 `:9090`으로 정렬하고 release test로 포트 정합성을 강제, production/strict 모드 기본 `GATEWAY_SECRET`·약한 admin token·열린 admin API 기동을 차단, HTTP read/write/idle/header timeout 기본값을 적용, `/ready`에 database component와 `/admin/ops/status` 참조를 포함 | ✅ (v0.9.94) |
| Manifest Create Studio — YAML 변경 화면에 신규 리소스 생성 모드와 Deployment/Service/ConfigMap/Secret/ServiceAccount/RBAC/PVC/Ingress/NetworkPolicy/HPA/Namespace/Job/CronJob 템플릿을 추가하고, `operation=create` 요청을 같은 원장·검증·승인·SSA 적용 흐름으로 처리하며 이미 존재하는 대상은 요청/적용 단계에서 차단 | ✅ (v0.9.95) |
| Manifest Create Convenience — 생성 모드에서 프리셋 버튼, YAML 본문 대상 자동 추출, 입력/YAML 불일치 감지, inventory 기반 중복 대상 미리보기와 제출 전 차단, Secret payload 경고를 제공해 YAML 생성 요청의 실수를 줄임 | ✅ (v0.9.96) |
| Ops Agent Manifest Bridge — Ops Agent가 YAML 생성/변경 초안, 위험 리뷰, blocker/warning, 운영자 체크리스트를 만들고 사용자가 명시하면 기존 Manifest Change 원장에 draft 요청을 저장. 검증·승인·적용은 계속 Manifest Change Studio 상태머신에서만 진행 | ✅ (v0.9.97) |
| Ops Status v2 — `/admin/ops/status`에 DB, async logger, ClickHouse, K8s collector, Mattermost, retention, alert worker component 상태와 overall(degraded/failed) 제공 | ✅ (v0.9.47) |

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
| GET | `/admin/k8s/clusters/{id}` | 클러스터 상세 |
| POST | `/admin/k8s/clusters/{id}/group` | 클러스터의 그룹 멤버십 배정·변경·해제(`group_id` 빈 값이면 미분류) |
| GET/POST | `/admin/k8s/groups` | 클러스터 그룹 목록(롤업)/생성 |
| GET/POST/DELETE | `/admin/k8s/groups/{id}` | 클러스터 그룹 조회·수정·삭제(삭제 시 멤버 클러스터 `group_id` 자동 해제) |
| GET/POST | `/admin/k8s/ownership` | 네임스페이스 오너십(담당팀·담당자·서비스·중요도·비용센터) 조회/설정·수정 |
| DELETE | `/admin/k8s/ownership/{cluster_id}/{namespace}` | 네임스페이스 오너십 매핑 삭제 |
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
| GET/POST | `/admin/external-integrations/credentials` | 사용자별 외부연동 Credential 조회·등록. GitLab, Bitbucket Server, Harbor, Mattermost Token/Password를 암호화 저장하고 원문은 응답하지 않음 |
| GET/POST/DELETE | `/admin/external-integrations/credentials/{id}` | Credential 개별 조회·수정·삭제(archive). secret 미입력 수정은 기존 암호화 secret 유지, 입력 시 회전 |
| POST | `/admin/external-integrations/credentials/{id}/test` | 저장 Credential을 메모리에서만 복호화해 GitLab/Bitbucket/Harbor 연결 확인. secret 원문·암호문·hash 미응답 |
| GET/POST | `/admin/harbor/registries` | Harbor registry 원장 조회·등록. URL 정규화, insecure TLS 메타데이터, 연결 상태 저장 |
| GET/POST/DELETE | `/admin/harbor/registries/{id}` | Harbor registry 개별 조회·수정·삭제. 연결된 robot/mapping/launch history가 있으면 기본 삭제 차단, `force=true`에서 registry/robot/mapping 메타데이터 정리 |
| POST | `/admin/harbor/registries/{id}/test` | Harbor `/api/v2.0/systeminfo` 연결 테스트. mock/offline URL은 네트워크 없이 connected로 검증 |
| GET/POST | `/admin/harbor/robots` | Harbor Robot Account 메타데이터 등록. token은 일회성 입력 또는 `credential_id`로 받아 hash 증적만 저장, 응답에는 미노출 |
| GET/POST/DELETE | `/admin/harbor/robots/{id}` | Robot Account 개별 조회·수정·삭제. 수정 시 일회성 token 또는 저장 Credential로 hash 증적을 회전하고 검증 상태를 재등록 상태로 되돌림 |
| POST | `/admin/harbor/robots/verify` | 일회성 token 또는 `credential_id`로 project repository pull/list 권한 검증 후 `verified`/`failed` 상태 기록 |
| GET/POST | `/admin/harbor/mappings` | Harbor project와 cluster/namespace/imagePullSecret/owner team 매핑 |
| GET/POST/DELETE | `/admin/harbor/mappings/{id}` | Harbor project→namespace 매핑 개별 조회·수정·삭제 |
| POST | `/admin/harbor/catalog/query` | 일회성 robot token 또는 `credential_id`로 Harbor projects/repositories/artifacts(tags·digest 포함)를 조회. token은 응답하지 않음 |
| POST | `/admin/harbor/pull-secret/preview` | Robot 기반 imagePullSecret redacted YAML preview. 실제 `.dockerconfigjson` token은 Credential Vault에서 메모리 복호화하거나 요청 token으로만 사용하며 응답·감사 로그에 남기지 않음 |
| POST | `/admin/harbor/launches/preview` | Harbor 이미지 기준 Deployment/Service YAML과 digest/latest/robot 만료 정책 판정 preview |
| GET/POST | `/admin/harbor/launches` | 앱 런칭 요청 원장 조회·생성. blocked/approval_required/allow 판정과 manifest preview 저장 |
| POST | `/admin/harbor/launches/{id}/manifest-change` | blocked가 아닌 런칭 요청의 Deployment/Service 문서를 Manifest Change Studio `operation=create` draft set으로 생성. 검증·승인·적용은 기존 YAML 변경/생성 원장에서만 진행 |
| GET | `/admin/k8s/config-impact?kind=&namespace=&name=` | ConfigMap/Secret 변경 영향: 참조 워크로드(env/envFrom/volume) + 재시작 필요 여부 |
| GET/POST | `/admin/k8s/config-changes` | ConfigMap/Secret 변경 요청 목록/생성. 생성 시 Config Impact 스냅샷 자동 첨부, Secret 또는 영향 workload가 있으면 승인 필요 |
| GET | `/admin/k8s/config-changes/{id}` | 변경 요청 상세: 승인/적용/검증 상태, 영향 workload, 검증 이력 |
| POST | `/admin/k8s/config-changes/{id}/approve`, `/reject`, `/apply`, `/verify` | 변경 요청 승인/반려, 외부/GitOps 적용 기록, 사후 검증. Secret 원문 payload는 저장하지 않음 |
| GET | `/admin/k8s/pods` | Pod 관리 목록: 클러스터·namespace·node·owner·status·risk·검색 필터, 누적 restart와 최근 restart 신호(`recent_restart_count`, `restart_signal`)·warning 요약 |
| GET | `/admin/k8s/pods/{namespace}/{pod}` | Pod 상세: 상태, 컨테이너 상태(`started_at`, `restart_signal`), 관련 이벤트, Pod 메트릭, 로그 감사, 마스킹 manifest |
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
| GET | `/admin/k8s/manifests/editor` | Manifest Change Studio 리소스 picker metadata: 클러스터, 인벤토리 리소스, kind 목록 |
| GET | `/admin/k8s/manifests/live` | YAML 변경용 live manifest 조회 alias. Secret/token/env 민감값 자동 마스킹 |
| GET/POST | `/admin/k8s/manifest-changes` | 단일 리소스 YAML 변경/생성 요청 목록/생성. 신규 리소스는 body에 `operation=create`를 지정하며 before YAML은 비워두고 after YAML 전체를 생성 후보로 저장. before/after YAML, field diff, impact, 위험도, target UID/resourceVersion을 원장에 저장 |
| GET | `/admin/k8s/manifest-changes/{id}` | YAML 변경/생성 요청 상세: operation, diff, impact, validation, apply, verify 결과 |
| GET | `/admin/k8s/manifest-changes/{id}/brief` | 승인자 브리핑: 위험도 분포, 상위 diff, approval reasons, dry-run/policy/drift 상태, 다음 액션, 운영자 체크리스트 |
| POST | `/admin/k8s/manifest-changes/{id}/validate` | schema basic check, 정책 검사, server dry-run(`dryRun=All`) 검증. Secret payload 원문 변경은 blocked 처리 |
| POST | `/admin/k8s/manifest-changes/{id}/approve`, `/reject`, `/apply`, `/verify`, `/rollback` | 승인/반려, 적용 직전 drift guard 통과 후 Server-Side Apply 실행, burst 수집 후 사후 검증, 이전 YAML 기반 롤백 요청 생성. 생성 요청은 대상이 이미 존재하면 적용을 차단하고, 의도한 덮어쓰기는 기존 변경 요청으로 재생성해야 함. 변경 요청의 의도한 덮어쓰기는 `apply` body에 `force_drift=true`와 `note`를 남김 |
| GET | `/admin/k8s/manifest-changes/{id}/evidence`, `/git-patch` | 변경/생성 증적 Markdown bundle과 Git PR용 pseudo patch export |
| POST | `/admin/agent/manifest-drafts` | Ops Agent 기반 YAML 생성/변경 초안 작성과 Manifest Change 원장 연결. `create_request=true`일 때만 draft 요청을 저장하며, 검증·승인·적용은 수행하지 않음 |
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
| GET | `/admin/k8s/security/vuln/summary` | 이미지 취약점, 예외, 런타임 이벤트, CIS 결과 요약 |
| GET | `/admin/k8s/security/vuln/images` | digest·namespace·severity·fixable 기준 이미지 취약점 목록 |
| GET | `/admin/k8s/security/vuln/workloads` | 실행 워크로드 기준 취약 이미지 영향도 집계 |
| GET/POST | `/admin/k8s/security/scans` | 외부 scanner/agent runner가 처리할 스캔 작업 등록 및 이력 조회 |
| POST | `/admin/k8s/security/scans/import` | 래퍼 JSON 또는 원본 Trivy/Grype/Trivy Operator JSON 결과를 표준 취약점 원장으로 import |
| GET/POST | `/admin/k8s/security/sboms` | 래퍼 JSON 또는 원본 CycloneDX/SPDX SBOM 업로드 및 digest별 SBOM 조회 |
| GET/POST | `/admin/k8s/security/exceptions` | 취약점·이미지·워크로드 예외 요청 생성 및 조회(만료일 필수) |
| POST | `/admin/k8s/security/exceptions/{id}/approve|revoke` | 보안 예외 승인 또는 폐기 |
| POST | `/admin/k8s/security/admission/evaluate` | YAML/image list에 대해 latest·digest·SBOM·Critical/High CVE 정책 평가 |
| POST | `/admin/k8s/security/admission/review` | AdmissionReview 호환 응답 생성(현재 admin/service token 보호 필요) |
| GET | `/admin/k8s/security/admission/decisions` | Admission 허용·경고·차단 결정 이력 |
| GET/POST | `/admin/k8s/security/runtime/events` | Falco/Falcosidekick 런타임 이벤트 수집 및 조회 |
| GET/POST | `/admin/k8s/security/benchmarks/job-manifest` | kube-bench 실행용 Kubernetes Job YAML 생성(서버는 직접 실행하지 않음) |
| GET/POST | `/admin/k8s/security/benchmarks/runs` | kube-bench JSON 결과 import 및 실행 이력 조회 |
| GET | `/admin/k8s/security/benchmarks/results` | kube-bench control별 상세 결과 조회 |
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
| GET | `/admin/k8s/action-flow` | Action/Config/YAML/Exec/Debug 요청을 사용자 다음 행동 기준으로 집계. `?cluster_id=&limit=`. 응답은 `lanes`, `items`, `summary`와 원래 처리 화면 href를 포함 |
| POST | `/admin/k8s/latency/collect` | 런타임 설정의 Prometheus에서 워크로드 latency 수집·적재 (RCA-10 latency) |
| GET/POST | `/admin/k8s/latency/config` | latency PromQL + 라벨 매핑(namespace/workload) 설정 |
| GET | `/admin/k8s/connectivity` | Service selector↔Pod endpoint, Ingress backend/host/TLS, PVC Pending 점검 |
| GET/POST | `/admin/k8s/actions` | 액션 요청 목록/생성. 생성 시 `idempotency_key`, `target_uid`, `target_resource_version`, `command_hash` 저장 |
| POST | `/admin/k8s/actions/{id}/approve` | 액션 승인 (요청 생성 시 영향도 자동 산출 → dry_run_diff, blocker 시 승인 강제). 허용 전이: `pending|approval_required|pending_approval -> approved` |
| POST | `/admin/k8s/actions/{id}/reject` | 액션 반려 |
| GET/POST | `/admin/k8s/dev-requests` | 개발자 뷰 요청 생성. `mode=request|approve|execute`로 역할별 승인/즉시 실행 흐름 선택 |

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

### Node/GPU 실사용 모니터링

`metrics.k8s.io` Node 수집은 인벤토리 reconcile과 분리되어 기본 60초 주기로 동작합니다. 관리자 **설정 → 런타임 설정 → `k8s.monitoring`**에서 `enabled`, `interval_seconds`, `retention_days`를 재시작 없이 조정할 수 있습니다. Metrics Server 미설치 또는 RBAC 거부는 사용률 0%로 처리하지 않고 `미수집`으로 표시합니다. 보존기간을 지난 Node/GPU 표본은 6시간마다 정리됩니다.

GPU 할당 현황은 Node의 `nvidia.com/gpu`·`amd.com/gpu`·`intel.com/gpu` allocatable과 Pod request로 항상 계산합니다. 실제 H100/H200/L40S 장치 관측에는 Prometheus와 NVIDIA DCGM Exporter가 필요합니다.

1. DCGM Exporter를 GPU 노드 DaemonSet으로 설치합니다.
2. 런타임 설정의 `dcgm_counters_csv` 또는 `deploy/k8s/dcgm-exporter-counters.csv`를 collector 파일로 마운트합니다.
3. `-k` 또는 `DCGM_EXPORTER_KUBERNETES=true`로 Kubernetes Pod 매핑을 활성화합니다.
4. `k8s.monitoring.prometheus_url`(선택: `prometheus_token`)을 저장합니다. 기존 `PROMETHEUS_URL`/`PROMETHEUS_TOKEN`은 DB 설정이 없을 때의 환경변수 기본값입니다.

설정 화면의 **입력값으로 GPU/DCGM 검증**은 저장하지 않은 입력값으로도 CSV 형식·필수 counter, Prometheus 인증/PromQL, instant vector 표본 수, Node 수와 실제 관측 metric을 점검합니다. CSV가 유효하고 고급 `dcgm_metrics_promql`이 비어 있으면 Clustara가 CSV metric 목록으로 PromQL selector를 생성합니다. **DCGM ConfigMap 미리보기**는 유효성·SHA-256과 apply-ready YAML을 제공하지만 실제 클러스터 반영은 운영자가 검토 후 수행합니다.

MIG는 DCGM의 `GPU_I_PROFILE`, `GPU_I_ID` 라벨을 그대로 보존합니다. XID/ECC/NVLink/과열 신호는 Kubernetes Warning Event로 변환되어 기존 알림·타임라인·RCA 흐름으로 들어갑니다. 중대한 오류의 UI는 cordon 승인 요청과 drain 영향 분석만 연결하며 자동 격리는 수행하지 않습니다.

GPU Operations API는 `GET /admin/k8s/gpu/operations?cluster_id=&window=6h`, 정책 API는 `GET/POST /admin/k8s/gpu/policy`입니다. DCGM 진단/ConfigMap API는 `GET /admin/k8s/gpu/dcgm-config`, 화면 입력값 연결 테스트는 `POST /admin/settings/test/k8s-monitoring`입니다. 장치 시계열은 `k8s_gpu_samples`에 보존되고 Collection Cost Guard의 metric 행 수에 포함됩니다.

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

## 리소스 카테고리 센터

`리소스 관리` 메뉴는 Pod 상세 진단 화면과 별도로 전체 Kubernetes 리소스를 운영 도메인별로 나눠 탐색합니다. `리소스 전체`는 카테고리별 자산 수와 high 이상 위험 리소스를 요약하고, 각 카테고리 화면은 같은 `/admin/k8s/inventory` 원천 데이터를 필터링해 상태, Kind, namespace, cluster, spec 요약, 최근 관측 시각, YAML 변경, 타임라인, 리소스 그래프 진입점을 제공합니다.

| 화면 | 포함 리소스 예시 | 주요 동선 |
| --- | --- | --- |
| 워크로드 | Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Pod | YAML 변경/생성, Pod 상세, 타임라인, 리소스 그래프 |
| 네트워크 | Service, Ingress, NetworkPolicy, Endpoints, EndpointSlice, Gateway API | 연결성 점검, 노출 영향 확인, YAML 변경 |
| 스토리지 | PV, PVC, StorageClass, VolumeSnapshot | 바인딩·용량 요약, PVC 생성, YAML 변경 |
| 구성요소 | Namespace, ConfigMap, Secret, HPA, PDB, Quota, LimitRange | 설정 변경 영향, 자동확장·중단예산 확인 |
| 개발자 도구 | ServiceMonitor, PodMonitor, PrometheusRule, HelmRelease, Kustomization, Certificate, Tekton | 플랫폼 확장 리소스와 GitOps/관측 도구 탐색 |
| 인증·권한 | ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding, CSR | RBAC 변경 검토, 권한 리소스 YAML 변경 |

카테고리별 `+ Kind` 버튼은 Manifest Change Studio의 `mode=create` 흐름으로 연결됩니다. 생성과 변경은 모두 요청 원장, 검증, 승인, Server-Side Apply, 사후 검증을 거치며 직접 적용하지 않습니다.

## GitOps Change Manager

`#/gitops`는 외부 CD 엔진을 대체하는 sync 화면이 아니라, Clustara의 Application Stack과 live cluster 상태를 Git 선언·PR 초안·단계적 rollout·rollback 증적으로 연결하는 변경관리 허브입니다. 자세한 사용 순서는 [GitOps Change Manager 가이드](GITOPS_CHANGE_MANAGER.md)를 참고하세요.

사내 오프라인망에서는 먼저 `외부연동` 메뉴에서 GitLab 또는 Bitbucket Server 6.x Token/Password를 사용자별 Credential로 저장합니다. GitOps 화면의 `사내 Git Provider 연동` 카드는 provider URL, 종류, 기본 project/repo 같은 metadata를 저장하고, secret은 저장 Credential(`credential_id`)을 선택해 재사용하거나 필요한 경우 일회성 token으로만 전달합니다. 연결 확인과 catalog 조회는 저장 Credential 또는 일회성 token으로 GitLab project/repository/branch/tree/file 또는 Bitbucket project/repo/branch/browse/raw 목록을 불러와 Git Source 입력폼에 바로 채울 수 있습니다.

| 흐름 | 설명 |
| --- | --- |
| Stack → Git Source | Stack 또는 서비스에 repo, branch, path를 연결해 Git 기준점을 기록합니다. |
| Drift 검토 | `live_only`, `spec_diff`, `in_sync` 분류와 위험도, 권장 행동을 확인합니다. |
| PR Draft | live hotfix를 Git에 반영할지, Git 선언을 클러스터에 적용할지 초안 원장으로 남깁니다. |
| Progressive Rollout | dev, qa, canary, prod 같은 단계와 gate를 저장해 운영 배포를 한 번에 밀지 않습니다. |
| Evidence/Rollback | apply history, evidence id, 이전 revision을 묶어 인계와 사후 복구에 사용합니다. |

GitOps 화면의 빠른 등록 폼은 원장과 계획을 저장합니다. 실제 Kubernetes 변경은 Stack Apply 또는 YAML 변경/생성의 검증·승인·Server-Side Apply 흐름으로만 진행합니다.

| API | 설명 |
| --- | --- |
| `GET/POST /admin/gitops/providers` | GitLab·Bitbucket Server provider metadata 조회·등록 |
| `GET/POST/DELETE /admin/gitops/providers/{id}` | provider 상세 조회·수정·비활성화 |
| `POST /admin/gitops/providers/test` | 저장 Credential 또는 일회성 token으로 provider 연결 확인 |
| `POST /admin/gitops/providers/catalog` | 저장 Credential 또는 일회성 token으로 projects, repositories, branches, tree, file catalog 조회 |
| `POST /admin/gitops/providers/pr-template` | GitLab Merge Request 또는 Bitbucket Server Pull Request API payload preview 생성. 외부 Git에는 쓰지 않음 |

## Pod 관리와 증적 번들

`Pod 관리` 화면은 수집된 Pod 인벤토리 위에서 목록·상세·로그·조치 안전성·디버그 요청을 제공합니다. 목록에서는 클러스터, namespace, node, owner, status, risk, 검색어로 필터링하고 CrashLoop/OOM/ImagePull/Pending/Evicted 계열 Pod를 위험 Pod로 강조합니다. Kubernetes의 `restartCount`는 Pod 생애 누적값이므로 알람성 판단에는 그대로 쓰지 않고, 컨테이너 `state.running.startedAt`, 현재 waiting/terminated 상태, CrashLoop/OOM/ImagePull 사유를 결합해 최근 restart 신호를 산출합니다. 위험 Pod, 최근 restart 신호가 있는 Pod, 최근 Warning 이벤트가 붙은 Pod는 `system:auto` 북마크로 자동 고정되며, 상세·로그·exec·debug 접근은 최근 이력에 남아 운영자가 보던 흐름으로 바로 돌아갈 수 있습니다.

상세에서는 ready, 누적 restart, 최근 restart 신호(recent/historical/unknown/none), 마지막 컨테이너 startedAt, node, owner, QoS, Pod IP, 컨테이너별 상태, 관련 이벤트, 최근 메트릭, 최근 로그 감사, 마스킹 manifest를 확인합니다. 현재 컨테이너가 1시간 이상 Running/Ready이고 startedAt 변화가 없으면 과거 restart로 보정되어 Health/Restart Storm/Resource Advisor 알람에서 제외됩니다. `Golden Pod Diff`는 같은 owner 또는 label workload 안에서 Running/Ready 상태가 좋고 최근 restart/warning이 적은 Pod를 자동 기준으로 골라 장애 Pod와 비교합니다. `Pod Health Replay`는 상태 스냅샷, 컨테이너 상태, 이벤트, 메트릭, 리비전, 로그 조회 감사, RCA 후보를 하나의 시간축으로 묶어 장애 흐름을 재생합니다. `조치 안전성`은 delete/evict/restart/scale/debug 전에 owner 존재 여부, replica 여유, HPA, 최근 Warning 이벤트, 최근 restart 신호를 함께 계산하고, `플레이북`은 Pod 상태와 이벤트에 맞는 확인·조치 순서를 제안합니다.

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

`delete_pod`, `cordon`, `scale`, `rollout_restart` 같은 위험 액션은 기본적으로 승인 대기 상태가 됩니다. 승인된 `scale`/`rollout_restart`/`cordon`/`uncordon`/`delete_pod`는 실클러스터 executor로 실행됩니다. 단일 리소스 YAML 적용은 Action Center의 임의 `apply_manifest` 액션이 아니라 **Manifest Change Studio**의 요청·검증·승인·Server-Side Apply 원장으로 처리하며, `drain`은 별도 안전성 검증 후속 범위로 남겨둡니다.
