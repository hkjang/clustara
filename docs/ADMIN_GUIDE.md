# 관리자 가이드 (Admin Guide)

Clustara(Kubernetes 운영 허브) 어드민 UI(`http://<host>:9090/admin`)의 메뉴별 사용법입니다. 모든 화면은 동일한 이름의 REST API(`/admin/k8s/*`)로도 자동화할 수 있습니다. API 상세·클러스터 등록은 **[K8s 운영 허브 가이드](K8S_OPERATIONS_HUB.md)** 를 참고하세요.

## 접속과 권한

- UI 상단 "관리자 토큰" 입력란에 `ADMIN_TOKEN` 값을 넣으면 데이터가 로드됩니다.
- 메뉴는 스코프로 게이팅됩니다: K8s 운영 메뉴는 `admin:read`, 보안/정책 센터는 `security:read`.
- 기본 랜딩은 **운영 홈**(`#/k8s-home`). SSO/역할 사용 시 `security_admin`은 보안 화면으로 랜딩.

## 메뉴 구성

운영(운영 홈·클러스터·수집 상태·Pod 관리·변경 타임라인·장애 분석·장애 워룸·리소스 그래프·연결성 점검·액션 승인함·용량·자동확장·그룹·오너십·AI 분석·리포트 센터·SLO 센터) · 비용 · 보안 · 정책 센터 · 운영 설정 · 설정.

---

## 1. 운영 홈 (`#/k8s-home`)

전 클러스터를 가로질러 **클러스터 위험 TOP5 · 장애 후보 TOP10 · 최근 변경 TOP10 · 비용 TOP10**을 한 화면에 모읍니다. 각 항목에서 해당 리소스의 변경 타임라인/Diff로 딥링크됩니다. 하루 운영을 여기서 시작하세요.

- 위험 점수 = (RCA high/critical ×3) + (위험 인벤토리 수) + (error 상태 클러스터 ×5)
- API: `GET /admin/k8s/home`

## 2. 클러스터 (`#/k8s`)

클러스터 등록/목록, 연결 테스트, 수집을 수행합니다.

- **등록**: 이름·API Server URL·인증 방식(kubeconfig/token/service_account/in_cluster)·credential. kubeconfig/token은 `GATEWAY_SECRET`으로 AES-GCM 암호화 저장(응답에 원문 미노출).
- **연결 테스트**: 버전·노드 수·네임스페이스 수 갱신.
- **수집**: 인벤토리(spec+status)·이벤트·메트릭을 저장. 인벤토리 행의 **이력·Diff** 링크로 타임라인 이동.
- minikube(개발 PC)·운영 클러스터 등록 절차(전용 ServiceAccount·읽기 전용 ClusterRole)는 [K8s 운영 허브 가이드](K8S_OPERATIONS_HUB.md#클러스터-등록).
- API: `GET/POST /admin/k8s/clusters`, `POST /admin/k8s/clusters/{id}/test|collect`

## 3. 수집 상태 (`#/k8s-collector`)

실시간 Collector Agent의 heartbeat와 watch 상태를 확인합니다.

- 표시 항목: agent live/stale, 마지막 heartbeat, watch lag, 마지막 resourceVersion, 수신 이벤트 수, 재연결 횟수, 최근 오류.
- resourceVersion checkpoint와 최근 watch 이벤트 원장을 함께 보여주므로 agent 재시작 복구·중복 재전송 여부를 확인할 수 있습니다.
- agent 설치는 [K8s Agent 가이드](K8S_AGENT.md)를 따릅니다. minikube는 `host.minikube.internal`, 운영망은 내부 HTTPS Clustara URL과 Secret 기반 토큰 주입을 권장합니다.
- agent 미배포 시에도 주기 수집(`collect`)과 snapshot 적재는 계속 폴백으로 사용할 수 있습니다.
- API: `POST /admin/k8s/agent/events`, `GET /admin/k8s/agent/status`

## 4. Pod 관리 (`#/k8s-pods`)

Pod 목록·상세·로그·로그 분석·증적 번들·Golden Pod Diff·Health Replay·조치 안전성·플레이북·정책 기반 exec 세션 요청·Debug Container 요청을 한 화면에서 확인합니다. CrashLoop/OOM/ImagePull/Pending/Evicted 계열 Pod, 최근 restart 신호가 있는 Pod, 최근 Warning 이벤트가 붙은 Pod를 빠르게 찾는 데 초점을 둡니다.

- **목록**: 클러스터, namespace, node, owner, status, risk, 검색어 필터. ready, 누적 restart, 최근 restart 신호, node, owner, warning 이벤트 수를 표시합니다. 위험 Pod는 자동 북마크로 고정되고, 사용자가 저장한 북마크와 최근 상세·로그·exec·debug 접근 이력을 함께 보여줍니다.
- **상세**: ready, phase, 누적 restart, 최근 restart 신호(recent/historical/unknown/none), 마지막 컨테이너 startedAt, Pod IP, QoS, owner, 컨테이너 상태, 관련 이벤트, 최근 메트릭, 최근 로그 감사, 마스킹 manifest.
- **로그**: container 선택, current/previous 로그, 실시간 tail, tail lines, since, 검색어, error-only 필터, 다운로드. 로그 프리셋, 마스킹 리포트, 장애 시점 스냅샷, 동일 workload 로그 병합을 제공하고 서버에서 민감값을 마스킹해 `k8s_pod_log_queries`와 관리자 감사 로그에 기록합니다.
- **로그 분석**: current/previous 로그에서 Exception, OOM, timeout, DNS, network, auth, probe, image pull 계열 패턴을 그룹핑하고 근거 라인과 조치 후보를 표시합니다.
- **증적 번들**: current/previous 로그, 이벤트, 메트릭, manifest, 리비전, RCA, 로그 감사를 ZIP으로 생성합니다.
- **Restart Recency 보정**: Kubernetes `restartCount`는 Pod 생애 누적값이라 오래전 기동 초기에만 재시작한 Pod도 숫자가 남습니다. Clustara는 컨테이너 `state.running.startedAt`, 현재 waiting/terminated 상태, CrashLoop/OOM/ImagePull 사유를 함께 봐 최근 restart 신호를 계산합니다. 현재 컨테이너가 1시간 이상 Running/Ready이면 누적 restart는 “과거 누적”으로 표시하고 Health/Restart Storm/Resource Advisor 알람에서 제외합니다.
- **Golden Pod Diff**: 같은 owner/label의 Running·Ready Pod를 자동 기준으로 골라 image, env 참조, resource, probe, volume, node, 누적/최근 restart 차이를 비교합니다. env/secret 값은 노출하지 않습니다.
- **Health Replay**: Pod 상태, 컨테이너 상태, 이벤트, 메트릭, 리비전, 로그 조회 감사, RCA 후보를 시간순으로 묶어 장애 전후 흐름을 확인합니다.
- **조치 안전성/플레이북**: delete pod, evict, owner restart, scale, debug 요청 전 replica 여유, owner/HPA, 최근 Warning, 최근 restart 신호를 점검하고 CrashLoop/OOM/ImagePull/Pending 유형별 대응 절차를 표시합니다.
- **터미널 요청**: container, role, command, reason을 Terminal Policy로 평가하고 세션 요청을 `ready`/`pending_approval`/`denied` 상태로 감사 기록합니다. 승인이 필요한 요청은 운영 설정의 Exec 세션 승인함에서 `ready` 또는 `rejected`로 결정하고, `ready` 세션은 단일 제한 명령으로 실행해 `completed` 또는 `failed`로 닫습니다. 세션 상세에서는 정책 결과, 요청·승인·실행 리플레이, 마스킹 출력 샘플을 확인하고 Markdown 감사 리포트로 내려받습니다. Risk Briefing과 명령 템플릿으로 접속 전 위험도를 확인할 수 있습니다.
- **Debug Container 요청**: catalog에 등록된 debug image만 선택하고 target container, template, 사유를 남깁니다. v0.8.0에서는 실제 주입 전 요청·승인·manifest preview·감사 이력을 우선 제공합니다.
- 운영망 전용 ServiceAccount는 `pods/log`의 `get` 권한이 필요합니다.
- API: `GET /admin/k8s/pods`, `GET /admin/k8s/pods/{namespace}/{pod}`, `GET /admin/k8s/pods/{namespace}/{pod}/logs`, `POST /admin/k8s/pods/{namespace}/{pod}/logs/analyze`, `GET /admin/k8s/pods/{namespace}/{pod}/logs/stream`, `GET /admin/k8s/pods/{namespace}/{pod}/logs/presets`, `POST /admin/k8s/pods/{namespace}/{pod}/logs/masking-report`, `POST /admin/k8s/pods/{namespace}/{pod}/logs/snapshot`, `GET /admin/k8s/pods/{namespace}/{pod}/logs/merge`, `POST /admin/k8s/pods/{namespace}/{pod}/evidence-bundle`, `GET /admin/k8s/pods/{namespace}/{pod}/golden-diff`, `GET /admin/k8s/pods/{namespace}/{pod}/health-replay`, `GET /admin/k8s/pods/{namespace}/{pod}/action-safety`, `GET /admin/k8s/pods/{namespace}/{pod}/runbook`, `POST /admin/k8s/pods/{namespace}/{pod}/exec/sessions`, `GET /admin/k8s/pods/{namespace}/{pod}/exec/briefing`, `GET/POST /admin/k8s/pods/{namespace}/{pod}/debug/sessions`, `GET /admin/k8s/exec/sessions/{id}`, `GET /admin/k8s/exec/sessions/{id}/export`

## 5. 변경 타임라인 (`#/k8s-timeline`)

리소스의 **spec 리비전·이벤트·액션**을 시간축으로 병합해 장애 전후 변화를 추적합니다.

- 필터(클러스터·namespace·이름·kind) 지정 시: 직전 **Resource Diff**(replica/image/env/resource limit/ingress host 하이라이트, 민감값 마스킹)와 **현재 Manifest**(YAML, Secret/token/env 마스킹)가 함께 표시됩니다.
- API: `GET /admin/k8s/timeline`, `/admin/k8s/diff`, `/admin/k8s/manifest`, `/admin/k8s/revisions`

## 6. 장애 분석 (`#/k8s-rca`)

규칙 기반 **원인 후보**를 심각도순으로 보여줍니다 — 원인·근거 이벤트·점검 대상·조치 후보 + 타임라인 딥링크.

- 탐지: CrashLoop/OOM/ImagePull/Pending/Unavailable, Readiness/Liveness probe, DNS, NodePressure(노드 condition), 직전 Config 변경 연계(24h), 배포 후 오류, Rollout 정체, Job/CronJob 실패.
- API: `GET /admin/k8s/rca`

## 7. 장애 워룸 (`#/k8s-incidents`)

현재 high/critical RCA 후보를 incident 단위로 묶고, 상세 화면에서 **RCA 근거·관련 이벤트·리비전·정책/보안 finding·관련 액션·영향도 그래프**를 한 번에 확인합니다.

- 화면 진입 시 현재 상태를 스캔해 열린 incident를 갱신합니다.
- 상세 화면의 **변경 타임라인·Diff**, **영향도 그래프**, **AI 설명**, **해결 처리** 버튼으로 대응 흐름을 이어갑니다.
- API: `GET/POST /admin/k8s/incidents`, `GET /admin/k8s/incidents/{id}`, `POST /admin/k8s/incidents/{id}/resolve`

## 8. 리소스 그래프 (`#/k8s-graph`)

최신 인벤토리에서 Service selector, Ingress backend, workload selector, Pod volume/node, HPA target 관계를 계산해 **서비스 영향 범위(blast radius)**를 보여줍니다.

- 필터: 클러스터·kind·namespace·name·반경(1~3 hop)
- 네임스페이스 오너십이 있으면 담당팀·서비스·중요도·비용센터가 영향도 요약에 함께 표시됩니다.
- API: `GET /admin/k8s/resource-graph`

## 9. 연결성 점검 (`#/k8s-conn`)

- **Service**: selector↔Pod 매칭 → endpoint 없음/selector 불일치
- **Ingress**: backend Service 존재·host 중복·TLS secretName 누락
- **PVC**: Pending + FailedMount/ProvisioningFailed 이벤트 연계
- API: `GET /admin/k8s/connectivity`

## 10. 액션 승인함 (`#/k8s-actions`)

위험 작업의 **요청 → 영향도 → 승인 → 실행** 워크플로우.

메뉴 위치는 상단 **액션 승인함** 바로가기 또는 **장애 및 대응 → 액션 승인함**입니다. 개발자 뷰에서 생성된 액션 요청도 이 화면에 모입니다.

- 요청 생성 시 영향도가 자동 산출되어 `dry_run_diff`에 기록되고, blocker(standalone Pod 삭제·drain·허용 외 patch 필드 등)가 있으면 자동으로 **승인 필수**로 격상됩니다.
- 요청에는 `idempotency_key`, `target_uid`, `target_resource_version`, `command_hash`가 저장됩니다. 같은 idempotency key로 재시도하면 기존 요청을 반환합니다.
- **승인**된 액션은 `approved -> running -> executed|failed` 전이만 허용되며 **실행** 버튼으로 실클러스터에 반영합니다: `scale`/`rollout_restart`/`cordon`/`uncordon`/`delete_pod`. 같은 승인 건의 중복 실행은 차단되고 drain은 수동입니다.
- 개발자 뷰 요청 생성은 `request`(승인 요청), `approve`(승인까지), `execute`(승인 후 즉시 실행) 모드를 지원합니다. `super_admin`/`admin`은 실행 가능한 작업을 즉시 실행할 수 있고, 개발자/조회자는 승인 요청만 생성합니다. `ops_admin`/`operator`/`approver`는 위험도에 따라 승인까지만 허용됩니다.
- 과거 개발자 뷰에서 생성된 `pending_approval` 액션도 호환 상태로 남아 있어 승인/반려할 수 있습니다.
- API: `GET/POST /admin/k8s/actions`, `POST /admin/k8s/actions/{id}/approve|reject|execute`

## 11. 용량·자동확장 (`#/k8s-capacity`)

- **HPA 현황/확장 한계**(desired=max 경고), **과소/과다 할당**(사용량 vs request), **노드 bin packing**(요청률), **GPU**(가용/요청/유휴), **노드 용량 예측**(증가율→소진 예상일), **Replica 시뮬레이션**(목표 replica의 request 합계).
- API: `GET /admin/k8s/capacity`, `/admin/k8s/capacity/simulate`

## 12. 그룹·오너십 (`#/k8s-meta`)

- **클러스터 그룹**(업무망/개발망/운영망/인터넷망/DMZ): 그룹별 클러스터 롤업(정상/위험/멤버).
- **네임스페이스 오너십**: 담당팀·담당자·서비스명·중요도·비용센터 — 알림 라우팅(NOTI-04)과 비용 집계의 기준.
- API: `GET/POST /admin/k8s/groups`(+`DELETE /groups/{id}`), `GET/POST /admin/k8s/ownership`

## 13. AI 분석 (`#/k8s-ai`)

자연어 장애 질의·운영 리포트. 수집된 **RCA·Warning 이벤트·변경 diff를 근거**로만 답합니다(근거 없으면 추측하지 않음). LLM 업스트림(`UPSTREAM_*`) 미설정 시 LLM 답변 대신 근거 데이터를 반환합니다.

- API: `POST /admin/k8s/ai/ask`, `POST /admin/k8s/ai/report`

## 14. 비용 (`#/k8s-cost`)

request×단가 기반 **월 비용 추정** — namespace/담당팀/클러스터 그룹/비용센터별 집계 + 단가 편집.

- API: `GET /admin/k8s/cost`, `GET/POST /admin/k8s/cost/config`

## 15. 보안 (`#/k8s-security`)

- **Pod Security 등급**(Privileged/Baseline/Restricted), **RBAC 위험**(cluster-admin·wildcard·secret 접근), **이미지 태그 정책**, **Secret 참조**, **NetworkPolicy 공백**, **RBAC 권한 변경**(리비전 기반), **감사 이상**(위험 액션 반복), **TLS 인증서 만료**(x509 CN/SAN/만료일) + 보안 점수.
- API: `GET /admin/k8s/security`, `/admin/k8s/rbac-diff`

## 16. 정책 센터 (`#/k8s-policy`)

- **정책 팩**(SEC-10): 7종 룰(privileged/hostNetwork/hostPath/latest태그/resource limits/runAsNonRoot/wildcard RBAC)을 Deny/Warn/Audit 액션으로 등록, 현재 인벤토리 컴플라이언스 검사.
- **Admission 시뮬레이터**(SEC-05): manifest(kind+spec)를 적용 전 정책에 검증해 allow/deny 미리보기.
- API: `GET/POST /admin/k8s/policies`(+`DELETE`, `/simulate`, `/compliance`)

## 17. SLO 센터 (`#/k8s-slo`)

namespace/service 단위 SLO와 에러버짓을 확인합니다. 현재는 incident open duration을 downtime proxy로 사용하며, Prometheus availability 보정은 후속 확장 대상입니다.

- 표시 항목: 가용성, 에러버짓 잔여율, incident 수, MTTR, downtime.
- API: `GET /admin/k8s/slo`

## 18. 운영 설정 (`#/k8s-settings`)

비용 단가(KRW/vCPU·월, KRW/GB·월), 알림(조용한 시간 `HH-HH`, 팀→Mattermost 채널 매핑 JSON), latency 분석, ChatOps, Terminal Policy Builder, Debug Container 요청 정책을 한 곳에서 설정합니다. 수집 주기·보존 기간은 게이트웨이 설정(설정 메뉴)을 따릅니다.

- Terminal Policy Builder: role, cluster, namespace glob, Pod label selector, 허용·차단 명령, 승인 필요, 최대 세션 시간, 감사 저장 여부를 설정합니다. Pod 상세의 터미널 요청은 이 정책 평가를 통과한 뒤 세션 요청 이력과 Exec 세션 승인함으로 연결됩니다.
- Exec 세션 승인함: `pending_approval` 요청을 승인하면 `ready`, 반려하면 `rejected`가 되며 승인자·시각·메모가 남습니다. 실행은 `ready -> running -> completed|failed` 전이만 허용되므로 같은 세션을 두 번 실행할 수 없습니다. `상세` 버튼은 정책 평가, 요청, 승인/반려, 실행 결과를 리플레이 타임라인으로 보여주고 `리포트` 버튼은 같은 내용을 Markdown 파일로 다운로드합니다.
- Debug Container 요청: 허용된 debug image catalog 안에서만 요청할 수 있으며 privileged, hostPID, hostNetwork는 기본 차단됩니다. 요청은 승인/반려 이력, manifest preview, 요청 사유와 함께 `k8s_debug_sessions`에 감사 기록으로 남습니다.
- API: `GET/POST /admin/k8s/cost/config`, `/admin/k8s/notify/config`, `/admin/k8s/latency/config`, `/admin/notifications/mattermost`
- 터미널·디버그 API: `GET/POST /admin/k8s/terminal-policies`, `DELETE /admin/k8s/terminal-policies/{id}`, `POST /admin/k8s/terminal-policies/evaluate`, `GET /admin/k8s/terminal/templates`, `POST /admin/k8s/pods/{namespace}/{pod}/exec/sessions`, `GET /admin/k8s/pods/{namespace}/{pod}/exec/briefing`, `GET /admin/k8s/exec/sessions`, `GET /admin/k8s/exec/sessions/{id}`, `GET /admin/k8s/exec/sessions/{id}/export`, `POST /admin/k8s/exec/sessions/{id}/approve|reject|execute`, `GET /admin/k8s/debug/catalog`, `GET /admin/k8s/debug/sessions`, `POST /admin/k8s/debug/sessions/{id}/approve|reject`, `GET /admin/ops/workers`, `GET /admin/workers`

---

## 알림 (Mattermost)

`POST /admin/k8s/notify/scan`이 현재 high/critical 장애·보안을 평가해 알림을 보냅니다 — **중복 제거**(6h 윈도우)·**조용한 시간**·**담당팀 채널 라우팅**·리소스 **딥링크** 포함. cron/`/loop`으로 주기 호출하세요. Mattermost webhook은 기존 알림 설정에서 구성합니다.

## 장기 분석 (ClickHouse)

`CLICKHOUSE_URL` 설정 후 `POST /admin/k8s/dw/bootstrap`(테이블 생성) → `POST /admin/k8s/dw/sink`(fact 적재, 주기 호출). 미설정 시 no-op.

## 일상 운영 체크리스트

1. **운영 홈**에서 위험 클러스터·장애 후보·최근 변경 확인
2. **수집 상태**에서 실시간 agent heartbeat, watch lag, resourceVersion checkpoint 확인
3. **Pod 관리**에서 위험 Pod의 컨테이너 상태, 이벤트, current/previous 로그 확인
4. 장애 보고가 필요하면 **증적 번들**로 로그·이벤트·manifest·RCA를 ZIP으로 보관
5. 장애 후보는 **장애 워룸**에서 근거·영향도·변경 이력 확인
6. **리소스 그래프**와 **연결성 점검**으로 Service/Ingress/PVC 영향 범위와 이상 점검
7. 주간: **보안**(Pod Security·RBAC·TLS 만료)·**용량**(확장 한계·과다 할당)·**비용**·**SLO** 리뷰
8. **정책 센터**로 표준 정책 위반 추적, 배포 전 **Admission 시뮬레이터** 활용
