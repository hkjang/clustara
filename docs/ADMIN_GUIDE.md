# 관리자 가이드 (Admin Guide)

Clustara(Kubernetes 운영 허브) 어드민 UI(`http://<host>:9090/admin`)의 메뉴별 사용법입니다. 모든 화면은 동일한 이름의 REST API(`/admin/k8s/*`)로도 자동화할 수 있습니다. API 상세·클러스터 등록은 **[K8s 운영 허브 가이드](K8S_OPERATIONS_HUB.md)** 를 참고하세요.

## 접속과 권한

- 레거시 모드는 UI 상단 "관리자 토큰" 입력란에 `ADMIN_TOKEN` 값을 넣습니다. `AUTH_ENABLED=true`인 운영 환경은 이메일/비밀번호 또는 SSO로 로그인합니다.
- 메뉴와 화면은 서버가 반환한 역할·스코프로 게이팅됩니다. 인증이 없으면 401 안내 화면, 로그인했지만 권한이 부족하면 403 역할 안내 화면을 표시하며 API JSON을 문서 화면에 그대로 노출하지 않습니다.
- `readonly_admin`은 조회만 가능하고, `ops_admin`·`ai_admin`·`security_admin`·`billing_admin`은 담당 도메인 설정과 작업만 변경할 수 있습니다. 버튼 숨김/비활성화는 편의 UX이며 최종 권한은 서버에서 다시 검사합니다.
- 기본 랜딩은 운영자 역할은 **운영 홈**(`#/k8s-home`), 비관리자·개발자 역할은 **내 홈**(`#/me`)입니다. SSO/역할 사용 시 `security_admin`은 보안 화면으로 랜딩.

### 계정 비밀번호 관리

- 모든 로컬 계정은 **내 영역 → 개인화 설정 → 계정 보안**에서 현재 비밀번호를 확인한 뒤 직접 변경할 수 있습니다. 변경 즉시 현재 세션을 포함한 모든 기기의 access/refresh 세션이 폐기되므로 새 비밀번호로 다시 로그인해야 합니다.
- 관리자·슈퍼 관리자는 **설정 → 시스템 설정 → 로그인 계정·팀**에서 하위 역할 사용자의 비밀번호를 임시 비밀번호로 초기화할 수 있습니다. 초기화 시 기존 세션을 모두 폐기하고 다음 로그인에서 비밀번호 변경을 강제합니다.
- 새 계정과 초기화 비밀번호는 12~128자, 영문 대/소문자·숫자·특수문자 중 3종 이상이어야 하며 흔한 문자열은 거부됩니다. 임시 비밀번호 원문은 응답·감사 로그에 저장하지 않습니다.
- API: `POST /auth/password/change`, `POST /admin/users/{id}/password-reset`.

### 관리자 접속 IP 허용 정책

- **설정 → 런타임 설정 → 관리자 IP 허용 정책**에서 현재 식별 IP를 확인하고 단일 IP/CIDR, 신뢰 프록시 CIDR을 입력한 뒤 저장 전 dry-run 검증을 수행합니다.
- 활성화할 때 현재 요청의 안전하게 식별된 IP가 새 허용 범위에 없으면 저장을 거부해 운영자 자기 잠금을 방지합니다. `X-Forwarded-For` 등 전달 헤더는 `trusted_proxy_cidrs`에 포함된 직접 프록시에서 온 경우에만 신뢰합니다.
- `security.admin_access.emergency_token`을 미리 암호화 저장하면 장애 복구 때 `X-Clustara-Break-Glass` 헤더로 우회할 수 있습니다. 모든 우회와 차단은 인증 감사 이벤트로 기록되므로 비상 토큰은 별도 Secret Manager에서 관리하고 사용 후 즉시 회전하세요.
- 런타임 키: `security.admin_access.ip_allowlist_enabled`, `allowed_cidrs`, `trusted_proxy_cidrs`, `emergency_token`. 부트스트랩 환경변수는 각각 `ADMIN_IP_ALLOWLIST_ENABLED`, `ADMIN_IP_ALLOWED_CIDRS`, `ADMIN_TRUSTED_PROXY_CIDRS`, `ADMIN_IP_EMERGENCY_TOKEN`입니다.
- API: `GET /admin/security/access-policy`, `POST`(입력값 dry-run), `PUT`(잠금 방지 후 적용).

## 메뉴 구성

내 영역(내 홈·내 업무 캘린더·개인 키 관리·나의 외부 연동·개인화 설정) · 서비스 플랫폼(서비스 홈·카탈로그·내/전체 서비스·Jupyter·DB·WAS/앱·작업 이력·템플릿) · 운영(운영 홈·클러스터·수집 상태·리소스 전체·워크로드·네트워크·스토리지·구성요소·개발자 도구·인증/권한·Pod 관리·노드 관리·앱 배포·YAML 변경·Harbor 레지스트리·Harbor Robot·앱 런처·런칭 이력·GitOps 변경관리·변경 타임라인·장애 분석·장애 워룸·리소스 그래프·연결성 점검·액션 승인함·용량·자동확장·그룹·오너십·AI 분석·리포트 센터·SLO 센터) · 비용 · 보안 · 정책 센터 · 운영 설정 · 외부연동 설정 · 설정(시스템 설정·런타임 설정·SSO·시스템 오류·설정 롤백 센터).

### 서비스 플랫폼

서비스 플랫폼은 PostgreSQL, Redis, Tomcat, Spring Boot, JupyterLab/JupyterHub를 Kubernetes 객체 묶음이 아닌 하나의 서비스로 생성·조회·운영합니다. 생성 마법사는 이미지·환경·자원 프로파일을 검증하고 기존 Application Stack 초안을 만듭니다. 재시작·확장은 기존 Action Center 승인 요청으로 연결됩니다. 서비스 상세의 **상태 동기화·검증**은 Stack과 실제 Kubernetes 인벤토리를 대조해 구성요소, Endpoint, Health Score, 비용을 표시하며 접속정보는 Secret 원문이 아닌 이름/key 참조만 관리합니다. 자세한 흐름과 capability는 [서비스 플랫폼 가이드](SERVICE_PLATFORM.md)를 참고하세요.

서비스 플랫폼 상단의 전용 소메뉴는 각 영역의 목적과 현재 건수를 함께 표시합니다. 현재 화면은 파란 활성 카드와 `현재/전체` 위치로 구분되며, 권한이 없는 메뉴는 렌더링하지 않습니다. 좁은 화면에서는 메뉴가 여러 줄로 무너지지 않고 가로 스크롤로 전환되며 현재 메뉴가 자동으로 중앙에 노출됩니다.

메뉴가 화면 너비를 넘으면 우측에 이전·다음 버튼이 나타나고 스크롤 시작·끝에서는 해당 버튼이 비활성화됩니다. 키보드 사용자는 서비스 메뉴에 focus한 뒤 좌우 방향키로 인접 메뉴, `Home`과 `End`로 처음·마지막 허용 메뉴로 이동하고 Enter로 선택할 수 있습니다.

서비스 홈은 전체 서비스의 Ready 비율과 정상·위험·승인 대기·수집/중지 상태를 먼저 보여줍니다. Jupyter·AI, 데이터베이스, WAS·앱 카드에서 유형별 정상률을 확인하고 **우선 조치 큐**에서 Failed, Degraded, 승인 대기, 만료 순으로 확인합니다. 실행 버튼은 현재 capability가 허용하는 경우에만 표시되며 조회 역할에는 조회 전용 안내만 제공합니다.

서비스 홈의 **서비스 상태 자동 동기화** 카드에서 worker 주기·최근 성공·수집 대기·오류를 확인하고 Dry-run 또는 즉시 동기화를 실행할 수 있습니다. 인벤토리가 없거나 설정된 신선도 기준보다 오래되면 실제 장애로 확정하지 않고 `collecting`으로 구분합니다. PostgreSQL 상세의 **논리 백업 요청**은 별도 Bound PVC와 등록된 Secret 참조로 Job 초안을 만들고 기존 Manifest Change Studio 승인 흐름으로 연결합니다.

서비스 상세의 **백업 요청**에서는 PostgreSQL SQL dump, Redis RDB, JupyterLab/JupyterHub 작업공간 아카이브, CSI VolumeSnapshot을 선택할 수 있습니다. JupyterHub 상세은 표준 사용자·배포 라벨과 Notebook Pod의 PVC mount를 결합해 사용자, PVC, 활성 상태, 용량과 매핑 근거를 보여줍니다. 사용자 Pod가 active이거나 사용자/PVC가 conflict이면 백업·복구를 차단하며, 백업 당시 사용자 소유권과 복구 대상 사용자도 일치해야 합니다. Jupyter 복구는 기존 파일을 덮어쓰지 않고 `.clustara-restore` staging 경로에 해제하며 경로 이탈·링크·특수 파일을 차단합니다.

JupyterHub 서비스 상세의 **JupyterHub API 설정**에서 서비스 계정 URL·토큰과 유휴 기준을 저장하고 연결을 검증할 수 있습니다. 토큰은 서비스 범위로 암호화되며 다시 표시되지 않습니다. Named Server 시작·중지는 Action Center 승인 요청으로 생성되고, 자동 유휴 정책도 즉시 종료 대신 승인 요청만 만듭니다. 승인 후 실행 시 마지막 활동을 다시 조회하므로 그 사이 사용자가 복귀한 서버는 종료하지 않습니다.

---

## 0. 내 영역 (`#/me`, `#/my-calendar`, `#/mykeys`, `#/my-integrations`, `#/my-profile`)

로그아웃 메뉴 위의 개인 메뉴와 상단 **내 영역** 그룹에서 현재 사용자 기준 기능을 모아 봅니다.

- **내 홈**: 개인 사용량, 비용, 추천, 알림, 세션, 개발도구 연결 힌트, 개인 액션 큐를 표시합니다.
- **내 업무 캘린더**: Action/Config/YAML/Exec/Debug 요청 중 내가 요청·승인·실행·검증했거나 내 역할이 처리해야 할 업무를 날짜별로 보여줍니다. 목록의 업무 링크는 기존 승인함·YAML 변경·운영 설정 화면으로 이어집니다.
- **개인 키 관리**: `SELF_SERVICE_KEYS_ENABLED=true`일 때 본인 권한 범위 안에서 API Key를 발급·회전·폐기합니다. 권한 상승 scope는 서버가 거부합니다.
- **나의 외부 연동**: GitLab, Bitbucket Server, Harbor, Mattermost Token/Password를 사용자별 Credential Vault에 암호화 저장합니다. JWT 사용자는 `user:<subject>` 기준으로 보관되어 세션 갱신 후에도 계속 조회됩니다.
- **개인화 설정**: 빠른 이동의 고정 메뉴, 최근 방문, 고정 리소스를 관리하고 내 알림·세션으로 이동합니다.
- API: `GET /me/dashboard`, `GET /me/work-calendar`, `GET/POST /me/keys`, `GET/POST /admin/external-integrations/credentials`

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

## 3-1. 리소스 카테고리 (`#/k8s-resources`)

Pod 상세 진단과 별개로 전체 Kubernetes 인벤토리를 운영 도메인별로 탐색합니다. `리소스 전체`는 카테고리별 자산 수와 high 이상 위험 리소스를 보여주고, 각 카테고리 화면은 같은 `/admin/k8s/inventory` 원천 데이터를 필터링해 상태, Kind, namespace, cluster, spec 요약, 관측/수정 시각, YAML 변경, 타임라인, 리소스 그래프 진입점을 제공합니다.

- **워크로드**(`#/k8s-workloads`): Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Pod.
- **네트워크**(`#/k8s-network`): Service, Ingress, NetworkPolicy, Endpoints, EndpointSlice, Gateway API.
- **스토리지**(`#/k8s-storage`): PersistentVolume, PersistentVolumeClaim, StorageClass, Snapshot 계열.
- **구성요소**(`#/k8s-components`): Namespace, ConfigMap, Secret, HPA, PDB, ResourceQuota, LimitRange.
- **개발자 도구**(`#/k8s-devtools`): ServiceMonitor, PodMonitor, PrometheusRule, HelmRelease, Kustomization, Certificate, Tekton 계열.
- **인증·권한**(`#/k8s-auth`): ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding, CSR.
- 카테고리별 `+ Kind` 버튼은 YAML 변경/생성 화면의 신규 리소스 생성 모드(`mode=create`)로 연결됩니다. 생성·변경 모두 요청 원장과 승인형 적용 흐름을 따릅니다.
- API: `GET /admin/k8s/inventory`

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

## 5-1. YAML 변경 (`#/k8s-manifest-changes`)

`kubectl edit` 대신 Clustara 안에서 단일 Kubernetes 리소스 YAML을 변경 요청으로 관리합니다. live manifest를 불러와 수정하고, 요청을 생성한 뒤 **검증 → 승인 → Server-Side Apply → 사후 검증 → 증적/patch export** 흐름으로 처리합니다.

- **대상**: Deployment, StatefulSet, DaemonSet, Service, Ingress, HPA, PDB, RBAC, NetworkPolicy, CRD 인스턴스 등 인벤토리에 수집된 단일 리소스.
- **Ops Agent 초안**: 자연어 프롬프트와 현재 선택 대상/YAML을 기반으로 생성·변경 초안, 위험 리뷰, blocker/warning, 체크리스트를 만들 수 있습니다. `초안 + 요청 저장`을 선택한 경우에도 실제 적용은 하지 않고 Manifest Change 원장에 `draft` 요청만 생성합니다.
- **검증**: basic schema(apiVersion/kind/name), 정책 팩, server dry-run(`dryRun=All`)을 수행합니다. 정책 Deny 또는 dry-run 실패는 `blocked/failed`로 중단됩니다.
- **브리핑**: `브리핑` 버튼은 위험도 분포, 상위 diff, approval reasons, dry-run/policy/drift 상태, 다음 액션, 운영자 체크리스트를 한 번에 보여줍니다.
- **승인**: workload, Service/Ingress, RBAC, Secret, NetworkPolicy 등 운영 영향이 있는 변경은 `approval_required`가 됩니다. 승인된 요청만 실제 apply할 수 있습니다.
- **적용**: 기존 Application Stack과 같은 Server-Side Apply 실행 경로를 사용하고, 성공 시 change-aware burst 수집을 등록해 사후 검증을 빠르게 합니다.
- **Drift Guard**: 적용 직전 현재 live manifest hash와 요청 생성 당시 before hash를 비교합니다. 요청 생성/승인 이후 리소스가 바뀌면 적용을 차단하고, 의도한 덮어쓰기만 `force_drift=true` 사유와 함께 재시도할 수 있습니다. UID 변경/리소스 삭제는 force도 차단합니다.
- **보안**: Secret `data`/`stringData` 원문은 저장하거나 적용하지 않습니다. Secret 값 변경은 Config Change Control 또는 외부 Secret 관리 체계를 사용하세요.
- **증적**: before/after YAML hash, field diff, impact, validation, apply result, verification을 Markdown evidence와 Git patch 형태로 확인할 수 있습니다.
- API: `GET /admin/k8s/manifests/editor|live`, `GET/POST /admin/k8s/manifest-changes`, `GET /admin/k8s/manifest-changes/{id}/brief`, `POST /admin/k8s/manifest-changes/{id}/validate|approve|reject|apply|verify|rollback`, `GET /admin/k8s/manifest-changes/{id}/evidence|git-patch`

## 5-2. Harbor 앱 런칭 (`#/harbor`, `#/harbor-robots`, `#/app-launcher`)

Harbor 기반 애플리케이션 런칭은 `Registry 등록 → Robot Account 등록/검증 → Project/Namespace 매핑 → imagePullSecret preview → Deployment/Service manifest preview → 런칭 요청 저장 → Manifest Change 초안 생성` 순서로 진행합니다.

- Robot token/password는 `외부연동` 메뉴에서 사용자별 Harbor Robot Credential로 암호화 저장해 재사용할 수 있습니다. Harbor 화면에서는 저장 Credential selectbox를 선택하거나 기존처럼 일회성 token을 입력합니다. Clustara는 token 원문을 응답하지 않고 Robot 메타데이터에는 hash 증적과 검증 상태만 보관합니다.
- `앱 런처`는 digest 우선 이미지 참조, imagePullSecret 참조, replica/port를 포함한 Deployment/Service YAML을 생성합니다.
- Registry, Robot Account, Project→Namespace 매핑은 각 목록의 **수정** 버튼으로 폼에 값을 다시 채운 뒤 저장할 수 있고, **삭제** 버튼으로 메타데이터를 정리할 수 있습니다. Registry 삭제는 연결된 Robot/매핑/런칭 이력이 있으면 기본 차단되며, 강제 삭제 시에도 런칭 이력은 감사 목적으로 남습니다.
- Project, Repository, Tag/Digest는 Harbor catalog에서 불러와 selectbox로 고를 수 있습니다. private project는 저장 Credential 또는 일회성 Robot token으로 조회하고, token은 응답하지 않습니다.
- `latest` 태그는 차단 판정, digest 없는 tag-only 이미지는 승인 필요 판정, 검증되지 않은 Robot Account는 승인 필요 판정으로 표시됩니다.
- 런칭 요청은 Harbor 런칭 원장에 저장됩니다. `#/app-launch-history`의 **Manifest 초안** 버튼은 blocked가 아닌 런칭 요청의 Deployment/Service 문서를 `YAML 변경/생성` 화면의 `operation=create` draft set으로 넘깁니다. 이후 schema/policy/server dry-run, 승인, Server-Side Apply, 사후 검증은 기존 Manifest Change Studio에서만 진행합니다.
- API: `GET/POST /admin/harbor/registries`, `GET/POST/DELETE /admin/harbor/registries/{id}`, `POST /admin/harbor/registries/{id}/test`, `GET/POST /admin/harbor/robots`, `GET/POST/DELETE /admin/harbor/robots/{id}`, `POST /admin/harbor/robots/verify`, `GET/POST /admin/harbor/mappings`, `GET/POST/DELETE /admin/harbor/mappings/{id}`, `POST /admin/harbor/catalog/query`, `POST /admin/harbor/pull-secret/preview`, `POST /admin/harbor/launches/preview`, `GET/POST /admin/harbor/launches`, `POST /admin/harbor/launches/{id}/manifest-change`

## 5-3. GitOps 변경관리 (`#/gitops`)

GitOps Change Manager는 외부 CD 도구를 대체하는 sync 엔진이 아니라, Clustara의 Application Stack과 live cluster 변경을 Git 선언, PR 초안, 단계적 배포, rollback 증적으로 연결하는 변경관리 화면입니다. 자세한 운영 개념은 [GitOps Change Manager 가이드](GITOPS_CHANGE_MANAGER.md)를 참고하세요.

- **운영 가이드** 버튼은 GitOps가 무엇인지, Stack → Git Source → Drift → PR Draft → Rollout/Evidence로 이어지는 사용 순서를 모달로 보여줍니다.
- **사내 Git Provider 연동** 카드에서 GitLab 또는 Bitbucket Server 6.x provider를 등록하고, `외부연동` 메뉴에 저장한 Credential 또는 일회성 token/password로 project/repository/branch/tree/file catalog를 불러올 수 있습니다. 선택한 repo/branch/path는 `Git Source 연결` 폼에 자동으로 채워집니다.
- **GitOps 빠른 등록** 카드에서 Stack에 repo/branch/path를 연결하고, PR Draft, Change Window, Progressive Rollout, Deployment Evidence를 바로 원장에 저장할 수 있습니다.
- **Drift and Change Readiness**는 Stack별 Git 연결 여부, sync policy, drift 여부, 마지막 apply 상태, rollback 후보와 권장 행동을 보여줍니다.
- **Drift Diff**는 `live_only`, `spec_diff`, `in_sync` 분류와 위험도를 표시합니다. 운영 UI에서 hotfix한 변경은 `cluster_to_git` PR Draft로 남기고, Git 선언을 기준으로 되돌릴 변경은 `git_to_cluster` 방향으로 기록합니다.
- **주의**: PR Draft와 Rollout은 외부 Git provider에 즉시 쓰는 작업이 아니라 감사 가능한 초안·계획 원장입니다. 실제 클러스터 변경은 Stack Apply 또는 YAML 변경/생성의 검증·승인·Server-Side Apply 흐름을 사용합니다.
- Provider metadata 원장에는 URL, provider 종류, username, 기본 project/repo metadata와 token hash 증적만 남습니다. Token/Password 원문은 `외부연동` Credential Vault에 사용자별로 암호화 저장하거나 catalog 조회·연결 확인 때 일회성으로 입력합니다.
- API: `GET /admin/gitops/overview`, `GET/POST /admin/gitops/providers`, `GET/POST/DELETE /admin/gitops/providers/{id}`, `POST /admin/gitops/providers/test`, `POST /admin/gitops/providers/catalog`, `POST /admin/gitops/providers/pr-template`, `GET/POST /admin/gitops/sources`, `GET /admin/gitops/drift`, `GET/POST /admin/gitops/pr-drafts`, `GET/POST /admin/gitops/progressive-rollouts`, `GET/POST /admin/gitops/change-calendar`, `GET/POST /admin/gitops/deployment-evidence`, `GET/POST /admin/gitops/rollback-plans`

## 5-4. 외부연동 (`#/external-integrations`)

GitLab, Bitbucket Server, Harbor Registry/Robot, Mattermost 같은 외부 연동 자격증명을 사용자별로 암호화 저장합니다. 일회성 token 입력이 반복되는 운영 동선을 줄이고, GitOps/Harbor 화면에서는 Credential selectbox만 선택해 재사용합니다. 화면은 전체, GitLab, Bitbucket, Harbor, Mattermost 탭으로 구분됩니다.

- 저장 항목: provider, base URL, username/robot name, auth type, token/password, 설명, 기본 project/repo/branch metadata.
- Secret 원문, 암호문, hash는 API 응답에 포함되지 않습니다. secret 미입력 수정은 기존 암호화 secret을 유지하고, 새 secret을 입력하면 회전합니다.
- 연결 확인은 저장 Credential을 메모리에서만 복호화해 수행하고 감사 로그에는 provider, credential id, 결과만 남깁니다.
- API: `GET/POST /admin/external-integrations/credentials`, `GET/POST/DELETE /admin/external-integrations/credentials/{id}`, `POST /admin/external-integrations/credentials/{id}/test`

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

- 화면 상단의 **토폴로지 맵**은 리소스 관계를 SVG 그래프로 표시하고, 관계 유형별 색상 범례와 포커스 리소스 강조를 제공합니다.
- YAML 변경 링크가 보이는 리소스 목록, Pod 상세, 노드 관리, 서비스 카탈로그, 장애 워룸에서는 `토폴로지` 링크로 현재 화면을 유지한 채 모달에서 그래프를 확인할 수 있습니다.
- 필터: 클러스터·kind·namespace·name·반경(1~3 hop). 모달 기본 반경은 2-hop이며, 그래프 안의 노드를 클릭하면 같은 모달에서 해당 리소스 기준 2-hop 관계를 다시 조회합니다.
- 포커스 없이 전체 그래프를 열면 관계가 있는 리소스를 우선 표시해 고립된 ClusterRole/ClusterRoleBinding 같은 RBAC 노이즈가 맵을 지배하지 않도록 보정합니다.
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

- 상단 **다음 행동 흐름**은 Action, Config 변경, YAML 변경, Exec 세션, Debug Container 요청을 한곳에 모아 `확인 필요`, `승인 대기`, `실행 가능`, `검증 필요`, `준비/검증`, `완료` 레인으로 보여줍니다. 각 카드의 버튼은 원래 처리 화면(Action Center, 보안 Config 변경, YAML 변경, 운영 설정)으로 이동합니다.
- 요청 생성 시 영향도가 자동 산출되어 `dry_run_diff`에 기록되고, blocker(standalone Pod 삭제·drain·허용 외 patch 필드 등)가 있으면 자동으로 **승인 필수**로 격상됩니다.
- 요청에는 `idempotency_key`, `target_uid`, `target_resource_version`, `command_hash`가 저장됩니다. 같은 idempotency key로 재시도하면 기존 요청을 반환합니다.
- **승인**된 액션은 `approved -> running -> executed|failed` 전이만 허용되며 **실행** 버튼으로 실클러스터에 반영합니다: `scale`/`rollout_restart`/`cordon`/`uncordon`/`delete_pod`. 같은 승인 건의 중복 실행은 차단되고 drain은 수동입니다.
- 개발자 뷰 요청 생성은 `request`(승인 요청), `approve`(승인까지), `execute`(승인 후 즉시 실행) 모드를 지원합니다. `super_admin`/`admin`은 실행 가능한 작업을 즉시 실행할 수 있고, 개발자/조회자는 승인 요청만 생성합니다. `ops_admin`/`operator`/`approver`는 위험도에 따라 승인까지만 허용됩니다.
- 과거 개발자 뷰에서 생성된 `pending_approval` 액션도 호환 상태로 남아 있어 승인/반려할 수 있습니다.
- API: `GET /admin/k8s/action-flow`, `GET/POST /admin/k8s/actions`, `POST /admin/k8s/actions/{id}/approve|reject|execute`

## 10.5 노드·GPU 운영 (`#/k8s-nodes`)

- Node CPU/Memory 실사용은 `metrics.k8s.io`를 전체 인벤토리와 분리해 기본 60초마다 수집합니다. 화면은 1h/6h/24h/7d 추세, peak, 시간당 증가율, 메트릭 신선도와 90% 임계치 도달 예상을 표시합니다. 이 예상은 선형 선행 경보이며 실제 장애 시점을 보장하지 않습니다.
- Ready/Pressure, Node Warning Event, CPU/Memory/GPU 사용률·증가율·피크, 수집 지연을 설명 가능한 위험 점수로 합성합니다. 중대한 조치는 기존처럼 `Drain 영향 분석 → cordon 승인 요청 → 실행` 흐름을 사용합니다.
- GPU가 있는 노드는 인벤토리만으로 모델/개수/Pod 요청·잔여량을 표시합니다. **설정 → 런타임 설정 → `k8s.monitoring`**에서 Prometheus URL/token을 저장하면 NVIDIA DCGM Exporter의 장치/MIG별 Util, SM/Tensor/DRAM Active, VRAM, 온도, 전력, clock, XID, ECC, PCIe replay, NVLink, thermal throttle을 추가합니다. 기존 `PROMETHEUS_URL`/`PROMETHEUS_TOKEN` 환경변수는 초기 기본값으로 계속 사용할 수 있습니다.
- 같은 설정 그룹에서 수집 on/off·주기·보존기간, Node label, alert 임계치, GPU-hour 단가, latency PromQL을 재시작 없이 바꿀 수 있습니다. 보존기간이 지난 Node/GPU 원시 표본은 6시간마다 함께 정리됩니다.
- `k8s.monitoring.dcgm_counters_csv`는 DCGM Exporter collector CSV 원본입니다. 저장할 때 형식·중복·필수 counter를 검증하고, 고급 PromQL override가 비어 있으면 이 CSV에서 수집 selector를 자동 생성합니다. **입력값으로 GPU/DCGM 검증**은 저장 전 화면 값을 사용해 CSV, Prometheus 인증/쿼리, 표본·노드·관측 metric을 확인합니다. **DCGM ConfigMap 미리보기**에서는 적용 가능한 YAML을 검토·다운로드할 수 있으며 Clustara가 자동 배포하지는 않습니다.
- DCGM Exporter에 `-k`(`DCGM_EXPORTER_KUBERNETES=true`)를 적용하면 Namespace/Pod/Container와 GPU 장치를 매핑합니다. 파일 기반 기본 예시는 `deploy/k8s/dcgm-exporter-counters.csv`입니다.
- GPU 운영 섹션은 장시간 저사용(request 대비 util), VRAM 90% 도달 추세, 하드웨어 오류, MIG 할당, Namespace/서비스/모델 서버별 GPU-hour 비용을 제공합니다. vLLM Prometheus 지표가 있으면 req/s, token/s, running request, TTFT p95, E2E p95를 GPU 소비량과 연결합니다.
- 임계치는 화면의 **GPU 알림 정책**에서 온도, VRAM, 저사용률/지속시간, GPU-hour 단가를 저장합니다. XID, DBE ECC, NVLink 오류는 항상 중대 격리 후보이며 자동 cordon/drain하지 않습니다.
- API: `GET /admin/k8s/nodes/monitoring`, `POST /admin/k8s/node-metrics/collect`, `GET /admin/k8s/gpu/operations`, `GET/POST /admin/k8s/gpu/policy`, `GET /admin/k8s/gpu/dcgm-config`, `POST /admin/settings/test/k8s-monitoring`.

## 11. 용량·자동확장 (`#/k8s-capacity`)

- **HPA 현황/확장 한계**(desired=max 경고), **과소/과다 할당**(사용량 vs request), **노드 bin packing**(요청률), **GPU**(가용/요청/유휴), **노드 용량 예측**(증가율→소진 예상일), **Replica 시뮬레이션**(목표 replica의 request 합계).
- API: `GET /admin/k8s/capacity`, `/admin/k8s/capacity/simulate`

## 12. 그룹·오너십 (`#/k8s-meta`)

- **클러스터 그룹**(업무망/개발망/운영망/인터넷망/DMZ): 그룹별 클러스터 롤업(정상/위험/멤버), 그룹 수정·삭제.
- **클러스터 그룹 멤버십**: 이미 추가한 클러스터를 별도 카드에서 그룹에 배정·변경·해제합니다. 그룹 삭제 시 기존 멤버 클러스터는 자동으로 미분류 처리되어 깨진 참조가 남지 않습니다.
- **네임스페이스 오너십**: 담당팀·담당자·서비스명·중요도·비용센터 — 알림 라우팅(NOTI-04)과 비용 집계의 기준. 목록에서 바로 수정 모드로 전환하거나 삭제할 수 있습니다.
- API: `GET/POST /admin/k8s/groups`, `GET/POST/DELETE /admin/k8s/groups/{id}`, `POST /admin/k8s/clusters/{id}/group`, `GET/POST /admin/k8s/ownership`, `DELETE /admin/k8s/ownership/{cluster_id}/{namespace}`

## 13. AI 분석 (`#/k8s-ai`)

자연어 장애 질의·운영 리포트. 수집된 **RCA·Warning 이벤트·변경 diff를 근거**로만 답합니다(근거 없으면 추측하지 않음). LLM 업스트림(`UPSTREAM_*`) 미설정 시 LLM 답변 대신 근거 데이터를 반환합니다.

- API: `POST /admin/k8s/ai/ask`, `POST /admin/k8s/ai/report`

## 14. 비용 (`#/k8s-cost`)

request×단가 기반 **월 비용 추정** — namespace/담당팀/클러스터 그룹/비용센터별 집계 + 단가 편집.

- API: `GET /admin/k8s/cost`, `GET/POST /admin/k8s/cost/config`

## 15. 보안 (`#/k8s-security`)

- **Pod Security 등급**(Privileged/Baseline/Restricted), **RBAC 위험**(cluster-admin·wildcard·secret 접근), **이미지 태그 정책**, **Secret 참조**, **NetworkPolicy 공백**, **RBAC 권한 변경**(리비전 기반), **감사 이상**(위험 액션 반복), **TLS 인증서 만료**(x509 CN/SAN/만료일) + 보안 점수.
- 신규 하위 화면: `#/k8s-security-vulnerabilities`(Trivy/Grype CVE), `#/k8s-security-sbom`(CycloneDX/SPDX), `#/k8s-security-cluster-scan`(Trivy Operator/스캔 이력), `#/k8s-security-admission`(배포 차단 정책 평가), `#/k8s-security-runtime`(Falco 이벤트), `#/k8s-security-benchmark`(kube-bench CIS), `#/k8s-security-exceptions`(만료형 예외 승인).
- 각 보안 하위 화면 상단의 `사용자 가이드` 버튼은 화면별 운영 순서, 업로드 예시, 차단·승인 판단 기준, scanner 직접 실행 금지 원칙을 모달로 제공합니다.
- 스캐너 실행 원칙: Clustara 서버가 직접 scanner shell을 실행하지 않고 CI, agent runner, Trivy Operator, Falcosidekick, kube-bench Job 결과를 import합니다.
- CI 업로드 편의: 스캔 결과와 SBOM은 래퍼 JSON뿐 아니라 원본 Trivy/Grype/Trivy Operator/CycloneDX/SPDX JSON body도 직접 import할 수 있으며, 이미지 digest 등 metadata는 query 또는 body에서 보정합니다.
- API: `GET /admin/k8s/security`, `/admin/k8s/rbac-diff`, `/admin/k8s/security/vuln/*`, `/admin/k8s/security/scans*`, `/admin/k8s/security/sboms`, `/admin/k8s/security/admission/*`, `/admin/k8s/security/runtime/events`, `/admin/k8s/security/benchmarks/job-manifest`, `/admin/k8s/security/benchmarks/*`, `/admin/k8s/security/exceptions*`

## 16. 정책 센터 (`#/k8s-policy`)

- **정책 팩**(SEC-10): privileged/hostNetwork/hostPath/latest태그/resource limits/runAsNonRoot/wildcard RBAC에 더해 이미지 서명, digest 고정, SBOM 필수, 취약점 스캔 attestation, Critical/High CVE, 만료 예외, privileged runtime, PSS Restricted 룰을 Deny/Warn/Audit 액션으로 등록합니다.
- **Admission 시뮬레이터**(SEC-05): manifest(kind+spec)를 적용 전 정책에 검증해 allow/deny 미리보기. 이미지 취약점·SBOM·예외 기반 평가는 `#/k8s-security-admission`의 이미지 정책 평가 API와 함께 사용합니다.
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
