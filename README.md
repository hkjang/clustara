<p align="center">
  <img src="docs/images/logo.svg" alt="Clustara Logo" width="160" />
</p>

# Clustara


**Clustara**는 Kubernetes 운영을 위한 **장애 분석·변경 추적·보안·용량·비용 통합 운영 허브**입니다. `kubectl` 없이도 클러스터의 위험과 장애 원인 후보를 한 화면에서 확인하고, 변경 이력을 추적하며, 위험 작업을 승인 워크플로우로 안전하게 실행합니다. 폐쇄망 운영을 위한 오프라인 도커 이미지 릴리즈를 제공합니다.

> Clustara는 OpenAI 호환 게이트웨이 코어 위에 구축되어 있으며, 그 LLM 호출 능력은 **AI 운영 분석**(근거 기반 장애 질의·리포트) 기능에 내부적으로 재사용됩니다.

## 문서

- **[K8s 운영 허브 가이드](docs/K8S_OPERATIONS_HUB.md)** — 클러스터 등록(minikube·운영), 수집, API 전체, 분석/액션 — **핵심 문서**
- **[GitOps Change Manager 가이드](docs/GITOPS_CHANGE_MANAGER.md)** — Stack·Git Source·Drift·PR Draft·Progressive Rollout·Evidence 운영 동선
- **[운영 가이드](docs/OPERATIONS.md)** — 기동/종료, 헬스체크, 백업·복구, 장애 대응 런북
- **[관리자 가이드](docs/ADMIN_GUIDE.md)** — 어드민 UI/설정/운영 체크리스트
- **[서비스 플랫폼 가이드](docs/SERVICE_PLATFORM.md)** — 서비스 카탈로그, Stack/Action Center 연결, PostgreSQL·Redis·Jupyter 작업공간 백업과 CSI 스냅샷 Clone Restore
- **[안전 및 보안 거버넌스 가이드](docs/SAFETY_GUIDE.md)** — 정책 엔진·승인 워크플로우
- **[PostgreSQL 가이드](docs/POSTGRES_GUIDE.md)** — 운영 DB 구성
- **[릴리즈 가이드](docs/RELEASE_GUIDE.md)** — 빌드·태깅·GitHub 릴리즈·오프라인 패키지·롤백
- **[2차 개발 플랜](docs/K8S_PHASE2_PLAN.md)** — 구현된 기능의 설계·PR 시퀀스

## 주요 기능

| 영역 | 내용 |
| --- | --- |
| **운영 홈** | 클러스터 위험 TOP5, 장애 후보 TOP10, 최근 변경 TOP10, 비용 TOP10 |
| **리소스 관리** | 워크로드, 네트워크, 스토리지, 구성요소, 개발자 도구, 인증·권한 카테고리별 인벤토리와 위험 리소스, Kind 분포, YAML 변경/생성·타임라인·리소스 그래프 딥링크 |
| **Pod 관리** | Pod 목록·상세, 위험 Pod 자동 북마크, 최근 접근 이력, 컨테이너 상태, 이벤트, 현재/previous 로그, 로그 분석·프리셋·마스킹 리포트·스냅샷·동일 workload 병합, 증적 번들, Golden Pod Diff, Health Replay, 조치 안전성·플레이북 |
| **터미널·디버그 정책** | Pod exec/web terminal 사전 정책: role·namespace·label·명령 allow/deny·승인·세션 시간·감사 평가, Risk Briefing, 명령 템플릿, 세션 요청 이력·승인함·상세 리플레이·감사 리포트, Debug Container 요청·승인 이력 |
| **변경 추적** | 리소스 spec 리비전(append-only), Resource Diff, 변경 타임라인, Manifest Viewer(민감값 마스킹), YAML 변경/생성 요청 원장, Ops Agent YAML 초안/요청 브리지 |
| **GitOps 변경관리** | Application Stack의 Git source 연결, 사용자별 외부연동 Credential Vault 기반 GitLab·Bitbucket Server catalog picker, drift 분류, PR draft 원장, progressive rollout 계획, change calendar, deployment evidence, rollback 후보 관리 |
| **장애 분석(RCA)** | CrashLoop·OOM·ImagePull·Pending·Unavailable + Readiness/Liveness probe·DNS·NodePressure(노드 condition) + 직전 Config 변경·배포 후 오류 연계, 근거 기반 장애 분석 센터 |
| **연결성 점검** | Service selector↔Endpoint, Ingress backend/host/TLS, PVC, Rollout, Job/CronJob |
| **액션 센터** | 영향도 분석·승인·감사 공통화 + 실클러스터 executor(scale / rollout restart / cordon / uncordon / delete pod) — Action/Config/YAML/Exec/Debug 요청을 다음 행동 흐름으로 묶는 승인 게이트 |
| **보안·정책** | Pod Security 등급, RBAC 위험·RBAC Diff, 이미지 태그, Secret 참조, NetworkPolicy 공백, TLS 인증서 만료, 감사 이상, 이미지 취약점(Trivy/Grype import), SBOM, 지속 스캔, Admission 이미지 정책, Falco 런타임 이벤트, CIS Benchmark, 만료형 예외 승인, 정책 센터(Admission 시뮬레이터 + 정책 팩) |
| **용량·자동확장** | HPA 진단, 과소/과다 할당, 노드 bin packing, GPU, 노드 용량 예측, replica 시뮬레이션 |
| **비용(FinOps)** | request×단가 기반 월 비용 추정 — namespace/팀/클러스터 그룹/비용센터별 |
| **알림** | Mattermost 연동 — 위험 이벤트·보안 위반 알림, 중복 제거·조용한 시간·담당팀 라우팅·딥링크 |
| **AI 운영 분석** | 자연어 장애 질의, 운영 리포트 — 수집된 RCA·이벤트·변경 diff를 근거로 답변 |
| **장기 분석** | ClickHouse fact 적재(change/event/health/security/cost/action/metric) |
| **메타데이터** | 멀티 클러스터 그룹(업무망/운영망/DMZ 등)과 등록 클러스터 그룹 배정·변경·해제, 네임스페이스 오너십 수정·삭제(담당팀·서비스·중요도·비용센터) |

## 동작 방식

Clustara는 **클러스터를 변경하지 않는 읽기 전용 수집**을 기본으로 합니다. 등록된 클러스터에서 인벤토리(spec+status)·이벤트·메트릭을 수집해 저장하고, 그 위에서 분석을 수행합니다. 쓰기 작업(scale/restart/cordon/delete)은 **요청 → 영향도 분석 → 승인 → 실행**의 워크플로우를 거칩니다.

## 실행 (개발)

```powershell
$env:GATEWAY_SECRET = "dev-only-secret"   # provider key·kubeconfig 암호화 키
$env:ADMIN_TOKEN    = "dev-admin"
go run ./cmd/clustara
```

기동 로그에 `Clustara listening addr=:9090 database=sqlite` 가 보이면 정상입니다. 어드민 UI: `http://localhost:9090/admin` (상단 "관리자 토큰"에 `ADMIN_TOKEN` 입력).

자세한 기동/종료/백업은 [운영 가이드](docs/OPERATIONS.md) 참고.

## 클러스터 등록

개발 PC의 **minikube**와 **운영 K8s 클러스터** 등록 방법(전용 ServiceAccount·읽기 전용 ClusterRole·kubeconfig 구성 포함)은 [K8s 운영 허브 가이드](docs/K8S_OPERATIONS_HUB.md#클러스터-등록)에 정리되어 있습니다.

요약: 어드민 UI **클러스터** 메뉴에서 등록 → **연결 테스트** → **수집**. kubeconfig/token은 `GATEWAY_SECRET` 기반 AES-GCM으로 암호화 저장되며 응답에 원문이 노출되지 않습니다.

## 주요 환경변수

| 변수 | 설명 |
| --- | --- |
| `LISTEN_ADDR` | 리슨 주소 (기본 `:9090`) |
| `GATEWAY_SECRET` | kubeconfig/token·provider key 암호화 키 — **운영 필수, 변경 시 기존 암호값 복호화 불가** |
| `ADMIN_TOKEN` | 어드민 API/UI 접근 토큰 |
| `DB_DRIVER` / `DB_DSN` | 저장소 (기본 sqlite `data/gateway.db`, PostgreSQL DSN 지원) |
| `CLICKHOUSE_URL` | (선택) 장기 분석 fact 적재 대상 — 미설정 시 sink는 no-op |
| `UPSTREAM_BASE_URL` / `UPSTREAM_API_KEY` | (선택) AI 운영 분석용 LLM 업스트림 — 미설정 시 AI 답변 대신 근거 데이터만 반환 |

알림(Mattermost)·비용 단가·조용한 시간·팀 채널 매핑은 어드민 UI **운영 설정** 화면에서 구성합니다.

## ClickHouse 장기 분석 (선택)

`CLICKHOUSE_URL` 설정 후:

```
POST /admin/k8s/dw/bootstrap   # K8s fact 테이블 생성
POST /admin/k8s/dw/sink        # 현재 fact 적재 (cron으로 주기 호출)
```

## Docker / 오프라인 릴리즈

```bash
docker build -t clustara:dev .
docker run -d --name clustara --restart=always -p 9090:9090 -v $PWD/data:/data \
  -e GATEWAY_SECRET=$(openssl rand -hex 32) -e ADMIN_TOKEN=$(openssl rand -hex 32) clustara:dev
```

빌드·태깅·GitHub 릴리즈·오프라인 도커 이미지 패키지 산출은 [릴리즈 가이드](docs/RELEASE_GUIDE.md) 참고.

## 라이선스 / 기여

이 프로젝트는 **GNU Affero General Public License v3.0 (AGPL-3.0)** 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](file:///d:/project/clustara/LICENSE) 파일을 참고하세요.

변경 이력은 [scripts/changelog.txt](scripts/changelog.txt)를 참고하세요.
