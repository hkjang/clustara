# K8s 운영 허브 2차 개발 구현 플랜

본 문서는 현재 MVP(클러스터 등록·인벤토리·이벤트·메트릭·보안 finding·RCA·액션 요청) 위에 2차 요건
(K8S-16~25, RCA-01~10, SCALE-01~08, SEC-01~10, ACT-01~10, DW-01~10, UI/NOTI/AI-OPS)을 어떤 순서와
구조로 붙일지 정의한다. 코드 작성은 이 문서의 PR 시퀀스를 따른다.

---

## 0. 현재 아키텍처 요약 (구현 시 반드시 따를 패턴)

| 레이어 | 위치 | 비고 |
| --- | --- | --- |
| K8s 스토어 | [internal/store/k8s.go](internal/store/k8s.go) | cluster / inventory / event / metric / security_finding / action_request |
| 스키마 DDL | [internal/store/sqlstore.go](internal/store/sqlstore.go) `~:1788` | `CREATE TABLE IF NOT EXISTS` 묶음. 새 테이블은 여기 추가 |
| HTTP 핸들러 | [internal/proxy/admin_k8s.go](internal/proxy/admin_k8s.go) | `/admin/k8s/*`. 새 핸들러는 여기 또는 신규 `admin_k8s_*.go` |
| 수집 | [internal/collector/snapshot.go](internal/collector/snapshot.go), [internal/kube/client.go](internal/kube/client.go) | client-go 라이브 수집 + 스냅샷 적재 |
| 분석 | [internal/analyzer/rca.go](internal/analyzer/rca.go), [internal/analyzer/k8s.go](internal/analyzer/k8s.go) | status 문자열 기반 RCA / finding 생성 |
| 액션 | [internal/action/k8s.go](internal/action/k8s.go) | 요청/승인/반려만. executor·dry-run 미연결 |
| UI | [internal/proxy/admin_ui.go](internal/proxy/admin_ui.go) `adminHTML` 상수 | 바닐라 JS 해시 SPA. `route()` switch + `renderXxx()` + `api()` |
| 네비게이션 | [internal/proxy/navigation.go](internal/proxy/navigation.go) | `menuRegistry`, `childTabs`, `menuVersion` |

### UI 추가 규칙
1. 신규 최상위 화면 → `menuRegistry`에 `menuItem` 추가하고 `menuVersion`을 +1.
2. 한 부모 화면의 서브 탭 → `childTabs`에 등록(부모 권한을 상속).
3. `route()` switch에 `case` 추가 → `renderXxx()` 작성 → 데이터는 `api('/admin/k8s/...')`로 로드.
4. 권한은 코드가 아니라 `menuItem.Scopes`/`Features`로만 게이팅(서버·클라 드리프트 방지).

### 백엔드 추가 규칙
- 새 테이블: snake_case `k8s_*`, `cluster_id` 인덱스 필수. PG/SQLite 양쪽 동작하도록 `s.bind(...)` 사용.
- 시간 컬럼은 기존과 동일하게 RFC3339 문자열(`nowString()`).
- 민감값(secret/token/env)은 응답 직전 마스킹. 원문은 API로 절대 반환 금지(기존 credential 패턴 준수).

---

## 1. 핵심 구조 결정 (모든 PR의 전제)

### 결정 A — 리소스 이력은 append-only 리비전 테이블로 분리
현재 `k8s_inventory`는 `ON CONFLICT(cluster_id,kind,namespace,name) DO UPDATE`로 **현재 상태만** 유지한다
([internal/store/k8s.go:284](internal/store/k8s.go)). 따라서 Resource Diff(K8S-18)·Timeline(K8S-19)·
change_fact(DW-09)·Config 변경 RCA(RCA-09)·배포 후 오류(RCA-10)는 **현재 구조 위에서 불가능**하다.

→ 신규 테이블 **`k8s_resource_revisions`** (append-only)를 도입한다.
수집 시 리소스의 정규화 spec 해시가 직전과 다를 때만 한 행을 append. 이 테이블 하나가
Diff/Timeline/Config-RCA/change_fact의 공통 토대가 된다.

```
k8s_resource_revisions(
  id, cluster_id, kind, namespace, name,
  spec_hash,            -- 정규화 spec의 sha256
  spec_json,            -- 그 시점 전체 spec (마스킹 전 원본은 암호화 또는 민감필드 제외 저장)
  replica, image_set,   -- diff 가속용 추출 컬럼 (옵션)
  change_kind,          -- created|updated|deleted
  observed_at, created_at
)
INDEX (cluster_id, kind, namespace, name, observed_at)
```

### 결정 B — K8s 화면은 단일 탭에서 멀티 화면으로 승격
현재 `#/k8s` 단일 탭. 2차 UI 요건(운영 홈/장애 분석 센터/변경 타임라인/보안·용량·비용 대시보드/
액션 승인함/정책 센터/리포트 센터/설정 센터)은 화면이 많다. → `k8s`를 부모로 두고 `childTabs["k8s"]`에
하위 화면을 등록하거나, `Group: "k8s"`를 신설해 좌측 메뉴 그룹으로 묶는다. **Group 신설을 권장**
(화면 수가 10+ 이므로).

### 결정 C — 메타데이터(그룹/오너십)를 가장 먼저
K8S-16(클러스터 그룹)·K8S-17(네임스페이스 오너십)은 비용 대시보드·알림 라우팅(NOTI-04)·필터링이
모두 참조하는 횡단 메타데이터다. → 우선순위 표(섹션 10)의 1순위(Diff/Timeline)와 함께 **PR0에서 토대로 먼저** 깐다.

---

## 2. PR 시퀀스 (의존성 순서)

> 우선순위 근거는 원 요건 섹션 10을 따르되, 의존성(결정 A/C)을 반영해 메타데이터·리비전 토대를 앞당겼다.

| PR | 묶음 | 포함 요건 | 의존 | 산출물 | 상태 |
| --- | --- | --- | --- | --- | --- |
| **PR0** | 토대: 그룹/오너십 | K8S-16, K8S-17 | — | cluster_group·ns_ownership 테이블/CRUD/롤업/팀필터 + 그룹·오너십 UI | ✅ 완료 |
| **PR1** | 리비전 + Diff + Timeline | K8S-18, K8S-19, (DW-09 emit) | PR0, 결정 A | `k8s_resource_revisions`, Diff/Timeline API+UI | ✅ 완료 |
| **PR2** | Manifest Viewer | K8S-20 | PR1 | YAML 조회 + secret/token/env 마스킹 | ✅ 완료 |
| **PR3** | RCA 고도화 | RCA-05~10 | PR1 | probe/DNS/NodePressure 이벤트 RCA + 리비전 연계 Config 변경·배포 후 오류 RCA + 장애 분석 센터 UI | ✅ 완료 |
| **PR3** | RCA 고도화 | RCA-05~10 | PR1(09·10) | 신규 RCA 룰 + **장애 분석 센터** UI |
| **PR4** | 워크로드 연결성 분석 | K8S-22, K8S-23, K8S-24 | PR0 | Service/Ingress/PVC 분석 + 연결성 점검 UI | ✅ 완료 |
| **PR4b** | status 적재 + Rollout/Job | K8S-21, K8S-25 | PR4 | inventory `status_json` 적재 + Rollout/Job/CronJob RCA | ✅ 완료 |
| **PR5** | 액션 센터 안전장치 | ACT-01~07 (executor·DW-07 미완) | PR0 | 영향도 분석·승인·감사 공통화 + **액션 승인함** UI | ✅ 완료(안전장치) |
| **PR6** | 보안·정책 | SEC-01·02·03·04·05·06·08·09·10 (07만 미완) | PR0, PR1 | Pod Security/RBAC/이미지/Secret/NetworkPolicy + RBAC Diff + 감사이상 + **정책 센터**(Admission 시뮬·정책팩) | ✅ 완료 |
| **PR7** | 자동확장·용량 | SCALE-01~08 전부 | PR4b(status) | HPA 진단·할당 효율·bin-packing·GPU·용량 예측·replica 시뮬 + **용량 대시보드** UI | ✅ 완료 |
| **PR8** | ClickHouse 장기 분석 + 리포트 센터 | DW-01~10 | PR1·5·6 | fact sink/bootstrap(ClickHouse) + **리포트 센터**(일간 장애·주간 비용·월간 SLO, 로컬 데이터) + 비용 증가율(로컬 스냅샷) | ✅ 완료 |
| **PR9** | Mattermost 알림 | NOTI-01~08 | PR0(라우팅), PR3 | 기존 Mattermost 재사용 + K8s 카테고리·중복제거·조용한시간·담당팀 라우팅·딥링크·스캔 | ✅ 완료 |
| **PR10** | 비용/FinOps | DW-08, 비용 대시보드 | PR0, PR7 | request×단가 비용 추정(ns/team/group/cost-center) + **비용 대시보드** + 운영홈 비용 TOP | ✅ 완료 |
| **PR11** | AI 운영 분석 | AI-OPS-01·06·08 (02·03·04·05·07 부분/미완) | PR1·3 | LLM 프록시 재사용 + 근거 기반 자연어 질문/리포트 (LLM 미구성 시 근거만 graceful) | ✅ 완료(핵심) |
| **PR12** | 운영 홈 (+설정 센터) | 섹션 7 운영홈 | 대부분 PR | 운영 홈 TOP-N 위젯(위험·장애·변경) ✅ / 설정 센터 미완 |

운영 홈(PR12)은 다른 PR이 만든 데이터를 모아 보여주므로 마지막에 가깝게 둔다.
설정 센터는 각 PR에서 자기 설정 항목을 점진 추가하고 PR12에서 통합 화면으로 정리한다.

---

## 3. PR별 상세

### PR0 — 토대: 클러스터 그룹 + 네임스페이스 오너십 + 네비 골격
- **스토어**: `k8s_cluster_groups(id, name, kind[업무망/개발망/운영망/인터넷망/DMZ], description)`,
  클러스터에 `group_id` 컬럼 추가. `k8s_namespace_ownership(cluster_id, namespace, team, owner, service_name, criticality, cost_center)`.
- **API**: `GET/POST /admin/k8s/groups`, `GET/POST /admin/k8s/ownership`. 인벤토리/이벤트/finding/RCA 필터에 `group_id`·`team` 파라미터 추가.
- **UI**: `navigation.go`에 K8s 그룹 신설 + `menuVersion`+1. 기존 `#/k8s`를 "운영 홈"의 자리로 재배치.
- **수용 기준**: 그룹별 상태/장애수/비용/보안 결과 집계 표시(K8S-16), 장애·비용·보안 결과를 담당팀 기준 필터(K8S-17).

### PR1 — 리비전 + Resource Diff + Deployment Timeline (1순위)
- **스토어**: `k8s_resource_revisions` 추가(결정 A). `InsertK8sInventory`를 수정해 spec_hash가 바뀌면 리비전 append.
  `ListResourceRevisions(filter)`, `DiffRevisions(a,b)` 헬퍼.
- **분석**: replica / image / env / resource limit / ingress host 변경을 추출하는 diff 함수(K8S-18).
- **API**: `GET /admin/k8s/resources/{kind}/{ns}/{name}/diff?from=&to=`,
  `GET /admin/k8s/timeline?cluster=&ns=&name=` — 리비전 + event + action_request를 `observed_at` 기준 머지(K8S-19).
- **UI**: "변경 타임라인" 화면(`renderK8sTimeline`) — 배포/scale/restart/pod 재생성/event/액션을 한 시간축. Diff는 좌우 비교 뷰.
- **DW-09 준비**: 리비전 append 시 change 이벤트를 emit(실제 sink는 PR8).
- **수용 기준**: replica/image/env/limit/ingress host 변경 이력 확인, 장애 전후 변경을 한 화면에서 추적.

### PR2 — Manifest Viewer (K8S-20)
- 현재 리비전의 `spec_json`을 YAML로 직렬화해 반환. Secret 값/`*token*`/env의 민감 키는 정규식 + 키명 기반 자동 마스킹.
- **API**: `GET /admin/k8s/resources/{kind}/{ns}/{name}/manifest`. **수용 기준**: 민감값 자동 마스킹.

### PR3 — RCA 고도화 (2순위)
[internal/analyzer/rca.go](internal/analyzer/rca.go)의 switch에 룰 추가:
- RCA-05 Readiness 실패(probe 설정·endpoint 제외 여부·Service 영향), RCA-06 Liveness 실패(timeout/initialDelay/failureThreshold),
  RCA-07 DNS 실패(CoreDNS 상태·Service name·NetworkPolicy), RCA-08 NodePressure(Memory/Disk/PID),
  RCA-09 Config 변경 장애(**PR1 리비전** diff와 장애 시점 매칭), RCA-10 배포 후 오류 증가(**PR1 timeline**과 restart/error/latency 매칭).
- **UI**: "장애 분석 센터" — 원인 후보 + 근거 이벤트 + 관련 로그 + 최근 변경(diff) + 조치 버튼을 한 화면(섹션 7).

### PR4 — Service / Ingress / PVC / Rollout / Job 분석 (3순위)
- **수집 확장**([internal/kube/client.go](internal/kube/client.go)): Endpoints, Ingress, PVC, Job/CronJob, Deployment rollout status 수집.
- **분석**: K8S-22 selector↔Endpoint 매칭(불일치/endpoint 없음/targetPort 오류), K8S-23 Ingress(backend 없음/TLS secret 없음/중복 host),
  K8S-24 PVC(Pending/StorageClass/사용률/FailedMount·VolumeAttach), K8S-21 Rollout(지연 원인·unavailable replica), K8S-25 Job(성공률·실패·마지막 성공 시각).
- **UI**: 각 리소스 상세 패널.

### PR5 — 액션 센터 안전장치 (4순위)
- **공통화**: `internal/action`에 dry-run → 영향도 요약 → 승인 → 실행 → 감사 로그의 단일 파이프라인. executor를 client-go에 연결.
- 액션별 안전장치: ACT-01 scale(replica diff), ACT-02 rollout restart, ACT-03 delete pod(controller 소유만, standalone은 승인),
  ACT-04 cordon(영향 ns 표시), ACT-05 uncordon, ACT-06 drain(PDB/DaemonSet/local storage 확인, 승인 필수),
  ACT-07 patch(image/replica/annotation만), ACT-08 rollback guide, ACT-09 restart failed pods(자동 금지·승인), ACT-10 maintenance mode(알림 억제).
- **UI**: "액션 승인함"(요청자/대상/위험도/diff/승인·반려 사유). **DW-07 action_fact** emit.

### PR6 — 보안·정책 (5순위)
- SEC-01 Pod Security Score(Privileged/Baseline/Restricted 위반), SEC-02 위험 권한(cluster-admin·wildcard·secret list/watch),
  SEC-03 Secret 접근 분석, SEC-04 이미지 태그 정책(latest/digest 미사용/사내 registry), SEC-06 NetworkPolicy(기본 deny),
  SEC-07 TLS(만료일·CN/SAN), SEC-08 RBAC Diff(**PR1 리비전** 패턴 재사용), SEC-09 감사 이상(대량/반복 조회), SEC-10 정책 팩.
- SEC-05 Admission 시뮬레이터(CEL 기반 ValidatingAdmissionPolicy 스타일) — 분량 큼, 서브 PR로 분리 가능.
- **UI**: "보안 대시보드" + "정책 센터". **DW-06 security_finding_fact** emit.

### PR7 — 자동확장·용량 (SCALE-01~08)
- HPA 수집 추가. SCALE-01 HPA 현황, 02 확장 한계 도달, 03 과소 할당, 04 과다 할당(비용 절감 후보), 05 노드 용량 예측,
  06 replica 시뮬레이션, 07 bin packing 힌트, 08 GPU 자원. 메트릭 추세는 PR4/DW-05 누적분 활용.
- **UI**: "용량 대시보드".

### PR8 — ClickHouse 장기 분석 (6순위, DW-01~10)
- 기존 ClickHouse sink 인프라 재사용. fact 10종(event/pod_state/workload_health/node_metric/pod_metric/
  security_finding/action/cost/change/slo) 적재. **UI**: "리포트 센터" 일부.

### PR9 — Mattermost 알림 (7순위, NOTI-01~08)
- NOTI-01 위험 이벤트/노드 장애/배포 실패/보안 위반, 02 중복 제거(ns+workload+reason 묶음), 03 조용한 시간,
  04 담당팀 라우팅(**PR0 오너십**), 05 장애 요약, 06 비용 요약(**PR10**), 07 보안 요약, 08 딥링크.

### PR10 — 비용 / FinOps (DW-08 + 비용 대시보드)
- namespace/workload/team/cluster-group 비용 추정. **UI**: "비용 대시보드", NOTI-06 연동.

### PR11 — AI 운영 분석 (8순위, AI-OPS-01~08)
- 기존 LLM 프록시를 **내부 분석 보조**로만 사용(외부 프록시 노출 X). AI-OPS-01 자연어 장애 질문, 02 Runbook 추천,
  03 변경 영향 요약(diff→한국어), 04 알림 요약, 05 안전한 액션 제안, 06 운영 리포트, 07 사내 용어 매핑, 08 근거 중심 답변.

### PR12 — 운영 홈 + 설정 센터
- 운영 홈: 클러스터 위험 TOP5, 장애 후보 TOP10, 최근 변경 TOP10, 비용 증가 TOP10.
- 설정 센터: 수집 주기/보존 기간/알림 채널/단가/정책/권한.

---

## 4. 횡단 관심사 체크리스트 (모든 PR 공통)
- [ ] PG/SQLite 양쪽 마이그레이션 동작 (`s.bind`, `IF NOT EXISTS`).
- [ ] 민감값 마스킹 (manifest·env·secret·token).
- [ ] 새 화면은 `menuRegistry` + `menuVersion` bump + `route()` case + 권한 scope.
- [ ] 액션·보안·비용 변화는 ClickHouse fact로 emit(PR8 sink가 받음).
- [ ] 테스트: 스토어 라운드트립, 분석 룰 단위 테스트, 핸들러 테스트([internal/proxy/admin_k8s_test.go](internal/proxy/admin_k8s_test.go) 패턴).

## 5. 첫 작업
**PR0 → PR1** 순으로 시작. PR1의 `k8s_resource_revisions`가 Diff/Timeline/Config-RCA/RBAC-Diff/change_fact의
공통 토대이므로, 이 테이블 설계를 확정하는 것이 전체 2차 개발의 첫 임계 경로다.
