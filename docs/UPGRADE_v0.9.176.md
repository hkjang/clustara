# 업그레이드 가이드 — v0.9.164 → v0.9.176

v0.9.165 부터 v0.9.176 까지 **동작이 바뀐 항목**만 모았습니다. 릴리즈 노트 12개를
훑지 않고도 업그레이드 전에 확인해야 할 것을 한 번에 볼 수 있게 하는 것이 목적입니다.

기능 추가와 내부 수정은 각 릴리즈 노트에 있습니다. 여기에는 **기존 동작이 달라지는
것**만 적었습니다.

---

## 0. 30초 요약

업그레이드 전에 이 세 가지만 확인하면 대부분의 사고를 막습니다.

1. **기동이 거부될 수 있습니다.** `SSO_KEYCLOAK_ENABLED=true` 인데 `AUTH_ENABLED` 가
   꺼져 있으면 프로세스가 뜨지 않습니다. → [1절](#1-기동이-거부되는-설정)
2. **승인 실행이 차단될 수 있습니다.** 롤아웃 승인 시점에 PDB·진행 중 rollout·삭제
   중 조건이 생겼으면 실행이 막힙니다. → [2절](#2-롤아웃-승인-실행이-차단될-수-있음)
3. **자기 승인이 막힙니다.** 터미널 세션을 요청한 사람이 그 세션을 승인할 수
   없습니다. → [3절](#3-터미널-세션-자기-승인-차단)

다중 replica 로 운영 중이라면 [7절](#7-다중-replica-운영-시-필수-확인)을 추가로
확인하세요.

---

## 1. 기동이 거부되는 설정

설정이 맞지 않으면 프로세스가 **기동 단계에서 종료**됩니다. 잘못된 상태로 뜨는 것보다
낫지만, 업그레이드 직후 컨테이너가 재시작 루프에 빠질 수 있으므로 먼저 확인하세요.

| 조건 | 오류 메시지 | 도입 |
| --- | --- | --- |
| `SSO_KEYCLOAK_ENABLED=true` + `AUTH_ENABLED` 미설정 | `AUTH_ENABLED=true is required when SSO_KEYCLOAK_ENABLED=true` | v0.9.165 |
| `K8S_ROLLOUT_RECONCILER_LEASE_TTL` < `K8S_ROLLOUT_RECONCILER_INTERVAL` | `... LEASE_TTL must be at least ... INTERVAL` | v0.9.165 |
| 워커 주기·배치 값이 0 이하 | `... must be positive` | v0.9.165 |
| `WORKER_SHUTDOWN_TIMEOUT` 이 음수 | `... must be non-negative` | v0.9.165 |

> lease TTL 이 tick 주기보다 짧으면 다른 replica 가 아직 진행 중인 롤아웃을 넘겨받아
> 패치를 **이중 실행**할 수 있습니다. 그래서 경고가 아니라 기동 거부입니다.

**기본값만 쓰면 이 검증에 걸리지 않습니다.** 워커 값을 직접 설정한 경우에만 확인하세요.

---

## 2. 롤아웃 승인 실행이 차단될 수 있음

**도입: v0.9.172**

precheck 의 차단 판정은 롤아웃을 **요청하는 시점**에만 평가됐고, 실행 직전 재검증은
target UID 와 spec hash drift 만 봤습니다. 승인이 몇 시간 뒤에 이뤄지면 그 사이 생긴
차단 조건은 아무도 보지 않은 채 실행됐습니다.

이제 실행 직전에 아래 세 가지를 다시 확인하고, 해당하면 **실행을 차단**합니다.

| 조건 | 이유 |
| --- | --- |
| 삭제 처리 중인 target | 사라지는 리소스를 교체할 수 없습니다 |
| 진행 중인 template rollout | 이전 template Pod 가 남아 있는데 새 rollout 을 겹칩니다 |
| PodDisruptionBudget 이 중단 불허 | 클러스터가 지금 Pod 손실을 감당할 수 없습니다 |

인벤토리를 읽지 못해 PDB 판정이 불가능하면 통과시키지 않고 사유를 보고합니다.

**의도적으로 차단하지 않는 것**: Pod 비정상·replica 미충족. 망가진 워크로드를
되살리려는 재시작을 막지 않기 위해서이며, 요청 시점의 차단 판정으로는 유지됩니다.

**영향**: 승인 대기 시간이 긴 운영에서 이전에는 통과하던 실행이 `실행 차단: ...` 으로
실패할 수 있습니다. 차단된 롤아웃은 terminal 상태가 되며 재시도 루프에 빠지지
않습니다. 조건을 해소한 뒤 새로 요청하세요.

---

## 3. 터미널 세션 자기 승인 차단

**도입: v0.9.173**

정책 엔진이 승인을 요구한 Pod 터미널 세션을 **요청자 본인이 승인할 수 없습니다**.
요청자와 결정자가 같으면 `403 exec_session_self_approval` 입니다.

- **자기 요청 철회(reject)는 계속 허용**됩니다. 접근 권한을 얻는 행위가 아닙니다.
- **`super_admin` 은 영향을 받지 않습니다.** 내장 break-glass 정책으로 승인 단계 자체를
  거치지 않습니다. 단일 관리자 배포는 `super_admin` 을 쓰면 막히지 않습니다.
- **관리자 인증이 비활성이면 규칙이 적용되지 않습니다.** 모든 호출자가 `anonymous` 라
  분리할 두 신원이 없습니다. 이 통제를 쓰려면 인증을 활성화해야 합니다.

**확인 방법**: 승인이 필요한 세션을 운영자 두 명이 처리하는 동선이 준비돼 있는지,
아니면 `super_admin` 으로 접근하는지 미리 정하세요.

---

## 4. 프로덕션 스킬 가드레일 필수화

**도입: v0.9.174**

스킬을 `production` 으로 저장하려면 승격 경로든 `POST /admin/skills` upsert 경로든
아래가 모두 채워져 있어야 합니다. 누락 시 `400` 과 함께 빠진 항목을 나열합니다.

- 지침(`instructions`)
- 허용 모델(`allowed_models`)
- 허용 도구(`allowed_tools`)
- 허용 팀(`allowed_teams`)
- 일일 한도(`daily_limit` > 0)

미설정 가드레일은 실행 시점에 **제한 없음**으로 해석되므로, 비워 둔 채 프로덕션에
올린 스킬은 모든 모델·도구·팀에서 한도 없이 실행됩니다. 이전에는 upsert 로 그런 스킬을
만들 수 있었습니다.

`draft`·`staging`·status 미지정은 제약이 없습니다.

**확인 방법**: 스킬 등록을 자동화했다면 프로덕션 스킬 생성 요청에 위 다섯 항목이
들어 있는지 확인하세요.

---

## 5. API 응답·상태 코드 변화

| 엔드포인트 | 변화 | 도입 |
| --- | --- | --- |
| `GET /admin/k8s/exec/sessions/{id}/stream` | Bearer 토큰만으로는 열리지 않음. 1회성 티켓 필수 (`401 terminal_ticket_required`) | v0.9.165 |
| `POST /admin/k8s/services/instances/{id}/reconcile` | 다른 reconcile 진행 중이면 `409` | v0.9.169 |
| 롤아웃 거절 | 상태 불일치 시 `409`, 없는 레코드 `404` (이전에는 조용히 성공) | v0.9.170 |
| Manifest rollback 요청 | 원본이 `applied`·`verified`·`verify_failed` 가 아니면 `409` (이전에는 `201`) | v0.9.170 |
| 프롬프트 랩 실행 | 응답에 `model_limit`·`dropped_models` 추가 | v0.9.175 |
| 과대 요청 본문 거절 | 보고되는 크기가 실제 본문 크기가 아니라 읽은 만큼 | v0.9.175 |

---

## 6. 새 환경 변수

전부 기본값이 있으며 **설정하지 않아도 됩니다.** 기본값으로 이전과 동등하거나 더
안전하게 동작합니다.

| 변수 | 기본값 | 용도 |
| --- | --- | --- |
| `WORKER_OWNER_ID` | `<hostname>-<pid>` | 롤아웃 lease 소유자. **replica 마다 달라야 합니다** |
| `WORKER_SHUTDOWN_TIMEOUT` | `15s` | 종료 시 진행 중 tick 이 lease 를 반납하기까지 대기 |
| `K8S_ROLLOUT_RECONCILER_ENABLED` | `true` | 롤아웃 리컨실러 사용 여부 |
| `K8S_ROLLOUT_RECONCILER_INTERVAL` | `5s` | tick 주기 |
| `K8S_ROLLOUT_RECONCILER_LEASE_TTL` | `1m` | 복제본 간 lease 유효시간 (interval 이상) |
| `K8S_ROLLOUT_RECONCILER_BATCH_SIZE` | `100` | tick 당 처리 수 |
| `K8S_ROLLOUT_RECONCILER_MAX_BACKOFF` | `2m` | 연속 실패 시 최대 대기 |
| `K8S_TERMINAL_REAPER_ENABLED` | `true` | 터미널 세션 리퍼 사용 여부 |
| `K8S_TERMINAL_REAPER_INTERVAL` | `30s` | tick 주기 |
| `K8S_TERMINAL_REAPER_BATCH_SIZE` | `250` | tick 당 검사 수 |
| `K8S_TERMINAL_REAPER_MAX_BACKOFF` | `5m` | 연속 실패 시 최대 대기 |
| `SERVER_SCHEDULERS_ENABLED` | `true` | 주기 스케줄러 전체 사용 여부 |
| `LIMITS_MAX_REQUEST_BYTES` | `0`(비활성) | 채팅 요청 본문 상한. 설정하면 **읽기 자체가** 한도+1 바이트에서 멈춤 |

> `SERVER_SCHEDULERS_ENABLED=false` 는 API 전용 replica 용입니다. **어느 replica 에서도
> 켜져 있지 않으면 인벤토리·메트릭·비용·서비스 상태가 수렴하지 않습니다.**

자세한 설명은 [운영 가이드 5.5·5.6](./OPERATIONS.md) 참고.

---

## 7. 다중 replica 운영 시 필수 확인

- **`WORKER_OWNER_ID` 는 replica 마다 달라야 합니다.** 지정하지 않으면 hostname+pid 로
  자동 생성되므로 대개 문제 없지만, 명시적으로 넣는 경우 값이 겹치지 않게 하세요.
- **모든 Pod 가 동일한 PostgreSQL 을 사용해야 합니다.** Pod 별 로컬 SQLite 구성은
  지원하지 않습니다(터미널 티켓·lease 가 공유 DB 기준입니다).
- 롤아웃 리컨실러는 lease 로 단일 소유를 보장하므로 replica 를 늘려도 중복 실행되지
  않습니다.

---

## 8. 업그레이드 후 확인

```bash
# 1) 기동 확인 (설정 거부 시 여기서 실패)
curl -fsS http://localhost:9090/readyz

# 2) 워커가 실제로 돌고 있는지 — overall 이 ok 인지 확인
curl -fsS http://localhost:9090/admin/ops/workers | jq '.overall, .workers[] | {name, status, running}'

# 3) 워커 메트릭이 노출되는지
curl -fsS http://localhost:9090/metrics | grep clustara_worker_
```

`/admin/ops/workers` 는 이제 **측정된 상태**를 보고합니다. 설정으로 꺼진 스케줄러는
`유휴`, 켜져 있는데 실행되지 않으면 `위험` 입니다. 이전 버전은 일부 워커를 실행 중으로
하드코딩하고 있었으므로, 업그레이드 후 처음으로 실제 상태가 보입니다 — **새로 나타난
경고가 업그레이드 때문에 생긴 문제가 아니라 원래 있던 상태일 수 있습니다.**

특히 `retention` 워커는 이전에 실행 시각을 성공 시각으로 보고했습니다. 업그레이드 후
`최근 실행 실패` 가 보인다면 그 실패는 이전부터 있었을 가능성이 높습니다.

---

## 9. 롤백

문제가 생기면 이전 태그로 되돌립니다. 이 구간의 스키마 변경은 **테이블·인덱스 추가와
기존 행 정규화뿐이며 컬럼 삭제나 데이터 파괴가 없습니다.** 다만 아래 한 가지는 롤백
후에도 남으므로 미리 알고 계셔야 합니다.

> **롤아웃 대상 잠금 인덱스는 롤백해도 남습니다.**
> v0.9.165 마이그레이션이 `idx_k8s_rollout_one_active_target_v2` 를 만듭니다. 이 부분
> unique 인덱스는 기존 v1 보다 **범위가 넓어** 진행 중인 롤백까지 같은 대상의 활성
> 롤아웃으로 봅니다. 마이그레이션은 이 인덱스를 지우지 않으므로 v0.9.164 로 되돌려도
> DB 에 남아 계속 적용됩니다.
>
> 결과적으로 되돌린 v0.9.164 에서 **롤백이 진행 중인 대상에 새 롤아웃을 요청하면**
> 이전에는 통과하던 요청이 unique 제약 오류로 실패할 수 있습니다. 롤백이 끝나면
> 해소됩니다. 즉시 풀어야 한다면 인덱스를 직접 제거하세요.
>
> ```sql
> DROP INDEX IF EXISTS idx_k8s_rollout_one_active_target_v2;
> ```
>
> 다시 v0.9.165 이상으로 올라가면 마이그레이션이 인덱스를 재생성합니다.

```bash
gunzip -c clustara-v0.9.164.tar.gz | docker load
docker rm -f clustara && docker run -d --name clustara ... clustara:v0.9.164
```

되돌린 뒤에는 2·3·4절의 차단이 다시 사라집니다. 그동안 차단으로 실패한 롤아웃·승인은
다시 요청해야 합니다.
