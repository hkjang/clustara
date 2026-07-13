# 서비스 플랫폼 가이드

Clustara Service Platform은 여러 Kubernetes 객체를 하나의 사용자 중심 서비스 인스턴스로 관리하는 상위 추상화 계층입니다. 실제 배포 실행기나 승인 엔진을 새로 만들지 않고 기존 Application Stack, Stack Apply, Action Center, 보안 정책, Resource Graph를 재사용합니다.

## 현재 구현 범위 (v0.9.135)

- 기본 카탈로그: PostgreSQL, Redis, Tomcat, Spring Boot, JupyterLab, JupyterHub
- 카탈로그 버전과 Small/Medium/Large 자원 프로파일
- 서비스 값 검증, `latest` 차단, 운영 환경 digest 고정, DNS label/replica 검증
- 생성 리소스·정책 사전 미리보기와 manifest 생성
- ServiceInstance 생성 시 기존 `k8s_application_stacks`와 append-only revision 생성
- 시작·중지·확장·재시작을 기존 Action Center의 `scale`/`rollout_restart` 승인 요청으로 변환
- 소유자 기반 목록 격리와 `service:*` capability 기반 메뉴/API 권한
- 서비스 홈, 카탈로그, 내 서비스, 전체 서비스, Jupyter, DB, WAS/앱, 작업 이력, 템플릿 화면
- 9개 서비스 업무 영역을 아이콘·설명·실시간 건수·현재 위치로 구분하고 모바일 가로 탐색을 지원하는 전용 소메뉴
- 오버플로 시에만 표시되는 이전·다음 컨트롤과 `←/→/Home/End` 키보드 focus 탐색
- 서비스 홈의 Ready 비율, 상태 요약, Jupyter/DB/WAS별 정상률, 위험·승인·만료 우선 조치 큐
- capability에 따른 생성·동기화·재시작·Stack 액션 노출과 제한 역할의 허용된 상세 경로 유지
- Application Stack manifest와 수집된 Kubernetes 인벤토리의 구성요소/Pod/PVC 동기화
- 워크로드·Endpoint·스토리지·재시작·백업·보안·자원 포화도를 합산한 100점 Health Score
- Service/Ingress/Route에서 내부·외부 Endpoint 파생 및 Kubernetes Secret 이름/key 참조 관리
- 관측된 Pod request 또는 선택한 자원 프로파일 기반 월 비용 추정
- 서비스 상세 화면의 **상태 동기화·검증**으로 구성요소, 누락, Health 증적, Endpoint, 비용을 즉시 재검증
- 런타임 설정 기반 주기 reconcile worker와 인스턴스별 DB lease 기반 멀티 Pod 중복 실행 방지
- 인벤토리 `missing/stale/observed` 구분: 수집 실패·지연은 실제 서비스 장애로 덮어쓰지 않고 `collecting`으로 표시
- Worker Dry-run, 즉시 동기화, 최근 처리·오류·lease skip 상태 화면
- PostgreSQL 논리 백업 Job 초안을 기존 Manifest Change Studio의 검증·승인·SSA Apply 흐름으로 연결
- 백업 Job 완료/실패를 reconcile하여 백업 원장과 Health Score에 반영
- 성공·무결성 검증된 PostgreSQL 백업의 Restore Preview와 차단 조건·영향도·복구 Job YAML 제공
- 원본 또는 사전 생성된 clone 대상 ServiceInstance로의 승인형 논리 복구와 복구 원장
- 서비스 데이터 PVC 기반 CSI VolumeSnapshot 초안, 선택적 VolumeSnapshotClass, `readyToUse` 상태 추적
- 검증 완료 VolumeSnapshot에서 새 PVC를 만드는 안전한 Clone Restore Preview·승인 초안·Bound 완료 증적
- Redis `redis-cli --rdb` 백업, 실제 scale-to-zero·실행 Pod 부재 확인, 전용 데이터 PVC RDB 복구와 완료 증적
- 단독 JupyterLab 작업공간 PVC 아카이브, 중지 상태 일관성 검증, 경로 이탈·링크 차단 staging 복구
- JupyterHub 표준 사용자·배포 라벨과 Notebook Pod volume을 결합한 사용자→Pod→PVC 매핑 및 사용자별 안전 백업·복구
- 서비스 범위 Credential Vault에 암호화한 JupyterHub API 연결과 토큰 비노출 연결 테스트
- 기본/Named Server 상태·마지막 활동·유휴 시간 조회와 Action Center 승인형 시작·중지
- Service reconcile 기반 유휴 종료 승인 요청 자동 생성, idempotency 중복 방지와 실행 직전 활동 재검사

사용자별 최대 동시 서버 수, 프로파일 기반 spawn options, VolumeSnapshotContent 기반 타 Namespace/클러스터 clone, 클론 PVC의 StatefulSet 자동 전환, 서비스별 exporter, Helm chart 원격 fetch/render, 의존성 Secret 자동 주입은 후속 단계입니다. 백업·복구 Job, VolumeSnapshot, 클론 PVC는 별도 실행기가 아니라 Manifest Change Studio에서 승인·적용합니다.

## 생성 흐름

1. **서비스 플랫폼 → 서비스 카탈로그**에서 서비스와 버전, 자원 프로파일을 선택합니다.
2. 클러스터, Namespace, 인스턴스명, 환경, Harbor 이미지를 입력합니다.
3. **리소스·정책 미리보기**로 입력값, 보안 조건, 생성 manifest를 검증합니다.
4. **Stack 초안 생성**은 ServiceInstance와 기존 Application Stack revision을 함께 만듭니다.
5. 운영 환경은 `pending_approval`로 표시됩니다. Stack 화면에서 기존 dry-run/정책/승인/SSA Apply 흐름을 진행합니다.
6. 재시작·확장은 Action Center 승인함에서 검토하고 기존 실행기로 수행합니다.
7. 서비스 상세의 **상태 동기화·검증**은 Stack 리소스와 최근 인벤토리/메트릭을 대조하고 Health snapshot을 저장합니다.

## 권한

| Capability | 기능 |
| --- | --- |
| `service:read` | 카탈로그와 허용된 인스턴스 조회 |
| `service:create` | 검증, 초안, 인스턴스/Stack 생성 |
| `service:update` | 구성 변경 |
| `service:operate` | 시작, 중지, 재시작, 확장 요청 |
| `service:delete` | 보존/백업 확인을 포함한 삭제 요청 |
| `service:backup`, `service:restore` | 백업·복구 요청 확장점 |
| `service:credential:read`, `service:credential:rotate` | Secret 원문 없는 접속정보 관리 |
| `service:approve` | 운영 요청 승인 |
| `service:catalog:manage` | 카탈로그·버전·템플릿 관리 |

Developer는 카탈로그와 본인 소유 서비스만 볼 수 있습니다. `service_admin`은 서비스 플랫폼 전체를 관리하며, Super Admin/Admin은 모든 capability를 가집니다. UI 숨김과 별개로 모든 API가 capability와 소유자/팀 범위를 다시 검사합니다.

## API

- `GET/POST /admin/k8s/services/catalogs`
- `GET/PUT/DELETE /admin/k8s/services/catalogs/{id}`
- `POST /admin/k8s/services/catalogs/{id}/versions`
- `POST /admin/k8s/services/catalogs/{id}/validate`
- `GET /admin/k8s/services/catalogs/{id}/schema`
- `GET/POST /admin/k8s/services/instances`
- `POST /admin/k8s/services/instances/draft|validate`
- `GET/DELETE /admin/k8s/services/instances/{id}`
- `POST /admin/k8s/services/instances/{id}/start|stop|restart|scale`
- `GET /admin/k8s/services/instances/{id}/health|topology`
- `POST /admin/k8s/services/instances/{id}/reconcile`
- `GET /admin/k8s/services/instances/{id}/endpoints|cost`
- `GET/POST /admin/k8s/services/instances/{id}/credentials`
- `GET/POST /admin/k8s/services/instances/{id}/jupyter-config`
- `GET /admin/k8s/services/instances/{id}/jupyter-servers`
- `POST /admin/k8s/services/instances/{id}/jupyter-server-actions`
- `GET/POST /admin/k8s/services/reconcile`
- `GET/POST /admin/k8s/services/instances/{id}/backups`
- `POST /admin/k8s/services/backups/{backupId}/restore-preview`
- `POST /admin/k8s/services/backups/{backupId}/restore`

Secret 값은 Clustara DB에 저장하지 않습니다. `k8s_service_credentials`는 Kubernetes Secret 이름과 key 참조만 저장하도록 설계되어 있습니다.

## 자동 동기화 런타임 설정

| 설정 key | 환경변수 | 기본값 |
| --- | --- | --- |
| `k8s.services.reconcile_enabled` | `K8S_SERVICE_RECONCILE_ENABLED` | `true` |
| `k8s.services.reconcile_interval_seconds` | `K8S_SERVICE_RECONCILE_INTERVAL_SECONDS` | `300` |
| `k8s.services.reconcile_batch_size` | `K8S_SERVICE_RECONCILE_BATCH_SIZE` | `100` |
| `k8s.services.reconcile_timeout_seconds` | `K8S_SERVICE_RECONCILE_TIMEOUT_SECONDS` | `30` |
| `k8s.services.inventory_stale_seconds` | `K8S_SERVICE_INVENTORY_STALE_SECONDS` | `900` |
| `k8s.services.health_retention_days` | `K8S_SERVICE_HEALTH_RETENTION_DAYS` | `90` |
| `k8s.services.jupyterhub_idle_threshold_minutes` | `K8S_SERVICE_JUPYTERHUB_IDLE_THRESHOLD_MINUTES` | `60` |
| `k8s.services.jupyterhub_http_timeout_seconds` | `K8S_SERVICE_JUPYTERHUB_HTTP_TIMEOUT_SECONDS` | `10` |
| `k8s.services.jupyterhub_user_limit` | `K8S_SERVICE_JUPYTERHUB_USER_LIMIT` | `500` |

런타임 설정 화면에서 저장하면 재시작 없이 다음 worker tick에 반영됩니다. `POST /admin/k8s/services/reconcile`의 `dry_run=true`는 Health를 계산하지만 구성요소·snapshot·인스턴스 상태를 변경하지 않습니다.

JupyterHub 서비스 상세의 **API 설정**에서 서비스 계정 API URL, 토큰, 서비스별 유휴 기준과 자동 승인 요청 여부를 설정합니다. 토큰은 `enterprise_records`의 서비스 scope에 암호화되어 API 응답에 포함되지 않습니다. 자동 유휴 정책은 Notebook을 직접 종료하지 않고 Action Center 요청만 만들며, 승인·실행 시 현재 활동이 기준보다 최근이면 stop 호출을 차단합니다.

## 백업·복구 안전 흐름

1. 논리 백업은 DB 데이터 PVC가 아닌 별도 Bound PVC와 Kubernetes Secret 참조를 사용합니다.
2. CSI Snapshot은 해당 서비스에 연결된 Bound 데이터 PVC만 원본으로 선택할 수 있습니다.
3. 생성되는 Job, VolumeSnapshot, 클론 PVC는 항상 Manifest Change Studio의 schema/policy/dry-run/승인을 거칩니다.
4. 논리 복구는 성공 및 비어 있지 않은 파일 검증이 끝난 백업만 사용할 수 있습니다.
5. Restore Preview는 대상 PostgreSQL 유형, 클러스터·Namespace, 백업 PVC, Service, Secret 참조를 검사합니다.
6. 원본 인스턴스 복구는 데이터 충돌 경고를 표시합니다. 다른 인스턴스 ID를 지정하면 사전 생성된 clone 대상 복구로 처리합니다.
7. 복구 Job은 백업 PVC를 read-only로 마운트하고 `psql --set ON_ERROR_STOP=on`으로 오류 즉시 종료합니다.
8. 스냅샷 복구는 `readyToUse`와 동일 클러스터·Namespace, 동일 서비스 유형, 새 PVC 이름, 요청 용량, 기존 PVC 충돌을 검사합니다.
9. 허용된 스냅샷 복구는 `dataSource.kind: VolumeSnapshot`인 새 PVC만 생성하며 기존 PVC나 워크로드 볼륨 연결을 자동 변경하지 않습니다.
10. 새 PVC가 `Bound`로 관측되면 복구 원장을 성공으로 전환합니다. 실제 워크로드 전환은 별도 영향도 분석·승인 변경으로 진행합니다.
11. Redis 논리 백업은 Secret 원문 없이 `REDISCLI_AUTH`와 `redis-cli --rdb`를 사용해 별도 Bound 백업 PVC에 RDB를 저장합니다.
12. Redis RDB 복구는 대상 StatefulSet/Deployment의 `spec.replicas=0`, 준비 Replica 0, 실행 중 Pod 없음이 실제 인벤토리에서 확인되어야 합니다.
13. 대상 데이터 PVC는 `Bound`이며 대상 Redis 서비스 label/이름과 연결되어야 합니다. 복구 Job은 임시 파일로 복사한 후 `dump.rdb`로 원자적 교체하며, 완료 후 시작 요청과 데이터 검증이 필요합니다.
14. JupyterLab 파일 백업은 작업공간 PVC를 read-only, 별도 백업 PVC를 read-write로 마운트하며 실제 scale-to-zero와 실행 중 Pod 부재를 요구합니다.
15. JupyterLab 복구는 tar 경로 이탈과 symlink/hardlink·특수 파일을 거부하고 `.clustara-restore/<작업ID>`에만 해제합니다. 기존 파일은 덮어쓰지 않으며 사용자가 검증한 파일만 수동 승격합니다.
16. JupyterHub는 `hub.jupyter.org/username`, `hub.jupyter.org/deployment`, `app.kubernetes.io/instance`, `clustara.io/service-instance`와 Pod `persistentVolumeClaim` mount를 결합해 사용자→Pod→PVC를 매핑합니다.
17. JupyterHub 사용자별 파일 백업은 요청 사용자와 PVC 매핑이 일치하고 해당 Notebook Pod가 비활성인 경우만 허용합니다. 복구도 백업 당시 사용자 소유권 증적과 대상 사용자·PVC가 모두 일치해야 합니다.
18. 사용자/PVC 충돌은 `conflict`로 표시하고 백업·복구에서 차단합니다. Secret 값은 작업공간 탐색에 사용하지 않습니다.
