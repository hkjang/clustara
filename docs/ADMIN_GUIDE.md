# 관리자 가이드 (Admin Guide)

Clustara(Kubernetes 운영 허브) 어드민 UI(`http://<host>:8080/admin`)의 메뉴별 사용법입니다. 모든 화면은 동일한 이름의 REST API(`/admin/k8s/*`)로도 자동화할 수 있습니다. API 상세·클러스터 등록은 **[K8s 운영 허브 가이드](K8S_OPERATIONS_HUB.md)** 를 참고하세요.

## 접속과 권한

- UI 상단 "관리자 토큰" 입력란에 `ADMIN_TOKEN` 값을 넣으면 데이터가 로드됩니다.
- 메뉴는 스코프로 게이팅됩니다: K8s 운영 메뉴는 `admin:read`, 보안/정책 센터는 `security:read`.
- 기본 랜딩은 **운영 홈**(`#/k8s-home`). SSO/역할 사용 시 `security_admin`은 보안 화면으로 랜딩.

## 메뉴 구성

운영(운영 홈·클러스터·변경 타임라인·장애 분석·연결성 점검·액션 승인함·용량·자동확장·그룹·오너십·AI 분석) · 비용 · 보안 · 정책 센터 · 운영 설정 · 설정.

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

## 3. 변경 타임라인 (`#/k8s-timeline`)

리소스의 **spec 리비전·이벤트·액션**을 시간축으로 병합해 장애 전후 변화를 추적합니다.

- 필터(클러스터·namespace·이름·kind) 지정 시: 직전 **Resource Diff**(replica/image/env/resource limit/ingress host 하이라이트, 민감값 마스킹)와 **현재 Manifest**(YAML, Secret/token/env 마스킹)가 함께 표시됩니다.
- API: `GET /admin/k8s/timeline`, `/admin/k8s/diff`, `/admin/k8s/manifest`, `/admin/k8s/revisions`

## 4. 장애 분석 (`#/k8s-rca`)

규칙 기반 **원인 후보**를 심각도순으로 보여줍니다 — 원인·근거 이벤트·점검 대상·조치 후보 + 타임라인 딥링크.

- 탐지: CrashLoop/OOM/ImagePull/Pending/Unavailable, Readiness/Liveness probe, DNS, NodePressure(노드 condition), 직전 Config 변경 연계(24h), 배포 후 오류, Rollout 정체, Job/CronJob 실패.
- API: `GET /admin/k8s/rca`

## 5. 연결성 점검 (`#/k8s-conn`)

- **Service**: selector↔Pod 매칭 → endpoint 없음/selector 불일치
- **Ingress**: backend Service 존재·host 중복·TLS secretName 누락
- **PVC**: Pending + FailedMount/ProvisioningFailed 이벤트 연계
- API: `GET /admin/k8s/connectivity`

## 6. 액션 승인함 (`#/k8s-actions`)

위험 작업의 **요청 → 영향도 → 승인 → 실행** 워크플로우.

- 요청 생성 시 영향도가 자동 산출되어 `dry_run_diff`에 기록되고, blocker(standalone Pod 삭제·drain·허용 외 patch 필드 등)가 있으면 자동으로 **승인 필수**로 격상됩니다.
- **승인**된 액션은 **실행** 버튼으로 실클러스터에 반영: `scale`/`rollout_restart`/`cordon`/`uncordon`/`delete_pod`. drain은 수동.
- API: `GET/POST /admin/k8s/actions`, `POST /admin/k8s/actions/{id}/approve|reject|execute`

## 7. 용량·자동확장 (`#/k8s-capacity`)

- **HPA 현황/확장 한계**(desired=max 경고), **과소/과다 할당**(사용량 vs request), **노드 bin packing**(요청률), **GPU**(가용/요청/유휴), **노드 용량 예측**(증가율→소진 예상일), **Replica 시뮬레이션**(목표 replica의 request 합계).
- API: `GET /admin/k8s/capacity`, `/admin/k8s/capacity/simulate`

## 8. 그룹·오너십 (`#/k8s-meta`)

- **클러스터 그룹**(업무망/개발망/운영망/인터넷망/DMZ): 그룹별 클러스터 롤업(정상/위험/멤버).
- **네임스페이스 오너십**: 담당팀·담당자·서비스명·중요도·비용센터 — 알림 라우팅(NOTI-04)과 비용 집계의 기준.
- API: `GET/POST /admin/k8s/groups`(+`DELETE /groups/{id}`), `GET/POST /admin/k8s/ownership`

## 9. AI 분석 (`#/k8s-ai`)

자연어 장애 질의·운영 리포트. 수집된 **RCA·Warning 이벤트·변경 diff를 근거**로만 답합니다(근거 없으면 추측하지 않음). LLM 업스트림(`UPSTREAM_*`) 미설정 시 LLM 답변 대신 근거 데이터를 반환합니다.

- API: `POST /admin/k8s/ai/ask`, `POST /admin/k8s/ai/report`

## 10. 비용 (`#/k8s-cost`)

request×단가 기반 **월 비용 추정** — namespace/담당팀/클러스터 그룹/비용센터별 집계 + 단가 편집.

- API: `GET /admin/k8s/cost`, `GET/POST /admin/k8s/cost/config`

## 11. 보안 (`#/k8s-security`)

- **Pod Security 등급**(Privileged/Baseline/Restricted), **RBAC 위험**(cluster-admin·wildcard·secret 접근), **이미지 태그 정책**, **Secret 참조**, **NetworkPolicy 공백**, **RBAC 권한 변경**(리비전 기반), **감사 이상**(위험 액션 반복), **TLS 인증서 만료**(x509 CN/SAN/만료일) + 보안 점수.
- API: `GET /admin/k8s/security`, `/admin/k8s/rbac-diff`

## 12. 정책 센터 (`#/k8s-policy`)

- **정책 팩**(SEC-10): 7종 룰(privileged/hostNetwork/hostPath/latest태그/resource limits/runAsNonRoot/wildcard RBAC)을 Deny/Warn/Audit 액션으로 등록, 현재 인벤토리 컴플라이언스 검사.
- **Admission 시뮬레이터**(SEC-05): manifest(kind+spec)를 적용 전 정책에 검증해 allow/deny 미리보기.
- API: `GET/POST /admin/k8s/policies`(+`DELETE`, `/simulate`, `/compliance`)

## 13. 운영 설정 (`#/k8s-settings`)

비용 단가(KRW/vCPU·월, KRW/GB·월)와 알림(조용한 시간 `HH-HH`, 팀→Mattermost 채널 매핑 JSON)을 한 곳에서 설정합니다. 수집 주기·보존 기간은 게이트웨이 설정(설정 메뉴)을 따릅니다.

- API: `GET/POST /admin/k8s/cost/config`, `/admin/k8s/notify/config`

---

## 알림 (Mattermost)

`POST /admin/k8s/notify/scan`이 현재 high/critical 장애·보안을 평가해 알림을 보냅니다 — **중복 제거**(6h 윈도우)·**조용한 시간**·**담당팀 채널 라우팅**·리소스 **딥링크** 포함. cron/`/loop`으로 주기 호출하세요. Mattermost webhook은 기존 알림 설정에서 구성합니다.

## 장기 분석 (ClickHouse)

`CLICKHOUSE_URL` 설정 후 `POST /admin/k8s/dw/bootstrap`(테이블 생성) → `POST /admin/k8s/dw/sink`(fact 적재, 주기 호출). 미설정 시 no-op.

## 일상 운영 체크리스트

1. **운영 홈**에서 위험 클러스터·장애 후보·최근 변경 확인
2. 장애 후보는 **장애 분석**에서 근거·조치 검토 → 필요 시 **액션 승인함**으로 요청·승인·실행
3. **연결성 점검**으로 Service/Ingress/PVC 이상 점검
4. 주간: **보안**(Pod Security·RBAC·TLS 만료)·**용량**(확장 한계·과다 할당)·**비용** 리뷰
5. **정책 센터**로 표준 정책 위반 추적, 배포 전 **Admission 시뮬레이터** 활용
