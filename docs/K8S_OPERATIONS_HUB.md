# K8s Operations Hub MVP

이 문서는 기존 관리자 플랫폼 위에 추가된 Kubernetes 운영 허브 MVP API를 설명합니다.

## 범위

- 클러스터 등록과 kubeconfig/token 암호화 저장 참조
- Resource Inventory 스냅샷 적재
- Kubernetes Event, Metric sample 적재
- Health/security finding 자동 생성
- 위험 액션 요청과 승인/반려 워크플로우

아직 실제 Kubernetes API watch 실행기와 action executor는 연결하지 않았습니다. 현재 단계는 외부 collector나 향후 client-go collector가 보낼 표준 스냅샷을 저장하고 분석하는 기반입니다.

## API

| Method | Path | 설명 |
| --- | --- | --- |
| GET | `/admin/k8s/overview` | 클러스터, 인벤토리, warning event, finding, action 요약 |
| GET | `/admin/k8s/home` | 운영 홈 집계: 클러스터 위험 TOP5, 장애 후보 TOP10, 최근 변경 TOP10 |
| GET/POST | `/admin/k8s/clusters` | 클러스터 목록/등록 (`group_id`로 그룹 지정 가능) |
| GET/POST | `/admin/k8s/groups` | 클러스터 그룹 목록(롤업)/생성, `DELETE /groups/{id}` |
| GET/POST | `/admin/k8s/ownership` | 네임스페이스 오너십(담당팀·담당자·서비스·중요도·비용센터) 조회/설정 |
| GET | `/admin/k8s/clusters/{id}` | 클러스터 상세 |
| POST | `/admin/k8s/clusters/{id}/test` | API Server 연결 테스트, 버전/노드/네임스페이스 수 갱신 |
| POST | `/admin/k8s/clusters/{id}/collect` | Kubernetes API에서 라이브 인벤토리·이벤트·메트릭 수집 |
| POST | `/admin/k8s/snapshot` | 리소스, 이벤트, 메트릭 스냅샷 적재 |
| GET | `/admin/k8s/inventory` | 리소스 인벤토리 조회 |
| GET | `/admin/k8s/revisions` | 리소스 spec 변경 리비전 이력 (`cluster_id`,`kind`,`namespace`,`name`,`limit`) |
| GET | `/admin/k8s/diff` | 두 리비전의 필드 단위 diff (`from`/`to` 미지정 시 최근 2개 비교, 민감값 자동 마스킹) |
| GET | `/admin/k8s/timeline` | 리비전·이벤트·액션을 시간순 병합한 변경 타임라인 |
| GET | `/admin/k8s/manifest` | 현재 리소스 manifest YAML 조회 (Secret/token/env 민감값 자동 마스킹) |
| GET | `/admin/k8s/security` | Pod Security 등급, RBAC 위험, 이미지 태그, Secret 참조, NetworkPolicy 공백 포스처 |
| GET | `/admin/k8s/capacity` | HPA 현황·확장한계, 과소/과다 할당, 노드 bin-packing, GPU, 노드 용량 예측(SCALE-05) |
| GET | `/admin/k8s/capacity/simulate` | replica 시뮬레이션 (SCALE-06): `kind`,`namespace`,`name`,`replicas` |
| GET | `/admin/k8s/rbac-diff` | Role/ClusterRole 권한 확대 추적 (SEC-08, 리비전 기반) |
| GET/POST | `/admin/k8s/policies` | 정책 팩 목록/생성 (SEC-10), `DELETE /policies/{id}` |
| POST | `/admin/k8s/policies/simulate` | manifest 적용 전 정책 위반 검증 (SEC-05 Admission 시뮬레이터) |
| GET | `/admin/k8s/policies/compliance` | 현재 인벤토리의 정책 위반 목록 |
| GET | `/admin/k8s/cost` | request×단가 월 비용 추정 (namespace/team/group/cost-center), `cost/config`로 단가 조정 |
| POST | `/admin/k8s/cost/snapshot` | 일별 비용 스냅샷 기록 (비용 증가율 추세용, 로컬 누적) |
| GET | `/admin/k8s/cost/trend` | namespace별 전일 대비 비용 증가/감소 |
| POST | `/admin/k8s/ai/ask` | 자연어 장애 질문 — RCA·이벤트·diff 근거 기반 답변(LLM 미구성 시 근거만) |
| POST | `/admin/k8s/ai/report` | 클러스터 운영 상태 AI 요약 리포트 |
| POST | `/admin/k8s/dw/sink` | K8s fact(change/event/health/security/cost/action/metric)를 ClickHouse 적재 (미구성 시 no-op) |
| POST | `/admin/k8s/dw/bootstrap` | ClickHouse에 K8s fact 테이블 생성 (미구성 시 no-op) |
| POST | `/admin/k8s/actions/{id}/execute` | 승인된 액션을 실클러스터에 실행 (scale/rollout_restart/cordon/uncordon/delete_pod) |
| POST | `/admin/k8s/notify/scan` | 현재 high/critical 장애·보안을 평가해 Mattermost 알림(중복제거·조용한시간·담당팀 라우팅·딥링크) |
| GET/POST | `/admin/k8s/notify/config` | 조용한 시간(`quiet_hours` HH-HH) + 팀→채널 매핑(`team_channels` JSON) |
| GET | `/admin/k8s/events` | 이벤트 조회 |
| GET | `/admin/k8s/findings` | health/security finding 조회 |
| GET | `/admin/k8s/rca` | Pending, CrashLoop, ImagePull, OOM, unavailable + Readiness/Liveness probe, DNS, NodePressure, 직전 config 변경·배포 후 오류·배포 후 latency 회귀 연계 원인 후보 |
| POST | `/admin/k8s/latency/collect` | Prometheus에서 워크로드 latency 수집·적재 (RCA-10 latency, `PROMETHEUS_URL` 필요) |
| GET/POST | `/admin/k8s/latency/config` | latency PromQL + 라벨 매핑(namespace/workload) 설정 |
| GET | `/admin/k8s/connectivity` | Service selector↔Pod endpoint, Ingress backend/host/TLS, PVC Pending 점검 |
| GET/POST | `/admin/k8s/actions` | 액션 요청 목록/생성 |
| POST | `/admin/k8s/actions/{id}/approve` | 액션 승인 (요청 생성 시 영향도 자동 산출 → dry_run_diff, blocker 시 승인 강제) |
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
curl.exe -X POST http://localhost:8080/admin/k8s/clusters `
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
curl.exe -X POST http://localhost:8080/admin/k8s/clusters/k8scl_.../test
```

라이브 수집:

```powershell
curl.exe -X POST http://localhost:8080/admin/k8s/clusters/k8scl_.../collect
```

## 스냅샷 적재

```powershell
curl.exe -X POST http://localhost:8080/admin/k8s/snapshot `
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
curl.exe -X POST http://localhost:8080/admin/k8s/actions `
  -H "Content-Type: application/json" `
  -d '{
    "cluster_id": "k8scl_...",
    "namespace": "default",
    "resource_kind": "Pod",
    "resource_name": "api-123",
    "action": "delete_pod"
  }'
```

`delete_pod`, `cordon`, `drain`, `apply_manifest` 같은 위험 액션은 기본적으로 승인 대기 상태가 됩니다. 실제 실행기는 아직 연결되지 않았고, 승인/반려 기록과 감사 로그만 남깁니다.
