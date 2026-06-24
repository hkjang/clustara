# Clustara Realtime Collector Agent

`clustara-agent`는 클러스터 내부에서 Kubernetes watch API를 구독하고 Clustara 서버의
`POST /admin/k8s/agent/events`로 delta 이벤트와 heartbeat를 전송합니다.

- 권한은 기본적으로 `get/list/watch`만 사용합니다.
- 실클러스터 action executor 권한과 분리됩니다.
- resourceVersion 상태 파일과 offline queue 파일을 사용해 재시작/일시 단절을 복구합니다.
- 서버는 watch event key로 중복을 제거하므로 같은 batch가 재전송되어도 inventory/revision이 중복 적용되지 않습니다.

## 1. 공통 준비

먼저 Clustara UI의 `#/k8s-clusters`에서 클러스터를 등록하고 `cluster_id`를 확인합니다.
agent는 이미 등록된 `cluster_id`로만 batch를 받습니다.

필수 값:

| 값 | 설명 |
| --- | --- |
| `CLUSTARA_CLUSTER_ID` | Clustara에 등록된 클러스터 ID |
| `CLUSTARA_URL` | agent Pod에서 접근 가능한 Clustara 서버 URL |
| `CLUSTARA_TOKEN` | Clustara admin token 또는 agent ingest 전용 토큰 |
| image | `/app/clustara-agent` 바이너리가 포함된 Clustara 이미지 |

샘플 매니페스트는 [deploy/k8s/clustara-agent.yaml](../deploy/k8s/clustara-agent.yaml)에 있습니다.
`REPLACE_WITH_*` 값을 바꾼 뒤 적용하세요.

## 2. minikube에서 테스트

로컬 PC에서 Clustara를 실행 중이면 minikube Pod는 보통 `host.minikube.internal`로 PC에 접근할 수 있습니다.
예를 들어 Clustara가 `http://localhost:9091`에서 실행 중이면 agent에는 다음처럼 넣습니다.

```powershell
$env:CLUSTARA_URL = "http://host.minikube.internal:9091"
$env:CLUSTARA_CLUSTER_ID = "k8scl_xxxxxxxxxxxxxxxx"
$env:CLUSTARA_TOKEN = "dev-admin"
```

로컬 이미지를 minikube에 넣습니다.

```powershell
docker build -t clustara:dev .
minikube image load clustara:dev
```

샘플을 복사해 값을 치환합니다.

```powershell
Copy-Item deploy/k8s/clustara-agent.yaml deploy/k8s/clustara-agent.local.yaml
(Get-Content deploy/k8s/clustara-agent.local.yaml) `
  -replace 'ghcr.io/hkjang/clustara:v0.4.0', 'clustara:dev' `
  -replace 'REPLACE_WITH_CLUSTER_ID', $env:CLUSTARA_CLUSTER_ID `
  -replace 'https://REPLACE_WITH_CLUSTARA_URL', $env:CLUSTARA_URL `
  -replace 'REPLACE_WITH_CLUSTARA_ADMIN_TOKEN', $env:CLUSTARA_TOKEN |
  Set-Content deploy/k8s/clustara-agent.local.yaml
kubectl apply -f deploy/k8s/clustara-agent.local.yaml
```

확인:

```powershell
kubectl -n clustara-system get pod -l app.kubernetes.io/name=clustara-agent
kubectl -n clustara-system logs deploy/clustara-agent --tail=80
```

Clustara UI의 `#/k8s-collector`에서 agent가 `live`로 보이고 `resourceVersion Checkpoint`가 갱신되면 정상입니다.

## 3. 운영 K8s 클러스터

운영망에서는 다음 원칙을 권장합니다.

- `CLUSTARA_URL`은 클러스터 내부에서 접근 가능한 HTTPS 주소를 사용합니다.
- `CLUSTARA_TOKEN`은 Kubernetes Secret, ExternalSecret, SealedSecret 등으로 주입합니다.
- 상태 파일 `/var/lib/clustara-agent/state.json`은 기본 `emptyDir`입니다. Pod 재스케줄까지 이어가야 하면 PVC로 바꿉니다.
- NetworkPolicy가 있다면 agent namespace에서 Clustara URL로 egress를 허용합니다.
- RBAC는 샘플처럼 `get/list/watch`만 부여하고, scale/restart/delete 같은 action executor 권한과 섞지 않습니다.

적용 후 확인:

```bash
kubectl -n clustara-system rollout status deploy/clustara-agent
kubectl -n clustara-system logs deploy/clustara-agent --tail=100
curl -H "Authorization: Bearer $CLUSTARA_TOKEN" "$CLUSTARA_URL/admin/k8s/agent/status?cluster_id=$CLUSTARA_CLUSTER_ID"
```

장애 재현 검증 예:

```bash
kubectl create ns clustara-agent-test
kubectl -n clustara-agent-test create deploy nginx --image=nginx --replicas=1
kubectl -n clustara-agent-test scale deploy/nginx --replicas=2
kubectl -n clustara-agent-test set image deploy/nginx nginx=not-exist:bad
```

수동 collect 없이 Clustara의 inventory, timeline, incident 후보가 갱신되어야 합니다.

## 4. 주요 환경 변수

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `CLUSTARA_URL` | 없음 | Clustara 서버 base URL |
| `CLUSTARA_AGENT_ENDPOINT` | `$CLUSTARA_URL/admin/k8s/agent/events` | batch 전송 endpoint 직접 지정 |
| `CLUSTARA_CLUSTER_ID` | 없음 | 등록된 클러스터 ID |
| `CLUSTARA_AGENT_ID` | Pod hostname | agent 식별자 |
| `CLUSTARA_TOKEN` | 없음 | Clustara admin/ingest token |
| `WATCH_KINDS` | 전체 | 쉼표 구분 kind 필터. 예: `Pod,Deployment,Event` |
| `CLUSTARA_AGENT_BATCH_INTERVAL` | `2s` | batch flush 주기 |
| `CLUSTARA_AGENT_HEARTBEAT_INTERVAL` | `30s` | heartbeat 주기 |
| `CLUSTARA_AGENT_STATE_FILE` | `/var/lib/clustara-agent/state.json` | resourceVersion checkpoint |
| `CLUSTARA_AGENT_QUEUE_FILE` | `/var/lib/clustara-agent/queue.ndjson` | offline batch queue |
| `KUBE_API_SERVER` | in-cluster service | Kubernetes API URL |
| `KUBE_TOKEN_FILE` | serviceaccount token | Kubernetes bearer token file |
| `KUBE_CA_FILE` | serviceaccount CA | Kubernetes CA file |
| `KUBE_INSECURE_TLS` | `false` | 테스트 클러스터에서만 사용 |
