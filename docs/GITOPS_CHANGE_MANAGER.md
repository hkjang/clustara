# GitOps Change Manager Guide

Clustara의 GitOps Change Manager는 Argo CD나 Flux처럼 Git을 자동 sync하는 별도 CD 엔진이 아닙니다. Clustara 안의 Application Stack, YAML 변경/생성, Action Center, Resource Revision, Evidence 흐름을 Git 선언과 연결해 **drift를 설명하고, PR 초안을 남기고, 단계적 배포와 rollback 증적을 관리하는 변경관리 허브**입니다.

## 핵심 개념

| 개념 | 의미 | Clustara에서 하는 일 |
| --- | --- | --- |
| Application Stack | 여러 Kubernetes manifest를 하나의 앱 배포 단위로 저장한 선언 묶음 | validate, server-side apply, approval, history, rollback의 기준 |
| Git Source | Stack 또는 서비스가 어느 repo/branch/path에서 선언되는지 기록 | drift 판단과 PR draft의 출발점 |
| Drift | Git/Stack 선언과 live cluster 상태가 달라진 신호 | `live_only`, `spec_diff`, `in_sync`로 분류하고 위험도와 권장 행동 표시 |
| PR Draft | 실제 Git provider PR이 아니라, 어떤 diff를 어떤 방향으로 반영할지 남기는 초안 원장 | 외부 GitHub/GitLab 자동화 또는 사람이 PR을 만들 때 근거로 사용 |
| Git Provider | 사내 GitLab 또는 Bitbucket Server 연결 metadata | project, repository, branch, path를 catalog로 불러와 Git Source 입력 실수 감소 |
| Progressive Rollout | dev, qa, canary, prod 같은 단계와 gate를 기록한 배포 계획 | prod 전체 동시 반영을 피하고 단계별 승인·검증을 남김 |
| Change Calendar | freeze window, maintenance window, 업무 중요 기간 | 위험 변경 승인 전 배포 가능 시간인지 확인 |
| Deployment Evidence | 적용, 검증, 실패, rollback 결과를 evidence id와 함께 기록 | 인계, 감사, 사후 분석에 사용 |

## 언제 쓰나요?

| 상황 | 권장 동선 |
| --- | --- |
| 운영자가 UI에서 긴급 YAML 변경을 했음 | Drift Diff 확인 → PR Draft 생성 → Git에 반영 → Deployment Evidence 저장 |
| Git 선언과 live cluster가 달라짐 | Drift 분류 확인 → `Git을 기준으로 되돌릴지` 또는 `live 상태를 Git에 반영할지` 결정 |
| 운영 배포 전 freeze 여부 확인 필요 | Change Calendar 확인 → freeze면 긴급 사유와 추가 승인으로 처리 |
| 배포 실패 후 되돌릴 후보가 필요 | Rollback Plans에서 이전 Stack revision 확인 → Stack Rollback 또는 YAML 변경 요청 생성 |
| 여러 환경에 순차 배포해야 함 | Progressive Rollout에 단계와 gate 저장 → 각 단계 검증 후 다음 단계 진행 |

## 화면 사용 순서

1. `GitOps` 메뉴로 들어갑니다.
2. 클러스터 필터를 고릅니다.
3. `운영 가이드` 버튼으로 흐름을 확인합니다.
4. 사내 GitLab 또는 Bitbucket Server를 쓰는 경우 `사내 Git Provider 연동`에서 provider를 등록하고 catalog를 불러옵니다.
5. catalog에서 project/repository/branch/path를 선택해 `Git Source 연결` 폼에 채웁니다.
6. `GitOps 빠른 등록`에서 Stack에 repo, branch, path를 연결합니다.
7. `Drift and Change Readiness`와 `Drift Diff`에서 위험도와 권장 행동을 확인합니다.
8. drift나 hotfix가 있으면 `PR Draft 생성`에 반영 방향과 요약을 남깁니다.
9. 운영 배포 전에는 `Change Window`와 `Progressive Rollout`을 기록합니다.
10. 적용 후에는 `Deployment Evidence`로 승인, 적용, 검증, 관련 incident/ticket을 남깁니다.

## 사내 Git Provider 연동

| Provider | 필요한 입력 | Clustara가 불러오는 것 |
| --- | --- | --- |
| GitLab | Base URL, private token, project id 또는 `group/project` path | projects/repositories, branches, repository tree, raw file preview, Merge Request API payload preview |
| Bitbucket Server 6.x | Base URL, username/password 또는 PAT, project key, repo slug | projects, repositories, branches, browse tree, raw file preview, Pull Request API payload preview |

- provider 등록은 URL, 종류, username, 기본 branch 같은 metadata만 저장합니다.
- token/password 원문은 저장하지 않고 연결 확인과 catalog 조회 요청에만 일회성으로 사용합니다.
- `mock://gitlab` 또는 `mock://bitbucket_server`를 Base URL로 넣으면 폐쇄망 도입 전에도 catalog picker와 Git Source 자동 채우기 흐름을 검증할 수 있습니다.
- PR API Template은 외부 Git에 실제 요청을 보내지 않고 endpoint와 JSON payload만 생성합니다. 실제 PR 생성 자동화는 별도 승인·감사 정책과 함께 붙이는 것을 권장합니다.

## 안전 원칙

- GitOps 화면은 원장과 계획을 저장합니다. Kubernetes에 직접 쓰는 작업은 기존 Stack Apply 또는 YAML 변경/생성의 검증, 승인, Server-Side Apply 흐름으로만 진행합니다.
- Secret 원문은 GitOps 원장에 저장하지 않습니다. Secret 값은 sealed secret, external secret, secret manager 같은 외부 체계를 사용하세요.
- PR Draft는 실제 GitHub/GitLab PR이 아니라 Clustara 내부 초안입니다. 외부 provider 연동이 붙으면 이 원장을 PR 생성 입력으로 사용할 수 있습니다.
- Git provider catalog 조회는 읽기 전용이며, 외부 Git에 쓰는 작업은 PR API Template preview까지만 제공합니다.
- 운영 namespace의 high-risk 변경은 Action Center와 Manifest Change 승인 흐름을 우회하지 않습니다.

## 주요 API

| API | 용도 |
| --- | --- |
| `GET /admin/gitops/overview` | Stack의 Git 연결, drift, apply history, rollback 준비 상태 요약 |
| `GET/POST /admin/gitops/providers` | GitLab·Bitbucket Server provider metadata 조회·등록 |
| `GET/POST/DELETE /admin/gitops/providers/{id}` | provider 상세 조회·수정·비활성화 |
| `POST /admin/gitops/providers/test` | 일회성 token으로 provider 연결 확인 |
| `POST /admin/gitops/providers/catalog` | provider project/repo/branch/tree/file catalog 조회 |
| `POST /admin/gitops/providers/pr-template` | GitLab MR 또는 Bitbucket PR API payload preview |
| `GET/POST /admin/gitops/sources` | Git Source 원장 조회·등록 |
| `GET /admin/gitops/drift` | Stack별 drift 분류와 권장 행동 조회 |
| `GET/POST /admin/gitops/pr-drafts` | PR 초안 원장 조회·등록 |
| `GET/POST /admin/gitops/progressive-rollouts` | 단계적 배포 계획 조회·등록 |
| `GET/POST /admin/gitops/change-calendar` | freeze/maintenance window 조회·등록 |
| `GET/POST /admin/gitops/deployment-evidence` | 배포 증적 조회·등록 |
| `GET/POST /admin/gitops/rollback-plans` | rollback 후보와 계획 조회·등록 |

## 추천 운영 루틴

| 주기 | 확인할 것 |
| --- | --- |
| 매일 | Drifted Stack, 실패한 apply history, active freeze window |
| 배포 전 | Git Source 연결 여부, Change Calendar, Progressive Rollout gate, rollback 후보 |
| 배포 후 | Deployment Evidence, Stack history, Resource Timeline, Incident 여부 |
| 장애 후 | Drift Diff, 최근 PR Draft, Manifest Change evidence, rollback plan |
