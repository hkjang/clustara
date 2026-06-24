package analyzer

import (
	"strings"
	"time"

	"clustara/internal/store"
)

type RCAFinding struct {
	ClusterID      string   `json:"cluster_id"`
	Namespace      string   `json:"namespace"`
	ResourceKind   string   `json:"resource_kind"`
	ResourceName   string   `json:"resource_name"`
	Condition      string   `json:"condition"`
	Severity       string   `json:"severity"`
	Cause          string   `json:"cause"`
	Evidence       []string `json:"evidence"`
	CheckResources []string `json:"check_resources"`
	Actions        []string `json:"actions"`
}

func AnalyzeRCA(items []store.K8sInventoryItem, events []store.K8sEvent) []RCAFinding {
	byKey := map[string][]store.K8sEvent{}
	for _, e := range events {
		key := rcaKey(e.Namespace, e.InvolvedKind, e.InvolvedName)
		byKey[key] = append(byKey[key], e)
	}
	out := []RCAFinding{}
	for _, item := range items {
		status := strings.ToLower(item.Status)
		if item.Kind != "Pod" && item.Kind != "Deployment" && item.Kind != "StatefulSet" && item.Kind != "DaemonSet" {
			continue
		}
		key := rcaKey(item.Namespace, item.Kind, item.Name)
		itemEvents := byKey[key]
		if len(itemEvents) == 0 && item.Kind != "Pod" {
			itemEvents = workloadRelatedEvents(item, events)
		}
		switch {
		case strings.Contains(status, "crashloopbackoff"):
			out = append(out, rca(item, "CrashLoopBackOff", "high", "컨테이너 프로세스가 반복 종료되고 있습니다.", itemEvents,
				[]string{"Pod logs --previous", "container exitCode", "ConfigMap/Secret env", "readiness/liveness probe"},
				[]string{"이전 컨테이너 로그를 확인합니다.", "최근 배포 이미지와 설정 변경을 확인합니다.", "probe 초기 지연과 의존 서비스 연결을 점검합니다."}))
		case strings.Contains(status, "imagepullbackoff") || strings.Contains(status, "errimagepull"):
			out = append(out, rca(item, "ImagePullBackOff", "high", "이미지 pull 또는 registry 인증에 실패했을 가능성이 큽니다.", itemEvents,
				[]string{"image name/tag", "imagePullSecrets", "registry connectivity", "ServiceAccount"},
				[]string{"이미지 태그와 registry 경로를 확인합니다.", "imagePullSecret 만료/권한을 확인합니다.", "노드에서 registry 접근 가능 여부를 확인합니다."}))
		case strings.Contains(status, "oomkilled"):
			out = append(out, rca(item, "OOMKilled", "high", "컨테이너가 메모리 제한을 초과해 종료되었습니다.", itemEvents,
				[]string{"container memory limit", "recent memory usage", "restart history"},
				[]string{"메모리 사용 추세를 확인합니다.", "limit/request 조정 또는 메모리 누수를 점검합니다.", "같은 노드의 메모리 압박을 확인합니다."}))
		case strings.Contains(status, "pending"):
			out = append(out, rca(item, "Pending", "medium", pendingCause(itemEvents), itemEvents,
				[]string{"FailedScheduling event", "node allocatable", "taints/tolerations", "PVC status", "quota"},
				[]string{"FailedScheduling 메시지의 부족 리소스를 확인합니다.", "PVC Pending 여부와 StorageClass를 확인합니다.", "namespace quota와 node taint를 확인합니다."}))
		case strings.Contains(status, "unavailable"):
			out = append(out, rca(item, "UnavailableReplicas", "medium", "원하는 replica 수에 도달하지 못했습니다.", itemEvents,
				[]string{"ReplicaSet", "Pod status", "rollout history", "events"},
				[]string{"하위 Pod 상태와 이벤트를 확인합니다.", "rollout 진행률과 maxUnavailable 설정을 확인합니다.", "필요 시 rollout restart 또는 rollback을 검토합니다."}))
		}
	}
	// Event-driven conditions the status string alone does not reveal
	// (probe failures, DNS resolution). RCA-05 / RCA-06 / RCA-07.
	out = append(out, analyzeProbeAndDNSEvents(events)...)
	// Status-object driven: rollout stalls (K8S-21) and Job/CronJob failures (K8S-25).
	out = append(out, analyzeRolloutAndJobs(items, events)...)
	// Node resource pressure from persisted node conditions (RCA-08 precise).
	out = append(out, analyzeNodeConditions(items)...)
	return out
}

// analyzeProbeAndDNSEvents scans Warning events for readiness/liveness probe failures and DNS
// resolution errors, deduplicated per resource+condition. RCA-05 / RCA-06 / RCA-07.
func analyzeProbeAndDNSEvents(events []store.K8sEvent) []RCAFinding {
	seen := map[string]bool{}
	out := []RCAFinding{}
	emit := func(e store.K8sEvent, condition, severity, cause string, checks, actions []string) {
		key := rcaKey(e.Namespace, e.InvolvedKind, e.InvolvedName) + "/" + condition
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, RCAFinding{
			ClusterID: e.ClusterID, Namespace: e.Namespace, ResourceKind: firstNonEmptyStr(e.InvolvedKind, "Pod"),
			ResourceName: e.InvolvedName, Condition: condition, Severity: severity, Cause: cause,
			Evidence: eventEvidence([]store.K8sEvent{e}), CheckResources: checks, Actions: actions,
		})
	}
	for _, e := range events {
		if !strings.EqualFold(e.Type, "Warning") {
			continue
		}
		msg := strings.ToLower(e.Message)
		reason := strings.ToLower(e.Reason)
		switch {
		case strings.Contains(msg, "readiness probe"):
			emit(e, "ReadinessProbeFailed", "medium", "Readiness probe 실패로 Pod가 Service endpoint에서 제외되고 있습니다.",
				[]string{"readiness probe 설정(path/port/timeout)", "Endpoints 제외 여부", "Service 영향", "의존 서비스 연결"},
				[]string{"probe 경로/포트와 initialDelaySeconds를 확인합니다.", "엔드포인트에서 빠진 Pod가 Service에 영향을 주는지 확인합니다."})
		case strings.Contains(msg, "liveness probe"):
			emit(e, "LivenessProbeFailed", "high", "Liveness probe 실패로 컨테이너가 반복 재시작될 수 있습니다.",
				[]string{"liveness probe timeout/initialDelay/failureThreshold", "컨테이너 기동 시간", "restart count"},
				[]string{"initialDelaySeconds/failureThreshold가 기동 시간 대비 충분한지 확인합니다.", "과도한 재시작 유발 여부를 점검합니다."})
		case isNodePressure(reason, msg):
			emit(e, "NodePressure", "high", "노드 자원 압박(메모리/디스크/PID) 또는 eviction이 감지되었습니다.",
				[]string{"node conditions(MemoryPressure/DiskPressure/PIDPressure)", "노드 allocatable", "영향 Pod", "eviction 이벤트"},
				[]string{"해당 노드의 압박 condition과 실제 사용량을 확인합니다.", "eviction 대상 Pod와 우선순위(PriorityClass)를 점검합니다.", "워크로드 재배치 또는 노드 증설을 검토합니다."})
		case isDNSFailure(msg, reason):
			emit(e, "DNSResolutionFailed", "medium", "DNS 조회 실패 가능성이 있습니다 — CoreDNS/Service name/NetworkPolicy를 점검하세요.",
				[]string{"CoreDNS Pod 상태", "Service name/namespace", "NetworkPolicy(egress 53)", "ndots/search domain"},
				[]string{"kube-system의 CoreDNS 상태를 확인합니다.", "대상 Service 이름과 namespace가 정확한지 확인합니다.", "NetworkPolicy가 DNS(53)를 막는지 확인합니다."})
		}
	}
	return out
}

func isNodePressure(reason, msg string) bool {
	for _, n := range []string{"evicted", "evictionthresholdmet", "nodehasdiskpressure", "nodehasmemorypressure", "nodehaspidpressure", "freediskspacefailed"} {
		if strings.Contains(reason, n) {
			return true
		}
	}
	return strings.Contains(msg, "disk pressure") || strings.Contains(msg, "memory pressure") || strings.Contains(msg, "was low on resource")
}

// AnalyzePostDeploymentErrors flags workloads whose error/restart events arrived AFTER a recent
// spec change, i.e. a deploy that likely introduced regressions. RCA-10 (배포 후 오류 증가).
func AnalyzePostDeploymentErrors(revisions []store.K8sResourceRevision, events []store.K8sEvent, now time.Time, lookback time.Duration) []RCAFinding {
	// Most recent "updated" revision per workload, within the lookback window.
	type dep struct {
		rev store.K8sResourceRevision
		at  time.Time
	}
	latest := map[string]dep{}
	for _, rev := range revisions {
		if rev.ChangeKind != "updated" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, rev.ObservedAt)
		if err != nil || now.Sub(at) > lookback {
			continue
		}
		key := rcaKey(rev.Namespace, rev.Kind, rev.Name)
		if cur, ok := latest[key]; !ok || at.After(cur.at) {
			latest[key] = dep{rev: rev, at: at}
		}
	}
	out := []RCAFinding{}
	for key, d := range latest {
		errs := []store.K8sEvent{}
		for _, e := range events {
			if !strings.EqualFold(e.Type, "Warning") || e.Namespace != d.rev.Namespace {
				continue
			}
			// Pods of a workload are named "<workload>-<hash>...", so match the workload name
			// or a child pod, then keep only events that happened after the deploy.
			if e.InvolvedName != d.rev.Name && !strings.HasPrefix(e.InvolvedName, d.rev.Name+"-") {
				continue
			}
			if when, err := time.Parse(time.RFC3339Nano, firstNonEmptyStr(e.LastSeen, e.FirstSeen)); err == nil && when.Before(d.at) {
				continue // pre-existing error, not caused by this deploy
			}
			errs = append(errs, e)
		}
		if len(errs) == 0 {
			continue
		}
		_ = key
		out = append(out, RCAFinding{
			ClusterID: d.rev.ClusterID, Namespace: d.rev.Namespace, ResourceKind: d.rev.Kind, ResourceName: d.rev.Name,
			Condition: "PostDeploymentErrors", Severity: "high",
			Cause:    "최근 배포(spec 변경) 직후 Warning 이벤트가 발생했습니다 — 배포가 장애를 유발했을 가능성이 있습니다.",
			Evidence: append([]string{"배포 시각: " + d.rev.ObservedAt}, eventEvidence(errs)...),
			CheckResources: []string{"rollout history", "이전/현재 image", "직전 diff", "배포 후 restart/error 추세"},
			Actions:        []string{"변경 타임라인에서 배포 전후를 비교합니다.", "필요 시 rollout undo(rollback)를 검토합니다.", "회귀가 확인되면 이전 리비전으로 되돌립니다."},
		})
	}
	return out
}

func isDNSFailure(msg, reason string) bool {
	if strings.Contains(reason, "dnsconfigforming") {
		return true
	}
	for _, needle := range []string{"no such host", "could not resolve", "name resolution", "lookup ", "server misbehaving", "i/o timeout", "dns"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// EnrichWithConfigChanges correlates each RCA finding with the most recent spec revision of the
// same resource. When a config/image change was observed within the lookback window before now,
// it is surfaced as evidence and a check action. RCA-09 (Config 변경 장애).
func EnrichWithConfigChanges(findings []RCAFinding, revisions []store.K8sResourceRevision, now time.Time, lookback time.Duration) []RCAFinding {
	latest := map[string]store.K8sResourceRevision{}
	for _, rev := range revisions {
		if rev.ChangeKind != "updated" {
			continue // only real changes, not the initial observation
		}
		key := rcaKey(rev.Namespace, rev.Kind, rev.Name)
		if cur, ok := latest[key]; !ok || rev.ObservedAt > cur.ObservedAt {
			latest[key] = rev
		}
	}
	for i := range findings {
		f := &findings[i]
		rev, ok := latest[rcaKey(f.Namespace, f.ResourceKind, f.ResourceName)]
		if !ok {
			continue
		}
		if when, err := time.Parse(time.RFC3339Nano, rev.ObservedAt); err == nil && now.Sub(when) > lookback {
			continue // change is too old to be a likely cause
		}
		detail := "spec"
		if rev.ImageSet != "" {
			detail = "image=" + rev.ImageSet
		}
		f.Evidence = append(f.Evidence, "직전 config 변경 감지("+detail+") @ "+rev.ObservedAt)
		f.Actions = append(f.Actions, "변경 타임라인에서 직전 diff를 확인하고 변경과 장애의 인과를 점검합니다.")
		if f.Severity == "medium" {
			f.Severity = "high" // a recent change raises the likelihood/urgency
		}
	}
	return findings
}

func rca(item store.K8sInventoryItem, condition, severity, cause string, events []store.K8sEvent, checks, actions []string) RCAFinding {
	return RCAFinding{
		ClusterID:      item.ClusterID,
		Namespace:      item.Namespace,
		ResourceKind:   item.Kind,
		ResourceName:   item.Name,
		Condition:      condition,
		Severity:       severity,
		Cause:          cause,
		Evidence:       eventEvidence(events),
		CheckResources: checks,
		Actions:        actions,
	}
}

func pendingCause(events []store.K8sEvent) string {
	for _, e := range events {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "insufficient") {
			return "스케줄링 가능한 노드의 CPU/Memory/GPU 등 가용 리소스가 부족합니다."
		}
		if strings.Contains(msg, "taint") {
			return "노드 taint와 Pod toleration 조건이 맞지 않습니다."
		}
		if strings.Contains(msg, "persistentvolumeclaim") || strings.Contains(msg, "pvc") {
			return "PVC 바인딩 또는 볼륨 마운트 문제로 스케줄링이 지연되고 있습니다."
		}
	}
	return "스케줄링 조건을 만족하지 못해 Pod가 Pending 상태입니다."
}

func workloadRelatedEvents(item store.K8sInventoryItem, events []store.K8sEvent) []store.K8sEvent {
	out := []store.K8sEvent{}
	for _, e := range events {
		if e.Namespace == item.Namespace && strings.Contains(e.Message, item.Name) {
			out = append(out, e)
		}
	}
	return out
}

func eventEvidence(events []store.K8sEvent) []string {
	out := []string{}
	for _, e := range events {
		s := strings.TrimSpace(e.Reason + ": " + e.Message)
		if s != ":" && s != "" {
			out = append(out, s)
		}
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func rcaKey(namespace, kind, name string) string {
	return namespace + "/" + kind + "/" + name
}
