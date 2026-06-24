package analyzer

import (
	"fmt"
	"strings"

	"clustara/internal/store"
)

// analyzeRolloutAndJobs inspects the raw .status of workloads/jobs (now persisted as
// StatusObject) to surface rollout stalls (K8S-21) and Job/CronJob failures (K8S-25).
func analyzeRolloutAndJobs(items []store.K8sInventoryItem, events []store.K8sEvent) []RCAFinding {
	byKey := map[string][]store.K8sEvent{}
	for _, e := range events {
		byKey[rcaKey(e.Namespace, e.InvolvedKind, e.InvolvedName)] = append(byKey[rcaKey(e.Namespace, e.InvolvedKind, e.InvolvedName)], e)
	}
	out := []RCAFinding{}
	for _, it := range items {
		evs := byKey[rcaKey(it.Namespace, it.Kind, it.Name)]
		switch it.Kind {
		case "Deployment", "StatefulSet":
			if f, ok := rolloutFinding(it, evs); ok {
				out = append(out, f)
			}
		case "Job":
			if f, ok := jobFinding(it, evs); ok {
				out = append(out, f)
			}
		case "CronJob":
			if f, ok := cronJobFinding(it); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// analyzeNodeConditions reads each Node's persisted status.conditions and flags real resource
// pressure (Memory/Disk/PID), listing the pods scheduled on the node. RCA-08 (precise — not
// event-inferred), enabled by the StatusObject persistence added in PR4b.
func analyzeNodeConditions(items []store.K8sInventoryItem) []RCAFinding {
	podsByNode := map[string][]string{}
	for _, it := range items {
		if it.Kind == "Pod" {
			if n := str(it.Spec["nodeName"]); n != "" {
				podsByNode[n] = append(podsByNode[n], it.Namespace+"/"+it.Name)
			}
		}
	}
	out := []RCAFinding{}
	for _, it := range items {
		if it.Kind != "Node" {
			continue
		}
		pressures := []string{}
		for _, raw := range asAnySlice(it.StatusObject["conditions"]) {
			c := asAnyMap(raw)
			typ, st := str(c["type"]), str(c["status"])
			if st == "True" && (typ == "MemoryPressure" || typ == "DiskPressure" || typ == "PIDPressure") {
				pressures = append(pressures, typ)
			}
		}
		if len(pressures) == 0 {
			continue
		}
		pods := podsByNode[it.Name]
		ev := []string{"압박 condition: " + strings.Join(pressures, ", "), fmt.Sprintf("영향 Pod 수: %d", len(pods))}
		for i, p := range pods {
			if i >= 5 {
				break
			}
			ev = append(ev, "  pod: "+p)
		}
		out = append(out, RCAFinding{
			ClusterID: it.ClusterID, ResourceKind: "Node", ResourceName: it.Name,
			Condition: "NodePressure", Severity: "high",
			Cause:          "노드 자원 압박(" + strings.Join(pressures, ", ") + ") 상태입니다 — eviction이 발생할 수 있습니다.",
			Evidence:       ev,
			CheckResources: []string{"node allocatable/usage", "eviction threshold", "영향 Pod PriorityClass"},
			Actions:        []string{"압박 자원(메모리/디스크/PID) 사용 원인을 확인합니다.", "워크로드 재배치 또는 노드 증설을 검토합니다."},
		})
	}
	return out
}

func rolloutFinding(it store.K8sInventoryItem, evs []store.K8sEvent) (RCAFinding, bool) {
	st := it.StatusObject
	desired := numVal(it.Spec["replicas"])
	if _, ok := it.Spec["replicas"]; !ok {
		desired = 1 // Deployment/StatefulSet default
	}
	available := numVal(st["availableReplicas"])
	updated := numVal(st["updatedReplicas"])
	ready := numVal(st["readyReplicas"])

	stuck, condMsg := false, ""
	for _, raw := range asAnySlice(st["conditions"]) {
		c := asAnyMap(raw)
		if str(c["type"]) == "Progressing" && str(c["reason"]) == "ProgressDeadlineExceeded" {
			stuck, condMsg = true, str(c["message"])
		}
	}
	// Healthy rollout: enough updated+available replicas and not deadline-stuck.
	if !stuck && desired > 0 && available >= desired && updated >= desired {
		return RCAFinding{}, false
	}
	if !stuck && desired == 0 {
		return RCAFinding{}, false
	}
	severity := "medium"
	if stuck || available == 0 {
		severity = "high"
	}
	cause := fmt.Sprintf("rollout 미완료: updated %d / ready %d / available %d / desired %d", updated, ready, available, desired)
	if stuck {
		cause = "rollout이 ProgressDeadline을 초과해 멈춰 있습니다. " + condMsg
	}
	evidence := append([]string{cause}, eventEvidence(evs)...)
	return RCAFinding{
		ClusterID: it.ClusterID, Namespace: it.Namespace, ResourceKind: it.Kind, ResourceName: it.Name,
		Condition: "RolloutStuck", Severity: severity, Cause: cause, Evidence: trimEvidence(evidence),
		CheckResources: []string{"ReplicaSet/Pod 상태", "이미지/probe 설정", "ProgressDeadlineSeconds", "events(FailedCreate 등)"},
		Actions:        []string{"하위 Pod의 이벤트·로그를 확인합니다.", "이미지/probe/리소스 설정을 점검합니다.", "필요 시 rollout undo(rollback)를 검토합니다."},
	}, true
}

func jobFinding(it store.K8sInventoryItem, evs []store.K8sEvent) (RCAFinding, bool) {
	st := it.StatusObject
	failed := numVal(st["failed"])
	succeeded := numVal(st["succeeded"])
	if failed == 0 {
		return RCAFinding{}, false
	}
	severity := "medium"
	if failed >= 3 {
		severity = "high"
	}
	evidence := []string{fmt.Sprintf("failed %d / succeeded %d", failed, succeeded)}
	if t := str(st["startTime"]); t != "" {
		evidence = append(evidence, "startTime: "+t)
	}
	if t := str(st["completionTime"]); t != "" {
		evidence = append(evidence, "마지막 완료: "+t)
	}
	evidence = append(evidence, eventEvidence(evs)...)
	cause := "Job이 반복 실패하고 있습니다."
	if succeeded == 0 {
		cause = "Job이 한 번도 성공하지 못했습니다."
	}
	return RCAFinding{
		ClusterID: it.ClusterID, Namespace: it.Namespace, ResourceKind: "Job", ResourceName: it.Name,
		Condition: "JobFailing", Severity: severity, Cause: cause, Evidence: trimEvidence(evidence),
		CheckResources: []string{"Pod logs", "backoffLimit", "command/args", "이미지/권한"},
		Actions:        []string{"실패 Pod의 로그를 확인합니다.", "backoffLimit과 재시도 정책을 점검합니다.", "입력/권한/네트워크 의존성을 확인합니다."},
	}, true
}

func cronJobFinding(it store.K8sInventoryItem) (RCAFinding, bool) {
	st := it.StatusObject
	lastSchedule := str(st["lastScheduleTime"])
	lastSuccess := str(st["lastSuccessfulTime"])
	// Scheduled at least once but never recorded a successful run.
	if lastSchedule == "" || lastSuccess != "" {
		return RCAFinding{}, false
	}
	return RCAFinding{
		ClusterID: it.ClusterID, Namespace: it.Namespace, ResourceKind: "CronJob", ResourceName: it.Name,
		Condition: "CronJobNoSuccess", Severity: "medium",
		Cause:    "CronJob이 스케줄됐지만 성공 기록이 없습니다.",
		Evidence: []string{"lastScheduleTime: " + lastSchedule, "lastSuccessfulTime: 없음"},
		CheckResources: []string{"최근 Job/Pod 상태", "schedule/suspend", "concurrencyPolicy", "startingDeadlineSeconds"},
		Actions:        []string{"최근 생성된 Job의 실패 원인을 확인합니다.", "suspend 여부와 스케줄 표현식을 점검합니다."},
	}, true
}

func numVal(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		// status counts are normally numeric; tolerate string just in case.
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
		return n
	}
	return 0
}
