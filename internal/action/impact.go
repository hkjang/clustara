package action

import (
	"fmt"
	"strings"

	"clustara/internal/store"
)

// Impact is the read-only "what will this action affect" assessment computed from the stored
// inventory before an action is approved. It never mutates the cluster (ACT-01~07 안전장치).
type Impact struct {
	Summary  string         `json:"summary"`
	Blockers []string       `json:"blockers"` // conditions that force human approval
	Details  map[string]any `json:"details"`
}

// AssessImpact summarizes the effect of an action on a target resource, using the full
// inventory snapshot for fan-out actions (cordon/drain need the pods on the node).
func AssessImpact(actionName string, params map[string]any, target store.K8sInventoryItem, all []store.K8sInventoryItem) Impact {
	name := strings.ToLower(strings.TrimSpace(actionName))
	switch name {
	case "scale":
		cur := currentReplicas(target)
		desired := num(params["replicas"])
		return Impact{
			Summary: fmt.Sprintf("replicas %d → %d (%+d)", cur, desired, desired-cur),
			Details: map[string]any{"current_replicas": cur, "desired_replicas": desired},
		}
	case "rollout_restart":
		return Impact{
			Summary: fmt.Sprintf("%s/%s 의 모든 Pod가 순차 재생성됩니다(rolling).", target.Kind, target.Name),
			Details: map[string]any{"strategy": "rolling restart"},
		}
	case "delete_pod":
		owned := podControllerOwned(target)
		imp := Impact{Summary: fmt.Sprintf("Pod %s 삭제", target.Name), Details: map[string]any{"controller_owned": owned}}
		if owned {
			imp.Summary += " — controller가 자동으로 재생성합니다."
		} else {
			imp.Summary += " — standalone Pod이라 자동 재생성되지 않습니다."
			imp.Blockers = append(imp.Blockers, "standalone Pod 삭제는 승인이 필요합니다(자동 복구 없음).")
		}
		return imp
	case "cordon", "uncordon":
		pods := podsOnNode(target.Name, all)
		return Impact{
			Summary: fmt.Sprintf("노드 %s: 현재 %d개 Pod(%d개 namespace) 영향. cordon은 신규 스케줄만 차단합니다.", target.Name, len(pods), countNamespaces(pods)),
			Details: map[string]any{"affected_pods": len(pods), "namespaces": namespaceList(pods)},
		}
	case "drain":
		pods := podsOnNode(target.Name, all)
		local, ds := 0, 0
		for _, p := range pods {
			if hasLocalStorage(p) {
				local++
			}
			if podControllerKindIsDaemonSet(p) {
				ds++
			}
		}
		imp := Impact{
			Summary: fmt.Sprintf("노드 %s drain: %d개 Pod evict(local-storage %d, DaemonSet %d). PDB는 미수집이라 별도 확인 필요.", target.Name, len(pods), local, ds),
			Details: map[string]any{"affected_pods": len(pods), "local_storage_pods": local, "daemonset_pods": ds, "namespaces": namespaceList(pods)},
		}
		imp.Blockers = append(imp.Blockers, "drain은 다수 워크로드를 evict할 수 있어 승인이 필요합니다.")
		if local > 0 {
			imp.Blockers = append(imp.Blockers, fmt.Sprintf("local storage(emptyDir/hostPath) Pod %d개의 데이터가 유실될 수 있습니다.", local))
		}
		return imp
	case "patch", "apply_manifest":
		allowed := map[string]bool{"image": true, "replicas": true, "annotations": true}
		bad := []string{}
		for k := range params {
			if !allowed[strings.ToLower(k)] {
				bad = append(bad, k)
			}
		}
		imp := Impact{Summary: fmt.Sprintf("%s/%s patch (허용 필드: image/replicas/annotations)", target.Kind, target.Name), Details: map[string]any{"fields": keysOf(params)}}
		if len(bad) > 0 {
			imp.Blockers = append(imp.Blockers, "허용되지 않은 patch 필드: "+strings.Join(bad, ", "))
		}
		return imp
	default:
		return Impact{Summary: "사용자 정의 액션 — 영향도를 자동 산출할 수 없습니다.", Blockers: []string{"알 수 없는 액션은 승인이 필요합니다."}}
	}
}

func currentReplicas(it store.K8sInventoryItem) int {
	if v, ok := it.Spec["replicas"]; ok {
		return num(v)
	}
	if it.StatusObject != nil {
		return num(it.StatusObject["replicas"])
	}
	return 0
}

func podsOnNode(node string, all []store.K8sInventoryItem) []store.K8sInventoryItem {
	out := []store.K8sInventoryItem{}
	for _, it := range all {
		if it.Kind == "Pod" && asString(it.Spec["nodeName"]) == node {
			out = append(out, it)
		}
	}
	return out
}

func podControllerOwned(pod store.K8sInventoryItem) bool {
	for _, k := range []string{"pod-template-hash", "controller-revision-hash", "job-name", "batch.kubernetes.io/job-name"} {
		if _, ok := pod.Labels[k]; ok {
			return true
		}
	}
	return false
}

func podControllerKindIsDaemonSet(pod store.K8sInventoryItem) bool {
	// Heuristic: DaemonSet pods carry a controller-revision-hash but no pod-template-hash.
	_, hasRev := pod.Labels["controller-revision-hash"]
	_, hasTmpl := pod.Labels["pod-template-hash"]
	return hasRev && !hasTmpl
}

func hasLocalStorage(pod store.K8sInventoryItem) bool {
	vols, ok := pod.Spec["volumes"].([]any)
	if !ok {
		return false
	}
	for _, raw := range vols {
		v, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := v["emptyDir"]; ok {
			return true
		}
		if _, ok := v["hostPath"]; ok {
			return true
		}
	}
	return false
}

func countNamespaces(pods []store.K8sInventoryItem) int { return len(namespaceList(pods)) }

func namespaceList(pods []store.K8sInventoryItem) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range pods {
		if !seen[p.Namespace] {
			seen[p.Namespace] = true
			out = append(out, p.Namespace)
		}
	}
	return out
}

func keysOf(m map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func num(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	}
	return 0
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
