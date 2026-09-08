package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"clustara/internal/store"
)

// ConnFinding is one Service/Ingress/PVC connectivity issue (K8S-22 / K8S-23 / K8S-24).
type ConnFinding struct {
	ClusterID    string   `json:"cluster_id"`
	Namespace    string   `json:"namespace"`
	ResourceKind string   `json:"resource_kind"`
	ResourceName string   `json:"resource_name"`
	Check        string   `json:"check"`
	Severity     string   `json:"severity"`
	Message      string   `json:"message"`
	Evidence     []string `json:"evidence"`
	Actions      []string `json:"actions"`
}

// AnalyzeConnectivity runs the Service, Ingress and PVC checks over an inventory snapshot.
func AnalyzeConnectivity(items []store.K8sInventoryItem, events []store.K8sEvent) []ConnFinding {
	out := []ConnFinding{}
	out = append(out, analyzeServices(items)...)
	out = append(out, analyzeIngresses(items)...)
	out = append(out, analyzePVCs(items, events)...)
	return out
}

// analyzeServices matches each Service's selector against Pod labels in the same namespace.
// A selector that matches no Pod means the Service has no endpoints (K8S-22).
func analyzeServices(items []store.K8sInventoryItem) []ConnFinding {
	// Pods are indexed per cluster+namespace: this analysis runs over the whole inventory when
	// the caller passes no cluster_id, and a Service only ever selects Pods inside its own
	// cluster. Matching on the namespace alone let another cluster's identically-named
	// namespace supply the endpoints, hiding a broken Service in the multi-cluster view.
	podsByNS := map[string][]store.K8sInventoryItem{}
	for _, it := range items {
		if it.Kind == "Pod" {
			key := it.ClusterID + "\x00" + it.Namespace
			podsByNS[key] = append(podsByNS[key], it)
		}
	}
	out := []ConnFinding{}
	for _, svc := range items {
		if svc.Kind != "Service" {
			continue
		}
		selector := stringValues(svc.Spec["selector"])
		if len(selector) == 0 {
			// Valid for headless/externalName/manually-managed endpoints; flag as low so it
			// is visible without drowning the high-signal findings.
			out = append(out, ConnFinding{
				ClusterID: svc.ClusterID, Namespace: svc.Namespace, ResourceKind: "Service", ResourceName: svc.Name,
				Check: "ServiceEmptySelector", Severity: "low",
				Message:  "Service에 selector가 없습니다(headless/ExternalName/수동 Endpoint일 수 있음).",
				Evidence: []string{"selector 없음"},
				Actions:  []string{"의도된 수동 Endpoint/ExternalName인지 확인합니다."},
			})
			continue
		}
		matches, serving := 0, 0
		for _, p := range podsByNS[svc.ClusterID+"\x00"+svc.Namespace] {
			if !labelsMatch(p.Labels, selector) {
				continue
			}
			matches++
			if !podReachedTerminalPhase(p) {
				serving++
			}
		}
		switch {
		case matches == 0:
			out = append(out, ConnFinding{
				ClusterID: svc.ClusterID, Namespace: svc.Namespace, ResourceKind: "Service", ResourceName: svc.Name,
				Check: "ServiceNoEndpoints", Severity: "high",
				Message:  "Service selector와 일치하는 Pod가 없어 endpoint가 비어 있습니다.",
				Evidence: []string{"selector: " + selectorString(selector)},
				Actions:  []string{"selector와 Pod label이 일치하는지 확인합니다.", "대상 워크로드가 실행 중인지(Ready Pod) 확인합니다."},
			})
		case serving == 0:
			out = append(out, ConnFinding{
				ClusterID: svc.ClusterID, Namespace: svc.Namespace, ResourceKind: "Service", ResourceName: svc.Name,
				Check: "ServiceNoEndpoints", Severity: "high",
				Message:  "Service selector와 일치하는 Pod가 모두 종료(Succeeded/Failed) 상태라 endpoint가 비어 있습니다.",
				Evidence: []string{"selector: " + selectorString(selector), fmt.Sprintf("일치 Pod %d개가 모두 종료 상태", matches)},
				Actions:  []string{"완료된 Job/CronJob Pod만 남아 있는지 확인합니다.", "대상 워크로드가 실행 중인지(Ready Pod) 확인합니다."},
			})
		}
	}
	return out
}

// ingressHostOwner is one Ingress that claims a host, kept as a record so the duplicate-host
// finding can carry the owner's cluster.
type ingressHostOwner struct {
	clusterID string
	namespace string
	name      string
}

func (o ingressHostOwner) ref() string { return o.namespace + "/" + o.name }

// ingressHostKey identifies a claimed host inside one cluster. Two clusters routing the same
// host (an active/standby pair mirrors its Ingresses) is the normal shape of a DR setup, not a
// routing conflict, so hosts are only ever compared within a cluster.
type ingressHostKey struct {
	clusterID string
	host      string
}

// ingressHostClaim is one Ingress's claim on a host, used to record a claim only once when the
// same Ingress lists the host in several rules.
type ingressHostClaim struct {
	key ingressHostKey
	ref string
}

// analyzeIngresses checks each Ingress backend Service exists, detects duplicate hosts across
// Ingresses, and flags TLS entries without a secretName (K8S-23).
func analyzeIngresses(items []store.K8sInventoryItem) []ConnFinding {
	// Keyed by cluster as well as namespace: a Service that only exists in another cluster does
	// not resolve this Ingress's backend, and treating it as one silently cleared a real
	// IngressBackendMissing whenever the report covered every cluster.
	svcByNS := map[string]bool{} // "cluster\x00ns/name" -> exists
	for _, it := range items {
		if it.Kind == "Service" {
			svcByNS[it.ClusterID+"\x00"+it.Namespace+"/"+it.Name] = true
		}
	}
	hostOwners := map[ingressHostKey][]ingressHostOwner{} // cluster+host -> claiming Ingresses
	hostClaimed := map[ingressHostClaim]bool{}            // cluster+host+owner -> already recorded
	out := []ConnFinding{}
	for _, ing := range items {
		if ing.Kind != "Ingress" {
			continue
		}
		owner := ingressHostOwner{clusterID: ing.ClusterID, namespace: ing.Namespace, name: ing.Name}
		// One finding per missing backend Service: the same Service is normally referenced by
		// several paths, and repeating an identical finding inflates the connectivity count.
		reportedBackend := map[string]bool{}
		checkBackend := func(svc map[string]any, where string) {
			name := str(svc["name"])
			if name == "" || svcByNS[ing.ClusterID+"\x00"+ing.Namespace+"/"+name] || reportedBackend[name] {
				return
			}
			reportedBackend[name] = true
			out = append(out, ConnFinding{
				ClusterID: ing.ClusterID, Namespace: ing.Namespace, ResourceKind: "Ingress", ResourceName: ing.Name,
				Check: "IngressBackendMissing", Severity: "high",
				Message:  "Ingress backend Service를 찾을 수 없습니다: " + name,
				Evidence: []string{"backend service: " + name, where},
				Actions:  []string{"backend Service 이름/namespace를 확인합니다.", "Service가 삭제되었거나 오타가 없는지 확인합니다."},
			})
		}
		for _, raw := range asAnySlice(ing.Spec["rules"]) {
			rule := asAnyMap(raw)
			if host := str(rule["host"]); host != "" {
				// One Ingress may list the same host in several rules (a legal way to group
				// paths); only distinct Ingresses claiming it are a routing conflict.
				hostKey := ingressHostKey{clusterID: ing.ClusterID, host: host}
				if claim := (ingressHostClaim{key: hostKey, ref: owner.ref()}); !hostClaimed[claim] {
					hostClaimed[claim] = true
					hostOwners[hostKey] = append(hostOwners[hostKey], owner)
				}
			}
			http := asAnyMap(rule["http"])
			for _, p := range asAnySlice(http["paths"]) {
				path := asAnyMap(p)
				checkBackend(asAnyMap(asAnyMap(path["backend"])["service"]), "path host: "+str(rule["host"]))
			}
		}
		// spec.defaultBackend serves every request that matches no rule, so a missing Service
		// there breaks the same traffic a missing per-path backend does.
		checkBackend(asAnyMap(asAnyMap(ing.Spec["defaultBackend"])["service"]), "defaultBackend")
		// TLS entries that reference no secret.
		for _, raw := range asAnySlice(ing.Spec["tls"]) {
			tls := asAnyMap(raw)
			if str(tls["secretName"]) == "" {
				out = append(out, ConnFinding{
					ClusterID: ing.ClusterID, Namespace: ing.Namespace, ResourceKind: "Ingress", ResourceName: ing.Name,
					Check: "IngressTLSNoSecret", Severity: "medium",
					Message:  "Ingress TLS 설정에 secretName이 없습니다.",
					Evidence: []string{"tls hosts: " + strings.Join(stringSlice(tls["hosts"]), ", ")},
					Actions:  []string{"TLS 인증서 Secret을 지정합니다.", "cert-manager 등으로 발급되는지 확인합니다."},
				})
			}
		}
	}
	// Sorted so the findings (and the report the UI renders in input order) are stable across runs.
	hostKeys := make([]ingressHostKey, 0, len(hostOwners))
	for key := range hostOwners {
		hostKeys = append(hostKeys, key)
	}
	sort.Slice(hostKeys, func(i, j int) bool {
		if hostKeys[i].clusterID != hostKeys[j].clusterID {
			return hostKeys[i].clusterID < hostKeys[j].clusterID
		}
		return hostKeys[i].host < hostKeys[j].host
	})
	for _, key := range hostKeys {
		host := key.host
		owners := hostOwners[key]
		if len(owners) > 1 {
			// Attribute the duplicate to the first owner; list the rest as evidence.
			refs := make([]string, 0, len(owners))
			for _, o := range owners {
				refs = append(refs, o.ref())
			}
			out = append(out, ConnFinding{
				ClusterID: owners[0].clusterID, Namespace: owners[0].namespace, ResourceKind: "Ingress", ResourceName: owners[0].name,
				Check: "IngressDuplicateHost", Severity: "medium",
				Message:  "동일 host를 여러 Ingress가 사용합니다: " + host,
				Evidence: []string{"host: " + host, "ingresses: " + strings.Join(refs, ", ")},
				Actions:  []string{"host 라우팅 충돌이 의도된 것인지 확인합니다.", "path/우선순위 충돌을 점검합니다."},
			})
		}
	}
	return out
}

// analyzePVCs flags Pending PVCs and correlates volume mount/attach failures (K8S-24).
func analyzePVCs(items []store.K8sInventoryItem, events []store.K8sEvent) []ConnFinding {
	out := []ConnFinding{}
	for _, pvc := range items {
		if pvc.Kind != "PersistentVolumeClaim" {
			continue
		}
		if !strings.Contains(strings.ToLower(pvc.Status), "pending") {
			continue
		}
		sc := str(pvc.Spec["storageClassName"])
		evidence := []string{"status: " + pvc.Status}
		if sc != "" {
			evidence = append(evidence, "storageClassName: "+sc)
		}
		for _, e := range events {
			// The cluster has to match too: the event feed spans clusters when the caller
			// asks for every cluster, and another cluster's namespace-mate would otherwise
			// be filed as this claim's provisioning error.
			if e.ClusterID != pvc.ClusterID || e.Namespace != pvc.Namespace || !eventConcernsPVC(e, pvc.Name) {
				continue
			}
			evidence = append(evidence, strings.TrimSpace(e.Reason+": "+e.Message))
		}
		out = append(out, ConnFinding{
			ClusterID: pvc.ClusterID, Namespace: pvc.Namespace, ResourceKind: "PersistentVolumeClaim", ResourceName: pvc.Name,
			Check: "PVCPending", Severity: "high",
			Message:  "PVC가 Pending 상태입니다(바인딩/프로비저닝 대기).",
			Evidence: trimEvidence(evidence),
			Actions:  []string{"StorageClass와 provisioner 상태를 확인합니다.", "용량/접근모드(ReadWriteOnce 등)와 가용 PV를 확인합니다.", "FailedMount/VolumeAttach 이벤트를 점검합니다."},
		})
	}
	return out
}

// eventConcernsPVC reports whether an event is evidence for this PVC.
//
// The involved object decides it: provisioning/binding events (ProvisioningFailed,
// WaitForFirstConsumer) are recorded on the claim itself, while mount/attach failures are
// recorded on the Pod and name the claim in the message. Accepting any volume-failure reason in
// the namespace — as the check used to — filed every namespace-mate's provisioning failure as
// this PVC's evidence, so a Pending PVC was reported with another PVC's error.
func eventConcernsPVC(e store.K8sEvent, pvcName string) bool {
	pvcName = strings.TrimSpace(pvcName)
	if pvcName == "" {
		return false
	}
	kind := strings.TrimSpace(e.InvolvedKind)
	name := strings.TrimSpace(e.InvolvedName)
	if name != "" && strings.EqualFold(kind, "PersistentVolumeClaim") {
		return strings.EqualFold(name, pvcName)
	}
	return volumeFailureReason(e.Reason) && strings.Contains(strings.ToLower(e.Message), strings.ToLower(pvcName))
}

func volumeFailureReason(reason string) bool {
	r := strings.ToLower(strings.TrimSpace(reason))
	return strings.Contains(r, "provisioningfailed") || strings.Contains(r, "failedmount") || strings.Contains(r, "failedattachvolume")
}

// --- small helpers (local to avoid touching shared analyzer helpers) ---

// podReachedTerminalPhase reports whether a Pod is in a terminal phase (Succeeded/Failed).
//
// The endpoints controller drops such Pods, but the API server keeps them in the inventory until
// they are garbage-collected, so a Service left over from a finished Job or fronting only evicted
// Pods looked like it still had endpoints. Pods that are merely unhealthy (Pending, CrashLoopBackOff)
// stay counted: they are still published as (not-ready) addresses and this check only asks whether
// the Service resolves to anything at all.
func podReachedTerminalPhase(p store.K8sInventoryItem) bool {
	phase := strings.TrimSpace(str(p.StatusObject["phase"]))
	if phase == "" {
		// The stored Status is the phase for Pods, except when a container waiting reason
		// (ImagePullBackOff 등) takes its place — those are never terminal phases.
		phase = strings.TrimSpace(p.Status)
	}
	return strings.EqualFold(phase, "Succeeded") || strings.EqualFold(phase, "Failed")
}

func labelsMatch(podLabels map[string]string, selector map[string]string) bool {
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

func stringValues(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, val := range m {
		out[k] = fmt.Sprintf("%v", val)
	}
	return out
}

func selectorString(sel map[string]string) string {
	parts := []string{}
	for k, v := range sel {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func asAnySlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asAnyMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func stringSlice(v any) []string {
	out := []string{}
	for _, x := range asAnySlice(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func trimEvidence(ev []string) []string {
	if len(ev) > 6 {
		return ev[:6]
	}
	return ev
}
