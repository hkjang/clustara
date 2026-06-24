package analyzer

import (
	"fmt"
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
	pods := []store.K8sInventoryItem{}
	for _, it := range items {
		if it.Kind == "Pod" {
			pods = append(pods, it)
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
		matches := 0
		for _, p := range pods {
			if p.Namespace == svc.Namespace && labelsMatch(p.Labels, selector) {
				matches++
			}
		}
		if matches == 0 {
			out = append(out, ConnFinding{
				ClusterID: svc.ClusterID, Namespace: svc.Namespace, ResourceKind: "Service", ResourceName: svc.Name,
				Check: "ServiceNoEndpoints", Severity: "high",
				Message:  "Service selector와 일치하는 Pod가 없어 endpoint가 비어 있습니다.",
				Evidence: []string{"selector: " + selectorString(selector)},
				Actions:  []string{"selector와 Pod label이 일치하는지 확인합니다.", "대상 워크로드가 실행 중인지(Ready Pod) 확인합니다."},
			})
		}
	}
	return out
}

// analyzeIngresses checks each Ingress backend Service exists, detects duplicate hosts across
// Ingresses, and flags TLS entries without a secretName (K8S-23).
func analyzeIngresses(items []store.K8sInventoryItem) []ConnFinding {
	svcByNS := map[string]bool{} // "ns/name" -> exists
	for _, it := range items {
		if it.Kind == "Service" {
			svcByNS[it.Namespace+"/"+it.Name] = true
		}
	}
	hostOwners := map[string][]string{} // host -> ["ns/ingress", ...]
	out := []ConnFinding{}
	for _, ing := range items {
		if ing.Kind != "Ingress" {
			continue
		}
		for _, raw := range asAnySlice(ing.Spec["rules"]) {
			rule := asAnyMap(raw)
			if host := str(rule["host"]); host != "" {
				hostOwners[host] = append(hostOwners[host], ing.Namespace+"/"+ing.Name)
			}
			http := asAnyMap(rule["http"])
			for _, p := range asAnySlice(http["paths"]) {
				path := asAnyMap(p)
				backend := asAnyMap(path["backend"])
				svc := asAnyMap(backend["service"])
				name := str(svc["name"])
				if name == "" {
					continue
				}
				if !svcByNS[ing.Namespace+"/"+name] {
					out = append(out, ConnFinding{
						ClusterID: ing.ClusterID, Namespace: ing.Namespace, ResourceKind: "Ingress", ResourceName: ing.Name,
						Check: "IngressBackendMissing", Severity: "high",
						Message:  "Ingress backend Service를 찾을 수 없습니다: " + name,
						Evidence: []string{"backend service: " + name, "path host: " + str(rule["host"])},
						Actions:  []string{"backend Service 이름/namespace를 확인합니다.", "Service가 삭제되었거나 오타가 없는지 확인합니다."},
					})
				}
			}
		}
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
	for host, owners := range hostOwners {
		if len(owners) > 1 {
			// Attribute the duplicate to the first owner; list the rest as evidence.
			ns, name := splitNSName(owners[0])
			out = append(out, ConnFinding{
				Namespace: ns, ResourceKind: "Ingress", ResourceName: name,
				Check: "IngressDuplicateHost", Severity: "medium",
				Message:  "동일 host를 여러 Ingress가 사용합니다: " + host,
				Evidence: append([]string{"host: " + host}, "ingresses: "+strings.Join(owners, ", ")),
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
			if e.Namespace != pvc.Namespace {
				continue
			}
			r := strings.ToLower(e.Reason)
			if strings.Contains(r, "provisioningfailed") || strings.Contains(r, "failedmount") || strings.Contains(r, "failedattachvolume") || strings.Contains(strings.ToLower(e.Message), pvc.Name) {
				evidence = append(evidence, strings.TrimSpace(e.Reason+": "+e.Message))
			}
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

// --- small helpers (local to avoid touching shared analyzer helpers) ---

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

func splitNSName(s string) (string, string) {
	if i := strings.Index(s, "/"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

func trimEvidence(ev []string) []string {
	if len(ev) > 6 {
		return ev[:6]
	}
	return ev
}
