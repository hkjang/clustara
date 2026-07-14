package proxy

import (
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

type k8sOwnerRef struct {
	Kind string
	Name string
}

func k8sPodOwnerIndex(items []store.K8sInventoryItem) map[string]k8sOwnerRef {
	out := map[string]k8sOwnerRef{}
	jobsByNamespace := map[string][]store.K8sInventoryItem{}
	for _, item := range items {
		if strings.EqualFold(item.Kind, "Job") {
			key := item.ClusterID + "|" + item.Namespace
			jobsByNamespace[key] = append(jobsByNamespace[key], item)
		}
	}
	for _, item := range items {
		if !strings.EqualFold(item.Kind, "Pod") {
			continue
		}
		kind, name := podOwner(item.Spec)
		// Some collectors or already-completed/TTL-cleaned Jobs leave a Pod without a usable
		// ownerReference. Kubernetes' standard job-name/controller-uid labels and generated
		// Pod-name prefix still let us keep finite attempts out of service RestartStorm rules.
		if !strings.EqualFold(kind, "Job") {
			jobName := firstNonEmpty(item.Labels["batch.kubernetes.io/job-name"], item.Labels["job-name"])
			controllerUID := firstNonEmpty(item.Labels["batch.kubernetes.io/controller-uid"], item.Labels["controller-uid"])
			if jobName != "" {
				// The standard label survives even when ttlSecondsAfterFinished has already
				// removed the Job object from the latest inventory.
				kind, name = "Job", jobName
			} else {
				for _, job := range jobsByNamespace[item.ClusterID+"|"+item.Namespace] {
					if (controllerUID != "" && controllerUID == job.UID) ||
						(job.Name != "" && strings.HasPrefix(item.Name, job.Name+"-")) {
						kind, name = "Job", job.Name
						break
					}
				}
			}
		}
		out[item.ClusterID+"|"+item.Namespace+"|"+item.Name] = k8sOwnerRef{Kind: kind, Name: name}
	}
	return out
}

func isBatchWorkloadItem(item store.K8sInventoryItem, owners map[string]k8sOwnerRef) bool {
	if strings.EqualFold(item.Kind, "Job") || strings.EqualFold(item.Kind, "CronJob") {
		return true
	}
	if !strings.EqualFold(item.Kind, "Pod") {
		return false
	}
	owner := owners[item.ClusterID+"|"+item.Namespace+"|"+item.Name]
	return strings.EqualFold(owner.Kind, "Job") || strings.EqualFold(owner.Kind, "CronJob")
}

// suppressBatchPodRisk keeps finite batch attempts out of generic service-Pod alarms.
// Their meaningful outcome remains visible through JobFailed, BackoffLimitExceeded,
// DeadlineExceeded and CronJob missed/no-success findings.
func suppressBatchPodRisk(f analyzer.RCAFinding, owners map[string]k8sOwnerRef) bool {
	if !strings.EqualFold(f.ResourceKind, "Pod") {
		return false
	}
	owner := owners[f.ClusterID+"|"+f.Namespace+"|"+f.ResourceName]
	return strings.EqualFold(owner.Kind, "Job") || strings.EqualFold(owner.Kind, "CronJob")
}

func filterBatchPodFindings(findings []analyzer.RCAFinding, owners map[string]k8sOwnerRef) []analyzer.RCAFinding {
	out := make([]analyzer.RCAFinding, 0, len(findings))
	for _, finding := range findings {
		if !suppressBatchPodRisk(finding, owners) {
			out = append(out, finding)
		}
	}
	return out
}

func filterBatchPodIncidentDrafts(drafts []analyzer.IncidentDraft, owners map[string]k8sOwnerRef) []analyzer.IncidentDraft {
	out := make([]analyzer.IncidentDraft, 0, len(drafts))
	for _, draft := range drafts {
		owner := owners[draft.ClusterID+"|"+draft.Namespace+"|"+draft.Name]
		if strings.EqualFold(draft.Kind, "Pod") && (strings.EqualFold(owner.Kind, "Job") || strings.EqualFold(owner.Kind, "CronJob")) {
			continue
		}
		out = append(out, draft)
	}
	return out
}

func filterSuppressedIncidents(incidents []store.K8sIncident, items []store.K8sInventoryItem) ([]store.K8sIncident, int) {
	owners := k8sPodOwnerIndex(items)
	jobs := map[string]bool{}
	for _, item := range items {
		if item.Kind == "Job" || item.Kind == "CronJob" {
			jobs[item.ClusterID+"|"+item.Namespace+"|"+item.Name] = true
		}
	}
	out := make([]store.K8sIncident, 0, len(incidents))
	suppressed := 0
	for _, incident := range incidents {
		batchStorm := strings.EqualFold(incident.Condition, "RestartStorm") && (strings.EqualFold(incident.Kind, "Job") || strings.EqualFold(incident.Kind, "CronJob") ||
			jobs[incident.ClusterID+"|"+incident.Namespace+"|"+incident.Name])
		if strings.EqualFold(incident.Condition, "RestartStorm") && strings.EqualFold(incident.Kind, "Pod") {
			owner := owners[incident.ClusterID+"|"+incident.Namespace+"|"+incident.Name]
			batchStorm = strings.EqualFold(owner.Kind, "Job") || strings.EqualFold(owner.Kind, "CronJob")
		}
		if strings.EqualFold(incident.Condition, "RestartStorm") && !batchStorm {
			for jobKey := range jobs {
				parts := strings.SplitN(jobKey, "|", 3)
				if len(parts) == 3 && incident.ClusterID == parts[0] && incident.Namespace == parts[1] &&
					(incident.Name == parts[2] || strings.HasPrefix(incident.Name, parts[2]+"-")) {
					batchStorm = true
					break
				}
			}
		}
		if batchStorm {
			suppressed++
			continue
		}
		out = append(out, incident)
	}
	return out, suppressed
}

func shouldSuppressIncident(incident store.K8sIncident, items []store.K8sInventoryItem) bool {
	filtered, _ := filterSuppressedIncidents([]store.K8sIncident{incident}, items)
	return len(filtered) == 0
}

func isK8sSystemNamespace(namespace string) bool {
	ns := strings.ToLower(strings.TrimSpace(namespace))
	if ns == "" {
		return false // cluster-scoped Node and control-plane signals remain operationally relevant
	}
	if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" {
		return true
	}
	for _, prefix := range []string{"openshift-", "cattle-system", "istio-system", "linkerd", "cert-manager", "argocd", "flux-system", "gpu-operator", "nvidia-gpu-operator", "tigera-operator", "monitoring"} {
		if ns == prefix || strings.HasPrefix(ns, prefix) {
			return true
		}
	}
	return false
}

func k8sRiskScopeMatches(namespace, scope string) bool {
	system := isK8sSystemNamespace(namespace)
	switch scope {
	case "all":
		return true
	case "system":
		return system
	default:
		return !system
	}
}
