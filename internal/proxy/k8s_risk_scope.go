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
	for _, item := range items {
		if item.Kind != "Pod" {
			continue
		}
		kind, name := podOwner(item.Spec)
		out[item.ClusterID+"|"+item.Namespace+"|"+item.Name] = k8sOwnerRef{Kind: kind, Name: name}
	}
	return out
}

func isBatchPodItem(item store.K8sInventoryItem) bool {
	if item.Kind != "Pod" {
		return false
	}
	kind, _ := podOwner(item.Spec)
	return strings.EqualFold(kind, "Job") || strings.EqualFold(kind, "CronJob")
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

func isK8sSystemNamespace(namespace string) bool {
	ns := strings.ToLower(strings.TrimSpace(namespace))
	if ns == "" {
		return false // cluster-scoped Node and control-plane signals remain operationally relevant
	}
	if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" {
		return true
	}
	for _, prefix := range []string{"openshift-", "cattle-system", "istio-system", "linkerd", "cert-manager", "argocd", "flux-system"} {
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
