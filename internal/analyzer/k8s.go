package analyzer

import (
	"encoding/json"
	"strings"
	"time"

	"clustara/internal/store"
)

func ScoreResource(item *store.K8sInventoryItem) {
	score := 100
	risk := "low"
	status := strings.ToLower(item.Status)
	spec := specText(item.Spec)

	penalize := func(points int, level string) {
		score -= points
		risk = maxRisk(risk, level)
	}

	switch {
	case strings.Contains(status, "crashloopbackoff"):
		penalize(45, "high")
	case strings.Contains(status, "imagepullbackoff") || strings.Contains(status, "errimagepull"):
		penalize(35, "medium")
	case strings.Contains(status, "oomkilled"):
		penalize(40, "high")
	case strings.Contains(status, "pending"):
		penalize(25, "medium")
	case strings.Contains(status, "notready") || strings.Contains(status, "unavailable"):
		penalize(30, "medium")
	}

	if strings.Contains(spec, `"privileged":true`) {
		penalize(35, "critical")
	}
	if strings.Contains(spec, `"runasuser":0`) || strings.Contains(spec, `"runasnonroot":false`) {
		penalize(25, "high")
	}
	if strings.Contains(spec, `"hostnetwork":true`) || strings.Contains(spec, `"hostpid":true`) || strings.Contains(spec, `"hostipc":true`) {
		penalize(25, "high")
	}
	if strings.Contains(spec, `"hostpath"`) {
		penalize(25, "high")
	}
	if strings.Contains(spec, `:latest"`) || strings.Contains(spec, `:latest,`) {
		penalize(10, "medium")
	}

	if score < 0 {
		score = 0
	}
	item.HealthScore = score
	item.RiskLevel = risk
}

func AnalyzeInventory(items []store.K8sInventoryItem, events []store.K8sEvent, id func(string) string) []store.K8sSecurityFinding {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	out := []store.K8sSecurityFinding{}
	add := func(clusterID, namespace, kind, name, rule, severity, message, evidence string) {
		out = append(out, store.K8sSecurityFinding{
			ID:           id("k8sf"),
			ClusterID:    clusterID,
			Namespace:    namespace,
			ResourceKind: kind,
			ResourceName: name,
			Rule:         rule,
			Severity:     severity,
			Message:      message,
			Evidence:     evidence,
			Status:       "open",
			FirstSeen:    now,
			LastSeen:     now,
		})
	}

	for _, item := range items {
		spec := specText(item.Spec)
		if strings.Contains(spec, `"privileged":true`) {
			add(item.ClusterID, item.Namespace, item.Kind, item.Name, "privileged-container", "critical", "Privileged container is enabled.", "spec.securityContext.privileged=true")
		}
		if strings.Contains(spec, `"runasuser":0`) || strings.Contains(spec, `"runasnonroot":false`) {
			add(item.ClusterID, item.Namespace, item.Kind, item.Name, "root-container", "high", "Container may run as root.", "runAsUser=0 or runAsNonRoot=false")
		}
		if strings.Contains(spec, `"hostnetwork":true`) {
			add(item.ClusterID, item.Namespace, item.Kind, item.Name, "host-network", "high", "Host network is enabled.", "spec.hostNetwork=true")
		}
		if strings.Contains(spec, `"hostpath"`) {
			add(item.ClusterID, item.Namespace, item.Kind, item.Name, "host-path-volume", "high", "hostPath volume is mounted.", "spec.volumes[].hostPath")
		}
		if strings.Contains(spec, `:latest"`) || strings.Contains(spec, `:latest,`) {
			add(item.ClusterID, item.Namespace, item.Kind, item.Name, "latest-image-tag", "medium", "Container image uses the mutable latest tag.", "image tag latest")
		}
		status := strings.ToLower(item.Status)
		if strings.Contains(status, "crashloopbackoff") || strings.Contains(status, "imagepullbackoff") || strings.Contains(status, "oomkilled") {
			add(item.ClusterID, item.Namespace, item.Kind, item.Name, "workload-health", "high", "Workload reports an unhealthy runtime state.", item.Status)
		}
		if (item.Kind == "Role" || item.Kind == "ClusterRole") && strings.Contains(spec, `"*"`) {
			add(item.ClusterID, item.Namespace, item.Kind, item.Name, "wildcard-rbac", "critical", "RBAC rule grants wildcard permissions.", "verbs/resources/apiGroups include *")
		}
	}

	for _, e := range events {
		if strings.ToLower(e.Type) != "warning" {
			continue
		}
		severity := "medium"
		reason := strings.ToLower(e.Reason)
		if strings.Contains(reason, "failed") || strings.Contains(reason, "backoff") || strings.Contains(reason, "evicted") {
			severity = "high"
		}
		add(e.ClusterID, e.Namespace, e.InvolvedKind, e.InvolvedName, "warning-event", severity, "Kubernetes Warning event observed.", e.Reason+": "+e.Message)
	}
	return out
}

func specText(spec map[string]any) string {
	if len(spec) == 0 {
		return ""
	}
	b, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	return strings.ToLower(string(b))
}

func maxRisk(a, b string) string {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
