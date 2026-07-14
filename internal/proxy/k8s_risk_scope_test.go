package proxy

import (
	"strings"
	"testing"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

func TestBatchPodGenericRisksAreSuppressedButJobRiskRemains(t *testing.T) {
	items := []store.K8sInventoryItem{{ClusterID: "c1", Namespace: "batch", Kind: "Pod", Name: "nightly-x", Spec: map[string]any{"ownerReferences": []any{map[string]any{"kind": "Job", "name": "nightly", "controller": true}}}}}
	owners := k8sPodOwnerIndex(items)
	findings := filterBatchPodFindings([]analyzer.RCAFinding{
		{ClusterID: "c1", Namespace: "batch", ResourceKind: "Pod", ResourceName: "nightly-x", Condition: "CrashLoopBackOff"},
		{ClusterID: "c1", Namespace: "batch", ResourceKind: "Job", ResourceName: "nightly", Condition: "JobFailing"},
	}, owners)
	if len(findings) != 1 || findings[0].ResourceKind != "Job" || findings[0].Condition != "JobFailing" {
		t.Fatalf("generic Pod noise must be replaced by Job outcome: %+v", findings)
	}
}

func TestK8sRiskScopeDefaultsToApplicationAndCanSelectSystem(t *testing.T) {
	if k8sRiskScopeMatches("kube-system", "application") {
		t.Fatal("kube-system must be hidden from default application risk list")
	}
	if !k8sRiskScopeMatches("kube-system", "system") || !k8sRiskScopeMatches("kube-system", "all") {
		t.Fatal("system resources must remain explicitly discoverable")
	}
	if k8sRiskScopeMatches("gpu-operator", "application") || !k8sRiskScopeMatches("gpu-operator", "system") {
		t.Fatal("GPU operator resources must be classified as platform-managed")
	}
	if !k8sRiskScopeMatches("payments", "application") || k8sRiskScopeMatches("payments", "system") {
		t.Fatal("application namespace scope mismatch")
	}
	if !k8sRiskScopeMatches("", "application") {
		t.Fatal("cluster-scoped Node/control-plane risks must remain visible")
	}
}

func TestBatchPodOwnerInferenceUsesJobLabelsAndNamePrefix(t *testing.T) {
	items := []store.K8sInventoryItem{
		{ClusterID: "c1", Namespace: "gpu-operator", Kind: "Job", Name: "nvidia-validator", UID: "job-uid"},
		{ClusterID: "c1", Namespace: "gpu-operator", Kind: "Pod", Name: "nvidia-validator-abcde", Labels: map[string]string{"batch.kubernetes.io/controller-uid": "job-uid"}},
	}
	owners := k8sPodOwnerIndex(items)
	owner := owners["c1|gpu-operator|nvidia-validator-abcde"]
	if owner.Kind != "Job" || owner.Name != "nvidia-validator" {
		t.Fatalf("batch owner should be inferred from standard labels: %+v", owner)
	}
	if !isBatchWorkloadItem(items[1], owners) {
		t.Fatal("inferred Job Pod must be excluded from generic workload risk")
	}
}

func TestBatchPodOwnerInferenceSurvivesTTLDeletedJob(t *testing.T) {
	items := []store.K8sInventoryItem{{ClusterID: "c1", Namespace: "kube-system", Kind: "Pod", Name: "upgrade-check-abcde", Labels: map[string]string{"batch.kubernetes.io/job-name": "upgrade-check"}}}
	owner := k8sPodOwnerIndex(items)["c1|kube-system|upgrade-check-abcde"]
	if owner.Kind != "Job" || owner.Name != "upgrade-check" {
		t.Fatalf("standard Job label must survive missing/TTL-deleted Job inventory: %+v", owner)
	}
}

func TestRiskScopeUXContract(t *testing.T) {
	for _, marker := range []string{"risk_scope", "애플리케이션 (기본)", "K8s·플랫폼 관리", "모두 표시", "operational_alert_suppressed", "해결된 이력 포함", "suppressed_noise"} {
		if !containsAdminHTML(marker) {
			t.Fatalf("risk scope UX missing %q", marker)
		}
	}
}

func TestIncidentListSuppressesLegacyBatchRestartStorm(t *testing.T) {
	items := []store.K8sInventoryItem{{ClusterID: "c1", Namespace: "batch", Kind: "Job", Name: "nightly"}}
	incidents := []store.K8sIncident{
		{ID: "noise", ClusterID: "c1", Namespace: "batch", Kind: "Job", Name: "nightly", Condition: "RestartStorm", Status: "resolved"},
		{ID: "real", ClusterID: "c1", Namespace: "batch", Kind: "Job", Name: "nightly", Condition: "JobFailing", Status: "open"},
	}
	got, suppressed := filterSuppressedIncidents(incidents, items)
	if suppressed != 1 || len(got) != 1 || got[0].ID != "real" {
		t.Fatalf("legacy batch storm must be hidden while Job failure remains: suppressed=%d incidents=%+v", suppressed, got)
	}
}

func containsAdminHTML(marker string) bool {
	return len(marker) > 0 && strings.Contains(adminHTML, marker)
}
