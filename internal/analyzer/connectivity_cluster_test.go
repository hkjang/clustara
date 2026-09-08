package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// The connectivity view is callable without a cluster_id, so one report can hold several
// clusters' inventories. Every cross-reference in it (Service→Pod, Ingress→Service,
// Ingress host↔Ingress host, PVC→Event) has to stay inside one cluster.

// A Service selects Pods in its own cluster only. Another cluster's identically-named namespace
// holding a matching Pod used to satisfy the endpoint check and hide the broken Service.
func TestAnalyzeServicesDoesNotBorrowPodsFromAnotherCluster(t *testing.T) {
	items := []store.K8sInventoryItem{
		{ClusterID: "prod", Kind: "Service", Namespace: "shop", Name: "api", Spec: map[string]any{"selector": map[string]any{"app": "api"}}},
		{ClusterID: "dr", Kind: "Pod", Namespace: "shop", Name: "api-1", Labels: map[string]string{"app": "api"}, Status: "Running"},
	}
	out := analyzeServices(items)
	f, ok := connByCheck(out, "ServiceNoEndpoints")
	if !ok {
		t.Fatalf("a Service whose only matching Pod lives in another cluster has no endpoints, got %+v", out)
	}
	if f.ClusterID != "prod" {
		t.Fatalf("finding should be attributed to the Service's cluster, got %q", f.ClusterID)
	}
}

// Succeeded/Failed Pods are dropped by the endpoints controller but linger in the inventory
// until they are garbage-collected, so a Service left behind by a finished Job resolves to
// nothing while still "matching" Pods.
func TestAnalyzeServicesTerminatedPodsAreNotEndpoints(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Service", Namespace: "batch", Name: "report", Spec: map[string]any{"selector": map[string]any{"job": "report"}}},
		{Kind: "Pod", Namespace: "batch", Name: "report-1", Labels: map[string]string{"job": "report"}, Status: "Succeeded"},
		{Kind: "Pod", Namespace: "batch", Name: "report-2", Labels: map[string]string{"job": "report"},
			StatusObject: map[string]any{"phase": "Failed"}, Status: "Failed"},
	}
	f, ok := connByCheck(analyzeServices(items), "ServiceNoEndpoints")
	if !ok {
		t.Fatalf("a Service backed only by terminated Pods has no endpoints, got %+v", analyzeServices(items))
	}
	if !strings.Contains(f.Message, "종료") {
		t.Fatalf("the finding should say the matching Pods are terminated, got %q", f.Message)
	}
}

// A Pod that is unhealthy but not terminal is still published as an endpoint address, so the
// check must stay quiet — this is the check's "empty endpoints" question, not a health question.
func TestAnalyzeServicesKeepsUnhealthyPodsAsEndpoints(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Service", Namespace: "web", Name: "front", Spec: map[string]any{"selector": map[string]any{"app": "front"}}},
		{Kind: "Pod", Namespace: "web", Name: "front-1", Labels: map[string]string{"app": "front"},
			Status: "CrashLoopBackOff", StatusObject: map[string]any{"phase": "Running"}},
	}
	if f, ok := connByCheck(analyzeServices(items), "ServiceNoEndpoints"); ok {
		t.Fatalf("a running-but-unhealthy Pod is still an endpoint: %+v", f)
	}
}

// An Ingress backend resolves against Services in its own cluster; a same-named Service
// elsewhere does not make the route work.
func TestAnalyzeIngressesResolveBackendsWithinTheCluster(t *testing.T) {
	items := []store.K8sInventoryItem{
		{ClusterID: "dr", Kind: "Service", Namespace: "shop", Name: "api"},
		{ClusterID: "prod", Kind: "Ingress", Namespace: "shop", Name: "shop", Spec: map[string]any{
			"rules": []any{map[string]any{"host": "shop.example.com", "http": map[string]any{"paths": []any{
				map[string]any{"backend": map[string]any{"service": map[string]any{"name": "api"}}},
			}}}},
		}},
	}
	if _, ok := connByCheck(analyzeIngresses(items), "IngressBackendMissing"); !ok {
		t.Fatalf("backend Service exists only in another cluster, expected IngressBackendMissing: %+v", analyzeIngresses(items))
	}
}

// Two clusters serving the same host is how an active/standby pair is built, not a routing
// conflict — the duplicate-host check compares hosts inside a cluster.
func TestAnalyzeIngressesDuplicateHostIsPerCluster(t *testing.T) {
	mk := func(cluster, name string) store.K8sInventoryItem {
		return store.K8sInventoryItem{ClusterID: cluster, Kind: "Ingress", Namespace: "shop", Name: name, Spec: map[string]any{
			"rules": []any{map[string]any{"host": "shop.example.com"}},
		}}
	}
	mirrored := []store.K8sInventoryItem{mk("prod", "shop"), mk("dr", "shop-standby")}
	if f, ok := connByCheck(analyzeIngresses(mirrored), "IngressDuplicateHost"); ok {
		t.Fatalf("mirrored Ingresses in two clusters are not a host conflict: %+v", f)
	}
	// Two distinct Ingresses inside one cluster still conflict.
	same := []store.K8sInventoryItem{mk("prod", "shop"), mk("prod", "shop-canary")}
	if _, ok := connByCheck(analyzeIngresses(same), "IngressDuplicateHost"); !ok {
		t.Fatalf("two Ingresses in one cluster claiming the same host is still a conflict")
	}
}

// Event evidence is another cluster's only when the cluster matches: the event feed spans
// clusters in the all-clusters view.
func TestAnalyzePVCsIgnoreEventsFromAnotherCluster(t *testing.T) {
	items := []store.K8sInventoryItem{
		{ClusterID: "prod", Kind: "PersistentVolumeClaim", Namespace: "shop", Name: "data", Status: "Pending"},
	}
	events := []store.K8sEvent{
		{ClusterID: "dr", Namespace: "shop", InvolvedKind: "PersistentVolumeClaim", InvolvedName: "data",
			Reason: "ProvisioningFailed", Message: "storageclass not found", Type: "Warning"},
	}
	out := analyzePVCs(items, events)
	if len(out) != 1 {
		t.Fatalf("expected one PVCPending, got %+v", out)
	}
	for _, e := range out[0].Evidence {
		if strings.Contains(e, "ProvisioningFailed") {
			t.Fatalf("another cluster's event was filed as this claim's evidence: %+v", out[0].Evidence)
		}
	}
}
