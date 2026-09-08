package analyzer

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// One Ingress may list the same host in several rules (a legal way to group paths). That is not a
// routing conflict, but hostOwners used to append per rule, so the single Ingress appeared twice.
func TestIngressSameHostTwiceInOneIngressIsNotDuplicate(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Service", ClusterID: "c1", Namespace: "default", Name: "api"},
		{Kind: "Ingress", ClusterID: "c1", Namespace: "default", Name: "solo", Spec: map[string]any{
			"rules": []any{
				map[string]any{"host": "example.com", "http": map[string]any{"paths": []any{
					map[string]any{"path": "/a", "backend": map[string]any{"service": map[string]any{"name": "api"}}},
				}}},
				map[string]any{"host": "example.com", "http": map[string]any{"paths": []any{
					map[string]any{"path": "/b", "backend": map[string]any{"service": map[string]any{"name": "api"}}},
				}}},
			},
		}},
	}
	for _, f := range analyzeIngresses(items) {
		if f.Check == "IngressDuplicateHost" {
			t.Fatalf("one Ingress reusing a host in two rules is not a conflict: %+v", f)
		}
	}
}

// A genuine conflict (two Ingresses on one host) must keep firing, carry the owner's cluster and
// list every owner once.
func TestIngressDuplicateHostKeepsRealConflict(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Ingress", ClusterID: "c1", Namespace: "default", Name: "ing1", Spec: map[string]any{
			"rules": []any{
				map[string]any{"host": "example.com"},
				map[string]any{"host": "example.com"},
			},
		}},
		{Kind: "Ingress", ClusterID: "c1", Namespace: "other", Name: "ing2", Spec: map[string]any{
			"rules": []any{map[string]any{"host": "example.com"}},
		}},
	}
	f, ok := connByCheck(analyzeIngresses(items), "IngressDuplicateHost")
	if !ok {
		t.Fatalf("two Ingresses on one host must be flagged")
	}
	if f.ClusterID != "c1" {
		t.Fatalf("duplicate-host finding must carry the owner cluster, got %q", f.ClusterID)
	}
	joined := ""
	for _, e := range f.Evidence {
		joined += e + "|"
	}
	if !containsSub([]string{joined}, "default/ing1") || !containsSub([]string{joined}, "other/ing2") {
		t.Fatalf("expected both owners in evidence, got %+v", f.Evidence)
	}
	if strings.Count(joined, "default/ing1") != 1 {
		t.Fatalf("owner listed more than once: %+v", f.Evidence)
	}
}

// spec.defaultBackend serves every request that matches no rule; a missing Service there breaks
// the same traffic a missing per-path backend does, but it was never checked.
func TestIngressDefaultBackendMissingService(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Ingress", ClusterID: "c1", Namespace: "default", Name: "ing", Spec: map[string]any{
			"defaultBackend": map[string]any{"service": map[string]any{"name": "ghost"}},
		}},
	}
	f, ok := connByCheck(analyzeIngresses(items), "IngressBackendMissing")
	if !ok {
		t.Fatalf("missing defaultBackend Service must be flagged")
	}
	if f.Severity != "high" || f.ResourceName != "ing" {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

// An existing defaultBackend Service must stay clean (false-positive regression).
func TestIngressDefaultBackendPresentIsClean(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Service", ClusterID: "c1", Namespace: "default", Name: "api"},
		{Kind: "Ingress", ClusterID: "c1", Namespace: "default", Name: "ing", Spec: map[string]any{
			"defaultBackend": map[string]any{"service": map[string]any{"name": "api"}},
		}},
	}
	if out := analyzeIngresses(items); len(out) != 0 {
		t.Fatalf("expected no findings, got %+v", out)
	}
}

// The same missing Service referenced by several paths is one problem, not three.
func TestIngressMissingBackendReportedOnce(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Ingress", ClusterID: "c1", Namespace: "default", Name: "ing", Spec: map[string]any{
			"rules": []any{map[string]any{"host": "example.com", "http": map[string]any{"paths": []any{
				map[string]any{"path": "/a", "backend": map[string]any{"service": map[string]any{"name": "ghost"}}},
				map[string]any{"path": "/b", "backend": map[string]any{"service": map[string]any{"name": "ghost"}}},
				map[string]any{"path": "/c", "backend": map[string]any{"service": map[string]any{"name": "ghost"}}},
			}}}},
		}},
	}
	n := 0
	for _, f := range analyzeIngresses(items) {
		if f.Check == "IngressBackendMissing" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected one IngressBackendMissing for ghost, got %d", n)
	}
}

// A namespace-mate's provisioning failure must not be filed as this PVC's evidence.
func TestPVCEvidenceDoesNotBorrowAnotherClaimsFailure(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "PersistentVolumeClaim", ClusterID: "c1", Namespace: "default", Name: "mine", Status: "Pending"},
	}
	events := []store.K8sEvent{
		{Namespace: "default", InvolvedKind: "PersistentVolumeClaim", InvolvedName: "other", Reason: "ProvisioningFailed",
			Message: "storageclass.storage.k8s.io \"gold\" not found", Type: "Warning"},
	}
	out := analyzePVCs(items, events)
	if len(out) != 1 {
		t.Fatalf("expected one PVCPending, got %+v", out)
	}
	for _, e := range out[0].Evidence {
		if containsSub([]string{e}, "ProvisioningFailed") {
			t.Fatalf("evidence borrowed another PVC's failure: %+v", out[0].Evidence)
		}
	}
}

// This PVC's own provisioning event, and a Pod mount failure naming the claim, stay as evidence.
func TestPVCEvidenceKeepsOwnEvents(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "PersistentVolumeClaim", ClusterID: "c1", Namespace: "default", Name: "mine", Status: "Pending"},
	}
	events := []store.K8sEvent{
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "PersistentVolumeClaim", InvolvedName: "mine", Reason: "WaitForFirstConsumer",
			Message: "waiting for first consumer to be created", Type: "Normal"},
		{ClusterID: "c1", Namespace: "default", InvolvedKind: "Pod", InvolvedName: "web-1", Reason: "FailedMount",
			Message: "Unable to attach or mount volumes: unbound PVC mine", Type: "Warning"},
	}
	out := analyzePVCs(items, events)
	if len(out) != 1 {
		t.Fatalf("expected one PVCPending, got %+v", out)
	}
	joined := ""
	for _, e := range out[0].Evidence {
		joined += e + "|"
	}
	if !containsSub([]string{joined}, "WaitForFirstConsumer") || !containsSub([]string{joined}, "FailedMount") {
		t.Fatalf("expected own events as evidence, got %+v", out[0].Evidence)
	}
}
